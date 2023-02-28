use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::fmt::Display;
use libc::{c_char, size_t};

#[cfg(feature = "uclient")]
pub type TransportWrap = transport::utangle::Client;

#[cfg(not(feature = "uclient"))]
pub type TransportWrap = Rc<RefCell<transport::bucket::Client>>;

use streams::{
    Address,
    Message as StreamsMessage,
    MessageContent,
    transport,
};

use cstr_core::{CStr, CString};

use core::ptr::null;



/// Last Error is a global variable to fetch the latest operational error should a task fail in
/// the bindings. Used for troubleshooting. Empty when there is no previous error.
#[no_mangle]
#[used]
pub static mut LAST_ERROR: Vec<u8> = Vec::new();

#[no_mangle]
pub unsafe extern "C" fn get_last_error() -> *const c_char {
    string_into_raw_unchecked(String::from_utf8_unchecked(LAST_ERROR.clone()))
}


#[repr(C)]
pub enum Err {
    Ok,
    NullArgument,
    BadArgument,
    OperationFailed,
}

pub unsafe fn operation_failed<E: Display>(e: E) -> Err {
    LAST_ERROR = e.to_string().into_bytes();
    Err::OperationFailed
}


#[repr(C)]
pub enum PermissionType {
    Read,
    Write
}





/// Convert an String-like collection of bytes into a raw pointer to the first byte
///
/// This function is unsafe because it does not check that the String does not contain a null byte.
/// Use this function instead of [`string_into_raw`] in those cases where it's certain there won't be
/// a null byte and don't want to incur the performance penalty of the validation.
unsafe fn string_into_raw_unchecked(string: impl Into<Vec<u8>>) -> *const c_char {
    CString::from_vec_unchecked(string.into()).into_raw()
}


pub(crate) fn safe_into_ptr<T>(value: T) -> *const T {
    Box::into_raw(Box::new(value))
}

pub(crate) fn safe_into_mut_ptr<T>(value: T) -> *mut T {
    Box::into_raw(Box::new(value))
}

pub(crate) fn safe_drop_ptr<T>(p: *const T) {
    unsafe {
        (p as *mut T).as_mut().map(|p| Box::from_raw(p));
    }
}

pub(crate) fn safe_drop_mut_ptr<T>(p: *mut T) {
    unsafe {
        p.as_mut().map(|p| Box::from_raw(p));
    }
}






#[repr(C)]
pub struct Buffer {
    pub(crate) ptr: *const u8,
    pub(crate) size: size_t,
    pub(crate) cap: size_t,
}

impl From<Vec<u8>> for Buffer {
    fn from(vec: Vec<u8>) -> Self {
        let p = core::mem::ManuallyDrop::new(vec);
        Self {
            ptr: p.as_ptr(),
            size: p.len(),
            cap: p.capacity(),
        }
    }
}

impl Default for Buffer {
    fn default() -> Self {
        Self {
            ptr: null(),
            size: 0,
            cap: 0,
        }
    }
}

impl From<Buffer> for Vec<u8> {
    fn from(b: Buffer) -> Self {
        unsafe { Vec::from_raw_parts(b.ptr as *mut u8, b.size, b.cap) }
    }
}

impl Buffer {
    pub fn new(size: usize) -> Self {
        Vec::with_capacity(size).into()
    }
    pub fn drop(self) {
        let _b: Vec<u8> = self.into();
    }
}

#[no_mangle]
pub extern "C" fn drop_buffer(b: Buffer) {
    b.drop()
}









static INSTANCE: OnceCell<Runtime> = OnceCell::new();

pub fn run_async<C: Future>(cb: C) -> C::Output {
    let runtime = INSTANCE.get_or_init(|| Runtime::new().unwrap());
    runtime.block_on(cb)
}







#[no_mangle]
pub extern "C" fn transport_new() -> *mut TransportWrap {
    safe_into_mut_ptr(TransportWrap::default())
}

#[no_mangle]
pub extern "C" fn transport_drop(tsp: *mut TransportWrap) {
    safe_drop_mut_ptr(tsp)
}


#[cfg(feature = "uclient")]
#[no_mangle]
pub unsafe extern "C" fn transport_client_new_from_url(c_url: *const c_char) -> *mut TransportWrap {
    let url = CStr::from_ptr(c_url).to_str().unwrap();
    safe_into_mut_ptr(TransportWrap::new(url))
}















#[no_mangle]
pub unsafe extern "C" fn get_address_inst_str(address: *const Address) -> *const c_char {
    address
        .as_ref()
        .map_or(null(), |addr| string_into_raw_unchecked(addr.base().to_hex_string()))
}

#[no_mangle]
pub unsafe extern "C" fn get_address_id_str(address: *const Address) -> *const c_char {
    address
        .as_ref()
        .map_or(null(), |addr| string_into_raw_unchecked(addr.relative().to_hex_string()))
}

#[no_mangle]
pub unsafe extern "C" fn get_address_index_str(address: *const Address) -> *const c_char {
    address.as_ref().map_or(null(), |addr| {
        let index = addr.to_msg_index();
        let index_hex = hex::encode(index);
        string_into_raw_unchecked(index_hex)
    })
}

#[no_mangle]
pub unsafe extern "C" fn get_identifier_str(id: *const Identifier) -> *const c_char {
    id.as_ref().map_or(null(), |id| {
        string_into_raw_unchecked(hex::encode(id.as_ref()))
    })
}
#[no_mangle]
pub unsafe extern "C" fn get_permissioned_str(id: *const Permissioned<Identifier>) -> *const c_char {
    id.as_ref().map_or(null(), |id| {
        string_into_raw_unchecked(hex::encode(id.identifier().as_ref()))
    })
}



#[no_mangle]
pub unsafe extern "C" fn drop_str(string: *const c_char) {
    CString::from_raw(string as *mut c_char);
}


#[no_mangle]
pub unsafe extern "C" fn drop_address(addr: *const Address) {
    safe_drop_ptr(addr)
}

#[no_mangle]
pub unsafe extern "C" fn drop_identifier(id: *const Identifier) {
    safe_drop_ptr(id)
}


/// Attempts to convert a c string into an address. If the c string is NULL or the string fails to
/// convert to an Address properly, a zeroed out Address is returned instead
#[no_mangle]
pub unsafe extern "C" fn address_from_string(c_addr: *const c_char) -> *const Address {
    CStr::from_ptr(c_addr).to_str().map_or(safe_into_ptr(Address::default()), |addr_str| {
        Address::from_str(addr_str).map_or(safe_into_ptr(Address::default()), |addr|
            safe_into_ptr(addr)
        )
    })
}






#[repr(C)]
pub enum MessageType {
    Announcement,
    BranchAnnouncement,
    Keyload,
    SignedPacket,
    TaggedPacket,
    Subscribe,
    Unsubscribe,
    Unknown,
}


fn message_type(msg_type: u8) -> MessageType {
    match msg_type {
        0 => MessageType::Announcement,
        1 => MessageType::BranchAnnouncement,
        2 => MessageType::Keyload,
        3 => MessageType::SignedPacket,
        4 => MessageType::TaggedPacket,
        5 => MessageType::Subscribe,
        6 => MessageType::Unsubscribe,
        _ => MessageType::Unknown,
    }
}

#[no_mangle]
pub unsafe extern "C" fn message_type_as_str(msg_type: MessageType) -> *const c_char {
    match msg_type {
        MessageType::Announcement => string_into_raw_unchecked("Announcement"),
        MessageType::BranchAnnouncement => string_into_raw_unchecked("BranchAnnouncement"),
        MessageType::Keyload => string_into_raw_unchecked("Keyload"),
        MessageType::SignedPacket => string_into_raw_unchecked("SignedPacket"),
        MessageType::TaggedPacket => string_into_raw_unchecked("TaggedPacket"),
        MessageType::Subscribe => string_into_raw_unchecked("Subscribe"),
        MessageType::Unsubscribe => string_into_raw_unchecked("Unsubscribe"),
        MessageType::Unknown => string_into_raw_unchecked("Unknown")
    }
}



#[repr(C)]
pub struct Message {
    message_type: MessageType,
    address: *const Address,
    publisher: *const Identifier,
    payloads: Payloads,
}

impl Default for Message {
    fn default() -> Self {
        Self {
            message_type: MessageType::Unknown,
            address: safe_into_ptr(Address::default()),
            publisher: safe_into_ptr(Identifier::default()),
            payloads: Payloads::default()
        }
    }
}

impl From<StreamsMessage> for Message {
    fn from(msg: StreamsMessage) -> Self {
        let address = msg.address();
        let publisher = match msg.content() {
            MessageContent::TaggedPacket(_) => Identifier::default(),
            _ => msg.header().publisher().clone()
        };

        let message_type = message_type(msg.header().message_type());
        let payloads: Payloads = msg.content.into();
        let message = Message {
            message_type,
            address: safe_into_ptr(address),
            publisher: safe_into_ptr(publisher),
            payloads,
        };
        message
    }
}

impl Message {
    pub unsafe fn drop(self) {
        //safe_drop_ptr(self.message_type);
        drop_address(self.address);
        drop_identifier(self.publisher);
        self.payloads.drop();
    }
}

#[no_mangle]
pub unsafe extern "C" fn drop_message(msg: *const Message) {
    safe_drop_ptr(msg)
}


#[repr(C)]
pub struct Payloads {
    public_payload: Buffer,
    masked_payload: Buffer,
}

impl Default for Payloads {
    fn default() -> Self {
        Self {
            public_payload: Buffer::default(),
            masked_payload: Buffer::default(),
        }
    }
}

impl From<MessageContent> for Payloads {
    fn from(content: MessageContent) -> Self {
        match content {
            MessageContent::TaggedPacket(tp) =>
                Payloads {
                    public_payload: tp.public_payload.into(),
                    masked_payload: tp.masked_payload.into(),
                },
            MessageContent::SignedPacket(sp) =>
                Payloads {
                    public_payload: sp.public_payload.into(),
                    masked_payload: sp.masked_payload.into(),
                },
            _ => Payloads {
                public_payload: Buffer::default(),
                masked_payload: Buffer::default(),
            },
        }
    }
}

impl Payloads {
    pub fn drop(self) {
        self.public_payload.drop();
        self.masked_payload.drop();
    }
}

#[no_mangle]
pub extern "C" fn drop_payloads(payloads: Payloads) {
    payloads.drop()
}
















#[no_mangle]
pub unsafe extern "C" fn new_permissioned(p: *mut *const Permissioned<Identifier>, id: *const Identifier, permission: PermissionType) -> Err {
    p.as_mut().map_or(Err::NullArgument, |permissioned| {
        id.as_ref().map_or(Err::NullArgument, |id| {
            let perm = match permission {
                PermissionType::Read => Permissioned::Read(id.clone()),
                PermissionType::Write => Permissioned::ReadWrite(id.clone(), PermissionDuration::Perpetual)
            };
            *permissioned = safe_into_ptr(perm);
            Err::Ok
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn drop_permissioned(p: *const Permissioned<Identifier>) {
    safe_drop_ptr(p)
}



#[repr(C)]
pub struct IdLists {
    user_ids: Vec<Permissioned<Identifier>>,
    psk_ids: Vec<PskId>,
}


impl IdLists {
    fn new() -> Self {
        Self {
            user_ids: Vec::new(),
            psk_ids: Vec::new(),
        }
    }

    fn push_user_id(&mut self, id: Permissioned<Identifier>) {
        self.user_ids.push(id)
    }

    fn push_psk_id(&mut self, id: PskId) {
        self.psk_ids.push(id)
    }

    fn remove_user_id(&mut self, id: &Identifier) {
        self.user_ids.retain(|i| i.identifier() != id)
    }

    fn remove_psk_id(&mut self, id: &PskId) {
        self.psk_ids.retain(|i| i != id)
    }
}

#[no_mangle]
pub extern "C" fn new_id_lists() -> *mut IdLists {
    safe_into_mut_ptr(IdLists::new())
}

#[no_mangle]
pub unsafe extern "C" fn push_user_to_id_lists(ids: *mut IdLists, id: *const Permissioned<Identifier>) -> Err {
    ids.as_mut().map_or(Err::NullArgument, |ids| {
        id.as_ref().map_or(Err::NullArgument, |p| {
            ids.push_user_id(p.clone());
            Err::Ok
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn remove_user_from_id_lists(ids: *mut IdLists, id: *const Identifier) -> Err {
    ids.as_mut().map_or(Err::NullArgument, |ids| {
        id.as_ref().map_or(Err::NullArgument, |id| {
            ids.remove_user_id(id);
            Err::Ok
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn push_psk_to_id_lists(ids: *mut IdLists, id: *const PskId) -> Err {
    ids.as_mut().map_or(Err::NullArgument, |ids| {
        id.as_ref().map_or(Err::NullArgument, |id| {
            ids.push_psk_id(id.clone());
            Err::Ok
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn remove_psk_from_id_lists(ids: *mut IdLists, id: *const PskId) -> Err {
    ids.as_mut().map_or(Err::NullArgument, |ids| {
        id.as_ref().map_or(Err::NullArgument, |id| {
            ids.remove_psk_id(id);
            Err::Ok
        })
    })
}


#[no_mangle]
pub unsafe extern "C" fn drop_id_lists(ids: *const IdLists) {
    safe_drop_ptr(ids)
}












#[no_mangle]
pub unsafe extern "C" fn pskid_as_str(pskid: *const PskId) -> *const c_char {
    pskid
        .as_ref()
        .map_or(null(), |pskid| string_into_raw_unchecked(hex::encode(&pskid)))
}

#[no_mangle]
pub unsafe extern "C" fn drop_pskid(pskid: *const PskId) {
    safe_drop_ptr(pskid)
}

/*use iota_streams::{
    app::{
        cstr_core::{
            CStr,
            CString,
        },
        cty::{
            c_char,
            size_t,
            uint8_t,
        },
        identifier::Identifier,
        message::Cursor,
        transport::tangle::MsgId,
    },
    app_channels::api::{
        psk_from_seed,
        pskid_from_psk,
        tangle::*,
    },
    core::{
        prelude::*,
        psk::PskId,
    },
};



use tokio::runtime::Runtime;
use once_cell::sync::OnceCell;

use core::ptr::{
    null,
    null_mut,
};

pub fn get_channel_type(channel_type: uint8_t) -> ChannelType {
    match channel_type {
        0 => ChannelType::SingleBranch,
        1 => ChannelType::MultiBranch,
        2 => ChannelType::SingleDepth,
        _ => ChannelType::SingleBranch,
    }
}

pub(crate) fn safe_into_ptr<T>(value: T) -> *const T {
    Box::into_raw(Box::new(value))
}

pub(crate) fn safe_into_mut_ptr<T>(value: T) -> *mut T {
    Box::into_raw(Box::new(value))
}

pub(crate) fn safe_drop_ptr<T>(p: *const T) {
    unsafe {
        (p as *mut T).as_mut().map(|p| Box::from_raw(p));
    }
}

pub(crate) fn safe_drop_mut_ptr<T>(p: *mut T) {
    unsafe {
        p.as_mut().map(|p| Box::from_raw(p));
    }
}

/// Convert an String-like collection of bytes into a raw pointer to the first byte
///
/// The pointer might be [`null`] if the String contains a null byte (which is invalid)
///
/// [`null`]: https://doc.rust-lang.org/std/ptr/fn.null.html
fn _string_into_raw(string: impl Into<Vec<u8>>) -> *const c_char {
    CString::new(string).map_or_else(|_e| null_mut(), CString::into_raw)
}

/// Convert an String-like collection of bytes into a raw pointer to the first byte
///
/// This function is unsafe because it does not check that the String does not contain a null byte.
/// Use this function instead of [`string_into_raw`] in those cases where it's certain there won't be
/// a null byte and don't want to incur the performance penalty of the validation.
unsafe fn string_into_raw_unchecked(string: impl Into<Vec<u8>>) -> *const c_char {
    CString::from_vec_unchecked(string.into()).into_raw()
}

#[repr(C)]
pub enum Err {
    Ok,
    NullArgument,
    BadArgument,
    OperationFailed,
}

#[no_mangle]
pub unsafe extern "C" fn address_from_string(c_addr: *const c_char) -> *const Address {
    Address::from_c_str(c_addr)
}

#[no_mangle]
pub unsafe extern "C" fn public_key_to_string(pubkey: *const PublicKey) -> *const c_char {
    pubkey
        .as_ref()
        .map_or(null(), |pk| string_into_raw_unchecked(hex::encode(pk.as_bytes())))
}

#[no_mangle]
pub unsafe extern "C" fn drop_address(addr: *const Address) {
    safe_drop_ptr(addr)
}

pub type PskIds = Vec<PskId>;
pub type KePks = Vec<PublicKey>;

#[no_mangle]
pub unsafe extern "C" fn pskid_as_str(pskid: *const PskId) -> *const c_char {
    pskid
        .as_ref()
        .map_or(null(), |pskid| string_into_raw_unchecked(hex::encode(&pskid)))
}

#[no_mangle]
pub unsafe extern "C" fn drop_pskid(pskid: *const PskId) {
    safe_drop_ptr(pskid)
}

pub type NextMsgIds = Vec<(Identifier, Cursor<Address>)>;

#[no_mangle]
pub extern "C" fn drop_next_msg_ids(m: *const NextMsgIds) {
    safe_drop_ptr(m)
}

pub type UserState = Vec<(String, Cursor<Address>)>;
#[no_mangle]
pub extern "C" fn drop_user_state(s: *const UserState) {
    safe_drop_ptr(s)
}

#[no_mangle]
pub unsafe extern "C" fn get_link_from_state(state: *const UserState, pub_key: *const PublicKey) -> *const Address {
    state.as_ref().map_or(null(), |state_ref| {
        pub_key.as_ref().map_or(null(), |pub_key| {
            let pk_str = hex::encode(pub_key.as_bytes());
            for (pk, cursor) in state_ref {
                if pk == &pk_str {
                    return safe_into_ptr(cursor.link.clone());
                }
            }
            null()
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn drop_unwrapped_message(ms: *const UnwrappedMessage) {
    Box::from_raw(ms as *mut UnwrappedMessage);
}

pub type UnwrappedMessages = Vec<UnwrappedMessage>;
#[no_mangle]
pub extern "C" fn drop_unwrapped_messages(ms: *const UnwrappedMessages) {
    safe_drop_ptr(ms)
}

//#[cfg(feature = "client")]
//pub type TransportWrap = streams::transport::tangle::Client;

#[cfg(not(feature = "client"))]
pub type TransportWrap = Rc<RefCell<BucketTransport>>;

static INSTANCE: OnceCell<Runtime> = OnceCell::new();

pub fn run_async<C: Future>(cb: C) -> C::Output {
    let runtime = INSTANCE.get_or_init(|| Runtime::new().unwrap());
    runtime.block_on(cb)
}

#[no_mangle]
pub extern "C" fn transport_new() -> *mut TransportWrap {
    safe_into_mut_ptr(TransportWrap::default())
}

#[no_mangle]
pub extern "C" fn transport_drop(tsp: *mut TransportWrap) {
    safe_drop_mut_ptr(tsp)
}

#[cfg(feature = "client")]
#[no_mangle]
pub unsafe extern "C" fn transport_client_new_from_url(c_url: *const c_char) -> *mut TransportWrap {
    let url = CStr::from_ptr(c_url).to_str().unwrap();
    safe_into_mut_ptr(TransportWrap::new_from_url(url))
}

#[cfg(feature = "client")]
mod client_details {
    use super::*;
    use iota_streams::app::transport::{
        tangle::client::{
            iota_client::{
                bee_rest_api::types::{
                    dtos::LedgerInclusionStateDto,
                    responses::MessageMetadataResponse,
                },
                MilestoneResponse,
            },
            Details as ApiDetails,
        },
        TransportDetails as _,
    };

    #[repr(C)]
    pub struct TransportDetails {
        metadata: MessageMetadata,
        milestone: Milestone,
    }

    impl From<ApiDetails> for TransportDetails {
        fn from(d: ApiDetails) -> Self {
            Self {
                metadata: d.metadata.into(),
                milestone: d.milestone.map_or(Milestone::default(), |m| m.into()),
            }
        }
    }

    #[repr(C)]
    pub enum LedgerInclusionState {
        Conflicting,
        Included,
        NoTransaction,
    }

    impl From<LedgerInclusionStateDto> for LedgerInclusionState {
        fn from(e: LedgerInclusionStateDto) -> Self {
            match e {
                LedgerInclusionStateDto::Conflicting => Self::Conflicting,
                LedgerInclusionStateDto::Included => Self::Included,
                LedgerInclusionStateDto::NoTransaction => Self::NoTransaction,
            }
        }
    }

    #[repr(C)]
    pub struct MessageMetadata {
        pub message_id: [u8; 129],
        pub parent_message_ids: [[u8; 129]; 2],
        pub is_solid: bool,
        pub referenced_by_milestone_index: u32,
        pub milestone_index: u32,
        pub ledger_inclusion_state: LedgerInclusionState,
        pub conflict_reason: u8,
        pub should_promote: bool,
        pub should_reattach: bool,
        pub field_flags: u32,
    }

    impl Default for MessageMetadata {
        fn default() -> Self {
            unsafe { core::mem::MaybeUninit::zeroed().assume_init() }
        }
    }

    impl From<MessageMetadataResponse> for MessageMetadata {
        fn from(m: MessageMetadataResponse) -> Self {
            let mut r = MessageMetadata::default();
            let field_flags = 0_u32
                | {
                    let s = core::cmp::min(r.message_id.len() - 1, m.message_id.as_bytes().len());
                    r.message_id[..s].copy_from_slice(&m.message_id.as_bytes()[..s]);
                    1_u32 << 0
                }
                | {
                    if 0 < m.parent_message_ids.len() {
                        let s = core::cmp::min(
                            r.parent_message_ids[0].len() - 1,
                            m.parent_message_ids[0].as_bytes().len(),
                        );
                        r.parent_message_ids[0][..s].copy_from_slice(&m.parent_message_ids[0].as_bytes()[..s]);
                    }
                    if 1 < m.parent_message_ids.len() {
                        let s = core::cmp::min(
                            r.parent_message_ids[1].len() - 1,
                            m.parent_message_ids[1].as_bytes().len(),
                        );
                        r.parent_message_ids[1][..s].copy_from_slice(&m.parent_message_ids[1].as_bytes()[..s]);
                    }
                    // TODO: support more than 2 parents
                    // assert!(!(2 < m.parent_message_ids.len()));
                    1_u32 << 1
                }
                | {
                    r.is_solid = m.is_solid;
                    1_u32 << 2
                }
                | m.referenced_by_milestone_index.map_or(0_u32, |v| {
                    r.referenced_by_milestone_index = v;
                    1_u32 << 3
                })
                | m.milestone_index.map_or(0_u32, |v| {
                    r.milestone_index = v;
                    1_u32 << 4
                })
                | m.ledger_inclusion_state.map_or(0_u32, |v| {
                    r.ledger_inclusion_state = v.into();
                    1_u32 << 5
                })
                | m.conflict_reason.map_or(0_u32, |v| {
                    r.conflict_reason = v;
                    1_u32 << 6
                })
                | m.should_promote.map_or(0_u32, |v| {
                    r.should_promote = v;
                    1_u32 << 7
                })
                | m.should_reattach.map_or(0_u32, |v| {
                    r.should_reattach = v;
                    1_u32 << 8
                });
            r.field_flags = field_flags;
            r
        }
    }

    #[repr(C)]
    pub struct Milestone {
        pub milestone_index: u32,
        pub message_id: [u8; 129],
        pub timestamp: u64,
    }

    impl Default for Milestone {
        fn default() -> Self {
            unsafe { core::mem::MaybeUninit::zeroed().assume_init() }
        }
    }

    impl From<MilestoneResponse> for Milestone {
        fn from(m: MilestoneResponse) -> Self {
            let mut r = Milestone::default();
            r.milestone_index = m.index;
            {
                let s = core::cmp::min(r.message_id.len() - 1, m.message_id.as_ref().len());
                r.message_id[..s].copy_from_slice(&m.message_id.as_ref()[..s]);
            }
            r.timestamp = m.timestamp;
            r
        }
    }

    #[no_mangle]
    pub unsafe extern "C" fn transport_get_link_details(
        r: *mut TransportDetails,
        tsp: *mut TransportWrap,
        link: *const Address,
    ) -> Err {
        r.as_mut().map_or(Err::NullArgument, |r| {
            tsp.as_mut().map_or(Err::NullArgument, |tsp| {
                link.as_ref().map_or(Err::NullArgument, |link| {
                    run_async(tsp.get_link_details(link)).map_or(Err::OperationFailed, |d| {
                        *r = d.into();
                        Err::Ok
                    })
                })
            })
        })
    }
}

#[cfg(feature = "client")]
pub use client_details::*;

#[repr(C)]
pub struct MessageLinks {
    pub msg_link: *const Address,
    pub seq_link: *const Address,
}

impl From<(Address, Option<Address>)> for MessageLinks {
    fn from(links: (Address, Option<Address>)) -> Self {
        let msg_link = safe_into_ptr(links.0);
        let seq_link = links.1.map_or(null(), safe_into_ptr);
        Self { msg_link, seq_link }
    }
}

impl MessageLinks {
    pub unsafe fn into_seq_link<'a>(self, branching: bool) -> Option<&'a Address> {
        if !branching {
            self.msg_link.as_ref()
        } else {
            self.seq_link.as_ref()
        }
    }

    pub fn drop(self) {
        safe_drop_ptr(self.msg_link);
        safe_drop_ptr(self.seq_link);
    }
}

impl Default for MessageLinks {
    fn default() -> Self {
        Self {
            msg_link: null(),
            seq_link: null(),
        }
    }
}

#[no_mangle]
pub extern "C" fn drop_links(links: MessageLinks) {
    links.drop()
}

#[no_mangle]
pub unsafe extern "C" fn get_msg_link(msg_links: *const MessageLinks) -> *const Address {
    msg_links.as_ref().map_or(null(), |links| links.msg_link)
}

#[no_mangle]
pub unsafe extern "C" fn get_seq_link(msg_links: *const MessageLinks) -> *const Address {
    msg_links.as_ref().map_or(null(), |links| links.seq_link)
}

#[repr(C)]
pub struct Buffer {
    pub(crate) ptr: *const uint8_t,
    pub(crate) size: size_t,
    pub(crate) cap: size_t,
}

impl From<Vec<u8>> for Buffer {
    fn from(vec: Vec<u8>) -> Self {
        let p = core::mem::ManuallyDrop::new(vec);
        Self {
            ptr: p.as_ptr(),
            size: p.len(),
            cap: p.capacity(),
        }
    }
}

impl Default for Buffer {
    fn default() -> Self {
        Self {
            ptr: null(),
            size: 0,
            cap: 0,
        }
    }
}

impl From<Bytes> for Buffer {
    fn from(b: Bytes) -> Self {
        let p = core::mem::ManuallyDrop::new(b.0);
        Self {
            ptr: p.as_ptr(),
            size: p.len(),
            cap: p.capacity(),
        }
    }
}

impl From<Buffer> for Bytes {
    fn from(b: Buffer) -> Self {
        unsafe { Self(Vec::from_raw_parts(b.ptr as *mut u8, b.size, b.cap)) }
    }
}

impl From<Buffer> for Vec<u8> {
    fn from(b: Buffer) -> Self {
        unsafe { Vec::from_raw_parts(b.ptr as *mut u8, b.size, b.cap) }
    }
}

impl<'a> From<&'a Bytes> for Buffer {
    fn from(b: &Bytes) -> Self {
        let p = &b.0;
        Self {
            ptr: p.as_ptr(),
            size: p.len(),
            cap: p.capacity(),
        }
    }
}

impl Buffer {
    pub fn new(size: usize) -> Self {
        Bytes(Vec::with_capacity(size)).into()
    }
    pub fn drop(self) {
        let _b: Bytes = self.into();
    }
}

#[no_mangle]
pub extern "C" fn drop_buffer(b: Buffer) {
    b.drop()
}

#[repr(C)]
pub struct PacketPayloads {
    public_payload: Buffer,
    masked_payload: Buffer,
}

impl Default for PacketPayloads {
    fn default() -> Self {
        Self {
            public_payload: Buffer::default(),
            masked_payload: Buffer::default(),
        }
    }
}

impl From<(Bytes, Bytes)> for PacketPayloads {
    fn from(payloads: (Bytes, Bytes)) -> Self {
        Self {
            public_payload: Buffer::from(payloads.0),
            masked_payload: Buffer::from(payloads.1),
        }
    }
}

impl<'a> From<(&'a Bytes, &'a Bytes)> for PacketPayloads {
    fn from(payloads: (&Bytes, &Bytes)) -> Self {
        Self {
            public_payload: Buffer::from(payloads.0),
            masked_payload: Buffer::from(payloads.1),
        }
    }
}

impl From<(PublicKey, Bytes, Bytes)> for PacketPayloads {
    fn from(signed_payloads: (PublicKey, Bytes, Bytes)) -> Self {
        let payloads = (signed_payloads.1, signed_payloads.2);
        PacketPayloads::from(payloads)
    }
}

impl PacketPayloads {
    pub fn drop(self) {
        self.public_payload.drop();
        self.masked_payload.drop();
    }
}

#[no_mangle]
pub extern "C" fn drop_payloads(payloads: PacketPayloads) {
    payloads.drop()
}

#[no_mangle]
pub unsafe extern "C" fn drop_str(string: *const c_char) {
    CString::from_raw(string as *mut c_char);
}

#[no_mangle]
pub unsafe extern "C" fn get_channel_address_str(appinst: *const ChannelAddress) -> *const c_char {
    appinst.as_ref().map_or(null(), |inst| {
        // Calling `to_hex_string()` instead of `to_string()` certifies that the String won't contain
        // a null byte, so that we can call `string_into_raw_unchecked()`
        string_into_raw_unchecked(inst.to_hex_string())
    })
}

#[no_mangle]
pub unsafe extern "C" fn get_msgid_str(msgid: *const MsgId) -> *const c_char {
    msgid
        .as_ref()
        .map_or(null(), |id| string_into_raw_unchecked(id.to_hex_string()))
}

#[no_mangle]
pub unsafe extern "C" fn get_address_inst_str(address: *const Address) -> *const c_char {
    address
        .as_ref()
        .map_or(null(), |addr| get_channel_address_str(&addr.appinst))
}

#[no_mangle]
pub unsafe extern "C" fn get_address_id_str(address: *const Address) -> *const c_char {
    address.as_ref().map_or(null(), |addr| get_msgid_str(&addr.msgid))
}

#[no_mangle]
pub unsafe extern "C" fn get_address_index_str(address: *const Address) -> *const c_char {
    address.as_ref().map_or(null(), |addr| {
        let index = addr.to_msg_index();
        let index_hex = format!("{:x}", index);
        string_into_raw_unchecked(index_hex)
    })
}

#[no_mangle]
pub unsafe extern "C" fn get_payload(msg: *const UnwrappedMessage) -> PacketPayloads {
    msg.as_ref().map_or(PacketPayloads::default(), handle_message_contents)
}

#[no_mangle]
pub unsafe extern "C" fn get_payloads_count(msgs: *const UnwrappedMessages) -> usize {
    msgs.as_ref().map_or(0, |msgs| msgs.len())
}

#[no_mangle]
pub unsafe extern "C" fn get_indexed_payload(msgs: *const UnwrappedMessages, index: size_t) -> PacketPayloads {
    msgs.as_ref()
        .map_or(PacketPayloads::default(), |msgs| handle_message_contents(&msgs[index]))
}

fn handle_message_contents(m: &UnwrappedMessage) -> PacketPayloads {
    match &m.body {
        MessageContent::TaggedPacket {
            public_payload: p,
            masked_payload: m,
        } => (p, m).into(),

        MessageContent::SignedPacket {
            pk: _,
            public_payload: p,
            masked_payload: m,
        } => (p, m).into(),

        _ => PacketPayloads::default(),
    }
}
*/
mod auth;
pub use auth::*;

//mod sub;
//pub use sub::*;
use core::future::Future;
use core::str::FromStr;
use once_cell::sync::OnceCell;
use tokio::runtime::Runtime;
use streams::id::{Identifier, PermissionDuration, Permissioned, PskId};
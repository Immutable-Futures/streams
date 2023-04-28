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

/// Retrieve a pointer to the last error string
#[no_mangle]
pub unsafe extern "C" fn get_last_error() -> *const c_char {
    string_into_raw_unchecked(String::from_utf8_unchecked(LAST_ERROR.clone()))
}

/// Return Values
#[repr(C)]
pub enum Err {
    Ok,
    NullArgument,
    BadArgument,
    OperationFailed,
}

/// Capture latest error into global `LAST_ERROR` variable, returning `OperationFailed`
pub unsafe fn operation_failed<E: Display>(e: E) -> Err {
    LAST_ERROR = e.to_string().into_bytes();
    Err::OperationFailed
}

/// User Permission Types
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

// Pointers

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


// Data Buffer

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


/// Stores the Runtime instance for the session
static INSTANCE: OnceCell<Runtime> = OnceCell::new();

/// Uses the stored runtime to block call a future
pub fn run_async<C: Future>(cb: C) -> C::Output {
    let runtime = INSTANCE.get_or_init(|| Runtime::new().unwrap());
    runtime.block_on(cb)
}


/// Create a default `TransportWrap` instance
#[no_mangle]
pub extern "C" fn transport_new() -> *mut TransportWrap {
    safe_into_mut_ptr(TransportWrap::default())
}

/// Drop a `TransportWrap` instance
#[no_mangle]
pub extern "C" fn transport_drop(tsp: *mut TransportWrap) {
    safe_drop_mut_ptr(tsp)
}


/// Create a `uClient` `TransportWrap` for use in a `User` instance
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
pub unsafe extern "C" fn pskid_as_str(pskid: *const PskId) -> *const c_char {
    pskid
        .as_ref()
        .map_or(null(), |pskid| string_into_raw_unchecked(hex::encode(&pskid)))
}

#[no_mangle]
pub unsafe extern "C" fn drop_pskid(pskid: *const PskId) {
    safe_drop_ptr(pskid)
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


/// Make a new `Permissioned` wrapper from `Identifier`. Returns `NullArgument` if provided
/// `Identifier` is null.
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


/// Utility wrapper for permissions to be injected into a stream.
#[repr(C)]
pub struct IdLists {
    /// List of [`Permissioned`]
    user_ids: Vec<Permissioned<Identifier>>,
    /// List of `Read` permissioned [`PskId`]'s
    psk_ids: Vec<PskId>,
}

impl IdLists {
    /// Create a default `IdLists` with empty lists
    fn new() -> Self {
        Self {
            user_ids: Vec::new(),
            psk_ids: Vec::new(),
        }
    }

    /// Insert a new [`Permissioned`] wrapped `Identifier` to the list
    ///
    /// # Arguments
    ///  * `id`: permission wrapped identifier
    fn push_user_id(&mut self, id: Permissioned<Identifier>) {
        self.user_ids.push(id)
    }

    /// Insert a new [`PskId`] to the list
    ///
    /// # Arguments
    ///  * `id`: pre shared key identifier
    fn push_psk_id(&mut self, id: PskId) {
        self.psk_ids.push(id)
    }

    /// Remove a [`Permissioned`] wrapped `Identifier` from the list
    ///
    /// # Arguments
    ///  * `id`: identifier
    fn remove_user_id(&mut self, id: &Identifier) {
        self.user_ids.retain(|i| i.identifier() != id)
    }

    /// Remove a [`PskId`] from the list
    ///
    /// # Arguments
    ///  * `id`: pre shared key identifier
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

mod user;
pub use user::*;

//mod sub;
//pub use sub::*;
use core::future::Future;
use core::str::FromStr;
use once_cell::sync::OnceCell;
use tokio::runtime::Runtime;
use streams::id::{Identifier, PermissionDuration, Permissioned, PskId};
use alloc::vec::Vec;
use streams::id::{Ed25519, Identifier};
use super::*;
use cstr_core::CStr;

pub type User = streams::User<TransportWrap>;

/// Generate a new user Instance
#[no_mangle]
pub unsafe extern "C" fn new_user_with_seed(
    c_user: *mut *mut User,
    c_seed: *const c_char,
    transport: *mut TransportWrap,
) -> Err {
    if c_seed == null() {
        return Err::NullArgument;
    }

    CStr::from_ptr(c_seed).to_str().map_or(Err::BadArgument, |seed| {
        transport.as_mut().map_or(Err::NullArgument, |tsp| {
            c_user.as_mut().map_or(Err::NullArgument, |u| {
                let user = streams::User::builder()
                    .with_identity(Ed25519::from_seed(seed))
                    .with_transport(tsp.clone())
                    .build();
                *u = safe_into_mut_ptr(user);
                Err::Ok
            })
        })
    })
}

/// Recover an existing channel from seed and existing announcement message
#[no_mangle]
pub unsafe extern "C" fn recover_user(
    c_user: *mut *mut User,
    c_seed: *const c_char,
    transport: *mut TransportWrap,
) -> Err {
    if c_seed == null() {
        return Err::NullArgument;
    }

    CStr::from_ptr(c_seed).to_str().map_or(Err::BadArgument, |seed| {
            transport.as_mut().map_or(Err::NullArgument, |tsp| {
                c_user.as_mut().map_or(Err::NullArgument, |u| {
                    let mut user = streams::User::builder()
                        .with_identity(Ed25519::from_seed(seed))
                        .with_transport(tsp.clone())
                        .build();
                    run_async(user.sync()).map_or(Err::OperationFailed, |_count| {
                            *u = safe_into_mut_ptr(user);
                            Err::Ok
                        })
                })
        })
    })
}

/// Import an user instance from an encrypted binary array
#[no_mangle]
pub unsafe extern "C" fn import_user(
    c_user: *mut *mut User,
    buffer: Buffer,
    c_password: *const c_char,
    transport: *mut TransportWrap,
) -> Err {
    if c_password == null() {
        return Err::NullArgument;
    }

    CStr::from_ptr(c_password).to_str().map_or(Err::BadArgument, |password| {
        transport.as_mut().map_or(Err::NullArgument, |tsp| {
            c_user.as_mut().map_or(Err::NullArgument, |u| {
                let bytes_vec: Vec<_> = buffer.into();
                run_async(User::restore(&bytes_vec, password, tsp.clone()))
                    .map_or(Err::OperationFailed, |user| {
                    *u = safe_into_mut_ptr(user);
                    Err::Ok
                })
            })
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn export_user(buf: *mut Buffer, c_user: *mut User, c_password: *const c_char) -> Err {
    if c_password == null() {
        return Err::NullArgument;
    }

    CStr::from_ptr(c_password).to_str().map_or(Err::BadArgument, |password| {
        c_user.as_mut().map_or(Err::NullArgument, |user| {
            buf.as_mut().map_or(Err::NullArgument, |buf| {
                run_async(user.backup(password))
                    .map_or(Err::OperationFailed, |bytes| {
                    *buf = bytes.into();
                    Err::Ok
                })
            })
        })
    })
}

#[no_mangle]
pub extern "C" fn drop_user(user: *mut User) {
    safe_drop_mut_ptr(user)
}

/// Stream announcement address.
#[no_mangle]
pub unsafe extern "C" fn stream_address(addr: *mut *const Address, user: *const User) -> Err {
    user.as_ref().map_or(Err::NullArgument, |user| {
        addr.as_mut().map_or(Err::NullArgument, |addr| {
            user.stream_address().map_or(Err::OperationFailed, |stream_address| {
                *addr = safe_into_ptr(stream_address);
                Err::Ok
            })
        })
    })
}

/// User Identifier
#[no_mangle]
pub unsafe extern "C" fn identifier(id: *mut *const Identifier, user: *const User) -> Err {
    user.as_ref().map_or(Err::NullArgument, |user| {
        id.as_mut().map_or(Err::NullArgument, |id| {
            user.identifier().map_or(Err::OperationFailed, |user_id| {
                *id = user_id as *const Identifier;
                Err::Ok
            })
        })
    })
}

/// Announce creation of a new stream.
#[no_mangle]
pub unsafe extern "C" fn create_stream(addr: *mut *const Address, user: *mut User, base_branch: *const c_char) -> Err {
    CStr::from_ptr(base_branch).to_str().map_or(Err::BadArgument, |base_branch| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            addr.as_mut().map_or(Err::NullArgument, |addr| {
                run_async(user.create_stream(base_branch)).map_or(Err::OperationFailed, |resp| {
                    *addr = safe_into_ptr(resp.address());
                    Err::Ok
                })
            })
        })
    })
}


/// Subscribe to a stream
#[no_mangle]
pub unsafe extern "C" fn subscribe(
    sub_link: *mut *const Address,
    user: *mut User,
) -> Err {
    sub_link.as_mut().map_or(Err::NullArgument, |s_link| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            run_async(user.subscribe())
                .map_or(Err::OperationFailed, |resp| -> Err {
                    *s_link = safe_into_ptr(resp.address());
                    Err::Ok
                })
        })
    })
}

/// Subscribe to a stream
#[no_mangle]
pub unsafe extern "C" fn unsubscribe(
    unsub_link: *mut *const Address,
    user: *mut User,
) -> Err {
    unsub_link.as_mut().map_or(Err::NullArgument, |u_link| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            run_async(user.unsubscribe())
                .map_or(Err::OperationFailed, |resp| -> Err {
                    *u_link = safe_into_ptr(resp.address());
                    Err::Ok
                })
        })
    })
}


/// Create a new branch
#[no_mangle]
pub unsafe extern "C" fn new_branch(
    r: *mut *const Address,
    user: *mut User,
    old_topic: *const c_char,
    new_topic: *const c_char,
) -> Err {
    r.as_mut().map_or(Err::NullArgument, |r| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            CStr::from_ptr(old_topic).to_str().map_or(Err::BadArgument, |old_topic| {
                CStr::from_ptr(new_topic).to_str().map_or(Err::BadArgument, |new_topic| {
                    run_async(user.new_branch(old_topic, new_topic))
                        .map_or(Err::OperationFailed, |resp| {
                            *r = safe_into_ptr(resp.address());
                            Err::Ok
                        })
                })
            })
        })
    })
}

/// Create a new keyload for a list of subscribers.
#[no_mangle]
pub unsafe extern "C" fn update_permissions(
    r: *mut *const Address,
    user: *mut User,
    topic: *const c_char,
    ids: *const IdLists,
) -> Err {
    r.as_mut().map_or(Err::NullArgument, |r| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            CStr::from_ptr(topic).to_str().map_or(Err::BadArgument, |topic| {
                ids.as_ref().map_or(Err::NullArgument, |ids| {
                    run_async(
                        user.send_keyload(topic, ids.user_ids.iter().map(|id| id.as_ref()), ids.psk_ids.iter().map(|id| *id))
                    )
                    .map_or(Err::OperationFailed, |response| {
                        *r = safe_into_ptr(response.address());
                        Err::Ok
                    })
                })
            })
        })
    })
}

/// Send Message
#[no_mangle]
pub unsafe extern "C" fn send_message(
    r: *mut *const Address,
    user: *mut User,
    topic: *const c_char,
    payload_ptr: *const u8,
    payload_size: size_t,
    signed: u8,
    masked: u8,
) -> Err {
    r.as_mut().map_or(Err::NullArgument, |r| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            CStr::from_ptr(topic).to_str().map_or(Err::BadArgument, |topic| {
                let payload = core::slice::from_raw_parts(payload_ptr as *mut u8, payload_size);
                let mut message = user.message()
                    .with_topic(topic)
                    .with_payload(payload);

                if signed != 0 {
                    message = message.signed();
                }
                if masked == 0 {
                    message = message.public();
                }

                run_async(message.send())
                    .map_or(Err::OperationFailed, |response| {
                        *r = safe_into_ptr(response.address());
                        Err::Ok
                    })
            })
        })
    })
}




/// Receive and process a message
#[no_mangle]
pub unsafe extern "C" fn receive_message(
    message: *mut *const Message,
    user: *mut User,
    address: *const Address,
) -> Err {
    message.as_mut().map_or(Err::NullArgument, |m| {
        address.as_ref().map_or(Err::NullArgument, |addr| {
            user.as_mut().map_or(Err::NullArgument, |user| {
                match run_async(user.receive_message(*addr)) {
                    Ok(msg) => {
                        let msg_wrap: Message = msg.into();
                        *m = safe_into_ptr(msg_wrap);
                        Err::Ok
                    },
                    Err(e) => operation_failed(e)
            }
            })
        })
    })
}

/// Fetch next message
#[no_mangle]
pub unsafe extern "C" fn fetch_next_message(
    message: *mut *const Message,
    user: *mut User,
) -> Err {
    message.as_mut().map_or(Err::NullArgument, |m| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            run_async(user.messages().next()).map_or(Err::OperationFailed, |message| {
                match message {
                    Ok(msg) => {
                        let msg_wrap: Message = msg.into();
                        *m = safe_into_ptr(msg_wrap);
                        Err::Ok
                    },
                    Err(e) => operation_failed(e)
                }
            })
        })
    })
}

/// Check message for role in branch. Returns Bad Argument if the message is not a keyload. Fails the
/// operation if the message cannot be retrieved via the address provided in it, or if the user is not
/// subscribed to the keyload.
#[no_mangle]
pub unsafe extern "C" fn user_role(
    user_role: *mut *const PermissionType,
    user: *mut User,
    message: *const Message,
) -> Err {
    user_role.as_mut().map_or(Err::NullArgument, |user_role| {
        message.as_ref().map_or(Err::NullArgument, |message| {
            message.address.as_ref().map_or(Err::NullArgument, |address| {
                match message.message_type {
                    MessageType::Keyload => {
                        user.as_mut().map_or(Err::NullArgument, |user| {
                            match run_async(user.receive_message(*address)) {
                                Ok(keyload) => {
                                    match keyload.content {
                                        MessageContent::Keyload(k) => {
                                            k.subscribers
                                                .iter()
                                                .find(|perm| perm.identifier() == user.identifier().unwrap())
                                                .map_or(Err::OperationFailed, |role| {
                                                    *user_role = match role {
                                                        Permissioned::Read(_) => safe_into_ptr(PermissionType::Read),
                                                        _ => safe_into_ptr(PermissionType::Write),
                                                    };
                                                    Err::Ok
                                                })
                                        }
                                        _ => Err::BadArgument
                                    }
                                },
                                Err(e) => operation_failed(e)
                            }
                        })
                    },
                    _ => Err::BadArgument
                }
            })
        })
    })

}


/*
/// Unwrap and add a subscriber to the list of subscribers

/// Create a new keyload for a list of subscribers.
#[no_mangle]
pub unsafe extern "C" fn auth_send_keyload(
    r: *mut MessageLinks,
    user: *mut User,
    link_to: *const Address,
    psk_ids: *const PskIds,
    ke_pks: *const KePks,
) -> Err {
    r.as_mut().map_or(Err::NullArgument, |r| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            link_to.as_ref().map_or(Err::NullArgument, |link_to| {
                psk_ids.as_ref().map_or(Err::NullArgument, |psk_ids| {
                    ke_pks.as_ref().map_or(Err::NullArgument, |ke_pks| {
                        let pks = ke_pks.into_iter().copied().map(Into::<Identifier>::into);
                        let psks = psk_ids.into_iter().copied().map(Into::<Identifier>::into);
                        let identifiers: Vec<Identifier> = pks.chain(psks).collect();
                        run_async(user.send_keyload(link_to, &identifiers))
                            .map_or(Err::OperationFailed, |response| {
                                *r = response.into();
                                Err::Ok
                            })
                    })
                })
            })
        })
    })
}

/// Create keyload for all subscribed subscribers.
#[no_mangle]
pub unsafe extern "C" fn auth_send_keyload_for_everyone(
    r: *mut MessageLinks,
    user: *mut User,
    link_to: *const Address,
) -> Err {
    r.as_mut().map_or(Err::NullArgument, |r| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            link_to.as_ref().map_or(Err::NullArgument, |link_to| {
                run_async(user.send_keyload_for_everyone(link_to))
                    .map_or(Err::OperationFailed, |response| {
                        *r = response.into();
                        Err::Ok
                    })
            })
        })
    })
}

/// Process a Tagged packet message
#[no_mangle]
pub unsafe extern "C" fn auth_send_tagged_packet(
    r: *mut MessageLinks,
    user: *mut User,
    link_to: MessageLinks,
    public_payload_ptr: *const uint8_t,
    public_payload_size: size_t,
    masked_payload_ptr: *const uint8_t,
    masked_payload_size: size_t,
) -> Err {
    r.as_mut().map_or(Err::NullArgument, |r| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            link_to
                .into_seq_link(user.is_multi_branching())
                .map_or(Err::NullArgument, |link_to| {
                    let public_payload = Bytes(Vec::from_raw_parts(
                        public_payload_ptr as *mut u8,
                        public_payload_size,
                        public_payload_size,
                    ));
                    let masked_payload = Bytes(Vec::from_raw_parts(
                        masked_payload_ptr as *mut u8,
                        masked_payload_size,
                        masked_payload_size,
                    ));
                    let e = run_async(user
                        .send_tagged_packet(link_to, &public_payload, &masked_payload))
                        .map_or(Err::OperationFailed, |response| {
                            *r = response.into();
                            Err::Ok
                        });
                    let _ = core::mem::ManuallyDrop::new(public_payload.0);
                    let _ = core::mem::ManuallyDrop::new(masked_payload.0);
                    e
                })
        })
    })
}

/// Process a Tagged packet message
#[no_mangle]
pub unsafe extern "C" fn auth_receive_tagged_packet(
    r: *mut PacketPayloads,
    user: *mut User,
    link: *const Address,
) -> Err {
    r.as_mut().map_or(Err::NullArgument, |r| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            link.as_ref().map_or(Err::NullArgument, |link| {
                run_async(user.receive_tagged_packet(link))
                    .map_or(Err::OperationFailed, |tagged_payloads| {
                        *r = tagged_payloads.into();
                        Err::Ok
                    })
            })
        })
    })
}

/// Process a Signed packet message
#[no_mangle]
pub unsafe extern "C" fn auth_send_signed_packet(
    r: *mut MessageLinks,
    user: *mut User,
    link_to: MessageLinks,
    public_payload_ptr: *const uint8_t,
    public_payload_size: size_t,
    masked_payload_ptr: *const uint8_t,
    masked_payload_size: size_t,
) -> Err {
    r.as_mut().map_or(Err::NullArgument, |r| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            link_to
                .into_seq_link(user.is_multi_branching())
                .map_or(Err::NullArgument, |link_to| {
                    let public_payload = Bytes(Vec::from_raw_parts(
                        public_payload_ptr as *mut u8,
                        public_payload_size,
                        public_payload_size,
                    ));
                    let masked_payload = Bytes(Vec::from_raw_parts(
                        masked_payload_ptr as *mut u8,
                        masked_payload_size,
                        masked_payload_size,
                    ));
                    let e = run_async(user
                        .send_signed_packet(link_to, &public_payload, &masked_payload))
                        .map_or(Err::OperationFailed, |response| {
                            *r = response.into();
                            Err::Ok
                        });
                    let _ = core::mem::ManuallyDrop::new(public_payload.0);
                    let _ = core::mem::ManuallyDrop::new(masked_payload.0);
                    e
                })
        })
    })
}

/// Process a Signed packet message
#[no_mangle]
pub unsafe extern "C" fn auth_receive_signed_packet(
    r: *mut PacketPayloads,
    user: *mut User,
    link: *const Address,
) -> Err {
     r.as_mut().map_or(Err::NullArgument, |r| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            link.as_ref().map_or(Err::NullArgument, move |link|{
                run_async(user.receive_signed_packet(link)).map_or(Err::OperationFailed, |signed_payloads| {
                        *r = signed_payloads.into();
                        Err::Ok
                    })
            })
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_receive_sequence(r: *mut *const Address, user: *mut User, link: *const Address) -> Err {
    r.as_mut().map_or(Err::NullArgument, |r| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            link.as_ref().map_or(Err::NullArgument, |link| {
                run_async(user.receive_sequence(link)).map_or(Err::OperationFailed, |seq_link| {
                    *r = safe_into_ptr(seq_link);
                    Err::Ok
                })
            })
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_gen_next_msg_ids(ids: *mut *const NextMsgIds, user: *mut User) -> Err {
    user.as_mut().map_or(Err::NullArgument, |user| {
        ids.as_mut().map_or(Err::NullArgument, |ids| {
            let next_msg_ids = user.gen_next_msg_ids(user.is_multi_branching());
            *ids = safe_into_ptr(next_msg_ids);
            Err::Ok
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_receive_msg(
    r: *mut *const UnwrappedMessage,
    user: *mut User,
    link: *const Address,
) -> Err {
    r.as_mut().map_or(Err::NullArgument, |r| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            link.as_ref().map_or(Err::NullArgument, |link| {
                run_async(user.receive_msg(link)).map_or(Err::OperationFailed, |u| {
                    *r = safe_into_ptr(u);
                    Err::Ok
                })
            })
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_receive_msg_by_sequence_number(
    r: *mut *const UnwrappedMessage,
    user: *mut User,
    anchor_link: *const Address,
    msg_num: size_t,
) -> Err {
    r.as_mut().map_or(Err::NullArgument, |r| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            anchor_link.as_ref().map_or(Err::NullArgument, |link| {
                run_async(user.receive_msg_by_sequence_number(link, msg_num as u32)).map_or(Err::OperationFailed, |u| {
                    *r = safe_into_ptr(u);
                    Err::Ok
                })
            })
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_fetch_next_msgs(umsgs: *mut *const UnwrappedMessages, user: *mut User) -> Err {
    user.as_mut().map_or(Err::NullArgument, |user| {
        umsgs.as_mut().map_or(Err::NullArgument, |umsgs| {
            let m = run_async(user.fetch_next_msgs());
            *umsgs = safe_into_ptr(m);
            Err::Ok
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_fetch_prev_msg(m: *mut *const UnwrappedMessage, user: *mut User, address: *const Address) -> Err {
    m.as_mut().map_or(Err::NullArgument, |m| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            address.as_ref().map_or(Err::NullArgument, |addr| {
                run_async(user.fetch_prev_msg(addr)).map_or(Err::OperationFailed, |msg| {
                    *m = safe_into_ptr(msg);
                    Err::Ok
                })
            })
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_fetch_prev_msgs(umsgs: *mut *const UnwrappedMessages, user: *mut User, address: *const Address, num_msgs: size_t) -> Err {
    umsgs.as_mut().map_or(Err::NullArgument, |umsgs| {
        user.as_mut().map_or(Err::NullArgument, |user| {
            address.as_ref().map_or(Err::NullArgument, |addr| {
                run_async(user.fetch_prev_msgs(addr, num_msgs)).map_or(Err::OperationFailed, |msgs| {
                    *umsgs = safe_into_ptr(msgs);
                    Err::Ok
                })
            })
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_sync_state(umsgs: *mut *const UnwrappedMessages, user: *mut User) -> Err {
    user.as_mut().map_or(Err::NullArgument, |user| {
        umsgs.as_mut().map_or(Err::NullArgument, |umsgs| {
            let mut ms = Vec::new();
            loop {
                let m = run_async(user.fetch_next_msgs());
                if m.is_empty() {
                    break;
                }
                ms.extend(m);
            }
            *umsgs = safe_into_ptr(ms);
            Err::Ok
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_fetch_state(state: *mut *const UserState, user: *mut User) -> Err {
    user.as_mut().map_or(Err::NullArgument, |user| {
        state.as_mut().map_or(Err::NullArgument, |state| {
            user.fetch_state().map_or(Err::OperationFailed, |st| {
                *state = safe_into_ptr(st);
                Err::Ok
            })
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_reset_state(user: *mut User) -> Err {
    user.as_mut().map_or(Err::NullArgument, |user| {
        user.reset_state().map_or(Err::OperationFailed, |_| Err::Ok)
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_store_psk(c_pskid: *mut *const PskId, c_user: *mut User, c_psk_seed: *const c_char) -> Err {
    if c_psk_seed == null() {
        return Err::NullArgument;
    }

    CStr::from_ptr(c_psk_seed).to_str().map_or(Err::BadArgument, |psk_seed| {
        c_user.as_mut().map_or(Err::NullArgument, |user| {
            c_pskid.as_mut().map_or(Err::NullArgument, |pskid| {
                let psk = psk_from_seed(psk_seed.as_ref());
                let id = pskid_from_psk(&psk);
                user.store_psk(id, psk).map_or(Err::OperationFailed, |_| {
                    *pskid = safe_into_ptr(id);
                    Err::Ok
                })
            })
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_remove_psk(c_user: *mut User, c_pskid: *const PskId) -> Err {
    c_user.as_mut().map_or(Err::NullArgument, |user| {
        c_pskid.as_ref().map_or(Err::NullArgument, |pskid| {
            user.remove_psk(*pskid).map_or(Err::OperationFailed, |_| Err::Ok)
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_store_new_subscriber(c_user: *mut User, c_pk: *const PublicKey) -> Err {
    c_user.as_mut().map_or(Err::NullArgument, |user| {
        c_pk.as_ref().map_or(Err::NullArgument, |pk| {
            user.store_new_subscriber(*pk).map_or(Err::OperationFailed, |_| Err::Ok)
        })
    })
}

#[no_mangle]
pub unsafe extern "C" fn auth_remove_subscriber(c_user: *mut User, c_pk: *const PublicKey) -> Err {
    c_user.as_mut().map_or(Err::NullArgument, |user| {
        c_pk.as_ref().map_or(Err::NullArgument, |pk| {
            user.remove_subscriber(*pk).map_or(Err::OperationFailed, |_| Err::Ok)
        })
    })
} */
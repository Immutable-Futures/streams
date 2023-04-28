use alloc::vec::Vec;
use streams::id::{Ed25519, Identifier};
use super::*;
use cstr_core::CStr;

/// User Instance using a [`TransportWrap`] client
pub type User = streams::User<TransportWrap>;


/// Generate a new [`User`] instance from a unique seed and [`TransportWrap`].
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


/// Recover an existing stream using the `User` seed. If the [`User`] instance is unable to sync its
/// state, an `OperationFailed` error will be returned.
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


/// Import a [`User`] instance from an encrypted binary array. If the provided password doesn't
/// match or the binary array is corrupted, an `OperationFailed` error will be returned.
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


/// Export a [`User`] instance into an encrypted binary array. If the serializing of the user is
/// unable to complete correctly, an `OperationFailed` error will be returned.
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


/// Return the Stream `Announcement` [`Address`]. If the user isn't attached to a stream yet, an
/// `OperationFailed` error will be returned.
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


/// Returns the [`User`] instance [`Identifier`]. If the user was created without an `Identity`, an
/// `OperationFailed` error will be returned.
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


/// Send an `Announce` message, signifying the creation of a new stream. If an announcement message
/// with the same address already exists, an `OperationFailed` error will be returned.
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


/// Send a `Subscribe` message informing the stream author that you are subscribing to their
/// stream. When this message is processed, the administrative `User` will add the sender to their
/// cursor storage. If the message fails to send, or the user has not subscribed to the stream yet,
/// an `OperationFailed` error will be returned.
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


/// Send an `Unsubscribe` message informing the stream author that you are unsubscribing from their
/// stream. When this message is processed, users will remove the sender from their cursor storage.
/// If the message fails to send, or the user has not subscribed to the stream yet, an
/// `OperationFailed` error will be returned.
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


/// Create a new branch within a stream. Provide the [`Topic`] of the branch the new branch will be
/// built off of, and the [`Topic`] that will be used to identify the new branch. If the branch
/// already exists, or if the user does not have write permissions, an `OperationFailed` error will
/// be returned.
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


/// Create a new `Keyload` message with a list of permissions for a specified branch `Topic`. The
/// permissions can be provided through an [`IdLists`] structure. If the keyload fails to send an
/// `OperationFailed` error will be returned.
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


/// Send a new `Message` to a stream with a provided `User` instance and branch `Topic`. A `User`
/// client will try to send the provided payload to the stream in the specified branch. The message
/// can be 0: unsigned or 1: signed (the former will be sent as a `TaggedPacket`, while the latter
/// will be sent as a `SignedPacket`), and the payload can be 0: public or 1: masked (raw encoded or
/// encrypted). If the message fails to send (usually the result of not having permission for the
/// specified `Topic`, an `OperationFailed` error will be returned. If the message sends correctly,
/// the `Address` of the message will be returned.
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


/// Receive and process a message via a given address. This is used to process a message with a known
/// location, rather than through discovery. This is relevant for retrieving specific message details
/// after mapping in an external application/store. Used to receive the `Announcement` messages that
/// designate the root of a stream. If the message cannot be found, an `OperationFailed` message is
/// returned.
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


/// Fetch the next available message from the stream. If no new message is found, the operation will
/// return with an OperationFailed error. If a message is found, it is converted into a `Message`
/// struct and returned.
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
// Rust
use alloc::{boxed::Box, vec::Vec};

// 3rd-party
use async_trait::async_trait;

// IOTA

// Streams

// Local
use crate::{
    address::Address,
    error::{Error, Result},
};

/// Network transport abstraction.
/// Parametrized by the type of message addresss.
/// Message address is used to identify/locate a message (eg. like URL for HTTP).
#[async_trait]
pub trait Transport<'a> {
    type Msg;
    type SendResponse;
    /// Send a message
    async fn send_message(&mut self, address: Address, msg: Self::Msg) -> Result<Self::SendResponse>
    where
        'a: 'async_trait;

    /// Receive messages
    async fn recv_messages(&mut self, address: Address) -> Result<Vec<Self::Msg>>
    where
        'a: 'async_trait;

    /// Receive a single message
    async fn recv_message(&mut self, address: Address) -> Result<Self::Msg> {
        let mut msgs = self.recv_messages(address).await?;
        if let Some(msg) = msgs.pop() {
            match msgs.is_empty() {
                true => Ok(msg),
                false => Err(Error::AddressError("More than one found", address)),
            }
        } else {
            Err(Error::AddressError("not found in transport", address))
        }
    }
}

/// Localised mapping for tests and simulations
#[cfg(feature = "bucket")]
pub mod bucket;
/// `sqlx` based mysql client
#[cfg(feature = "mysql-client")]
pub mod mysql;
/// `iota.rs` based tangle client
#[cfg(any(feature = "tangle-client", feature = "tangle-client-wasm"))]
pub mod tangle;
/// Localised micro tangle client
#[cfg(feature = "utangle-client")]
pub mod utangle;

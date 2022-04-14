// Rust
use alloc::{
    boxed::Box,
    vec::Vec,
};
use core::fmt::Display;

// 3rd-party
use anyhow::{
    ensure,
    Result,
};
use async_trait::async_trait;
use futures::{
    future::{
        join_all,
        try_join_all,
    },
    TryFutureExt,
};

// IOTA
use iota_client::bee_message::Message as IotaMessage;

// Streams

// Local
use crate::transport::Transport;

// TODO: REMOVE
// use core::fmt;

// use futures::{
//     executor::block_on,
//     future::join_all,
// };

// use iota_streams_core::{
//     async_trait,
//     prelude::Box,
// };

// use iota_client;

// use iota_client::{
//     bee_rest_api::types::responses::MessageMetadataResponse,
//     MilestoneResponse,
// };

// use iota_client::bee_message::{
//     payload::Payload,
//     Message,
// };

// use iota_streams_core::{
//     err,
//     prelude::Vec,
//     try_or,
//     wrapped_err,
//     Errors::*,
//     Result,
//     WrappedError,
// };

// use crate::{
//     message::BinaryMessage,
//     transport::{
//         tangle::*,
//         *,
//     },
// };

// use iota_streams_core::prelude::String;

// #[cfg(feature = "did")]
// use identity::iota::{
//     Client as DIDClient,
//     Network,
// };

// /// Options for the user Client
// #[derive(Clone)]
// struct SendOptions {
//     url: String,
//     local_pow: bool,
// }

// impl Default for SendOptions {
//     fn default() -> Self {
//         Self {
//             url: "https://chrysalis-nodes.iota.org".to_string(),
//             local_pow: true,
//         }
//     }
// }

// #[derive(Clone, Debug)]
// struct Details {
//     metadata: MessageMetadataResponse,
//     milestone: Option<MilestoneResponse>,
// }

// impl fmt::Display for Details {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
//         write!(f, "<metadata={:?}, milestone={:?}>", self.metadata, self.milestone)
//     }
// }

// fn handle_client_result<T>(result: iota_client::Result<T>) -> Result<T> {
//     result.map_err(|err| wrapped_err!(ClientOperationFailure, WrappedError(err)))
// }

// /// Reconstruct Streams Message from bundle.
// ///
// /// The input bundle is not checked (for validity of the hash, consistency of indices, etc.).
// /// Checked bundles are returned by `client.get_message().index`.
// fn msg_from_tangle_message(message: &Message, link: &TangleAddress) -> Result<TangleMessage> {
//     if let Some(Payload::Indexation(i)) = message.payload().as_ref() {
//         let mut bytes = Vec::<u8>::new();
//         for b in i.data() {
//             bytes.push(*b);
//         }

//         let binary = BinaryMessage::new(*link, TangleAddress::default(), bytes.into());
//         Ok(binary)
//     } else {
//         err!(BadMessagePayload)
//     }
// }

// async fn get_messages(client: &iota_client::Client, link: &TangleAddress) -> Result<Vec<Message>> {
//     let hash = link.to_msg_index();
//     let msg_ids = handle_client_result(client.get_message().index(hash).await)?;
//     try_or!(!msg_ids.is_empty(), IndexNotFound)?;

//     let msgs = join_all(
//         msg_ids
//             .iter()
//             .map(|msg| async move { handle_client_result(client.get_message().data(msg).await) }),
//     )
//     .await
//     .into_iter()
//     .filter_map(|msg| msg.ok())
//     .collect::<Vec<_>>();
//     try_or!(!msgs.is_empty(), MessageContentsNotFound)?;
//     Ok(msgs)
// }

// /// Send a message to the Tangle using a node client
// async fn async_send_message_with_options(client: &iota_client::Client, msg: &TangleMessage) -> Result<()> {
//     let hash = msg.link.to_msg_index();

//     // TODO: Get rid of copy caused by to_owned
//     client
//         .message()
//         .with_index(hash)
//         .with_data(msg.body.to_bytes())
//         .finish()
//         .await?;
//     Ok(())
// }

// /// Retrieve a message from the tangle using a node client
// async fn async_recv_messages(client: &iota_client::Client, link: &TangleAddress) -> Result<Vec<TangleMessage>> {
//     match get_messages(client, link).await {
//         Ok(txs) => Ok(txs
//             .iter()
//             .filter_map(|b| msg_from_tangle_message(b, link).ok()) // Ignore errors
//             .collect()),
//         Err(_) => Ok(Vec::new()), // Just ignore the error?
//     }
// }

// /// Retrieve details of a link from the tangle using a node client
// async fn async_get_link_details(client: &iota_client::Client, link: &TangleAddress) -> Result<Details> {
//     let hash = link.to_msg_index();
//     let msg_ids = handle_client_result(client.get_message().index(hash).await)?;
//     try_or!(!msg_ids.is_empty(), IndexNotFound)?;

//     let metadata = handle_client_result(client.get_message().metadata(&msg_ids[0]).await)?;

//     let mut milestone = None;
//     if let Some(ms_index) = metadata.referenced_by_milestone_index {
//         milestone = Some(handle_client_result(client.get_milestone(ms_index).await)?);
//     }

//     Ok(Details { metadata, milestone })
// }

#[derive(Debug)]
/// Stub type for iota_client::Client.  Removed: Copy, Default, Clone
struct Client(
    // send_opt: SendOptions,
    iota_client::Client,
);

// impl Default for Client {
//     // Creates a new instance which links to a node on localhost:14265
//     fn default() -> Self {
//         Self {
//             send_opt: SendOptions::default(),
//             client: block_on(
//                 iota_client::ClientBuilder::new()
//                     .with_node("http://localhost:14265")
//                     .unwrap()
//                     .finish(),
//             )
//             .unwrap(),
//         }
//     }
// }

impl Client {
    // Create an instance of Client with a ready client and its send options
    fn new(client: iota_client::Client) -> Self {
        Self(client)
    }

    // Shortcut to create an instance of Client connecting to a node with default parameters
    async fn for_node(node_url: &str) -> Result<Self> {
        Ok(Self(
            iota_client::ClientBuilder::new()
                .with_node(node_url)?
                .with_local_pow(false)
                .finish()
                .await?,
        ))
    }

    fn client(&self) -> &iota_client::Client {
        &self.0
    }

    fn client_mut(&mut self) -> &mut iota_client::Client {
        &mut self.0
    }

    // TODO: REMOVE
    // #[cfg(feature = "did")]
    // async fn to_did_client(&self) -> Result<DIDClient> {
    //     let did_client = DIDClient::builder()
    //         .network(Network::Mainnet)
    //         .primary_node(&self.send_opt.url, None, None)?
    //         .local_pow(self.send_opt.local_pow)
    //         .build()
    //         .await?;
    //     Ok(did_client)
    // }
}

// impl Clone for Client {
//     fn clone(&self) -> Self {
//         Self {
//             send_opt: self.send_opt.clone(),
//             client: block_on(
//                 iota_client::ClientBuilder::new()
//                     .with_node(&self.send_opt.url)
//                     .unwrap()
//                     .with_local_pow(self.send_opt.local_pow)
//                     .finish(),
//             )
//             .unwrap(),
//         }
//     }
// }

// impl TransportOptions for Client {
//     type SendOptions = SendOptions;
//     fn send_options(&self) -> SendOptions {
//         self.send_opt.clone()
//     }
//     fn set_send_options(&mut self, opt: SendOptions) {
//         self.send_opt = opt;

//         // TODO
//         // self.client.set_send_options()
//     }

//     type RecvOptions = ();
//     fn recv_options(&self) {}
//     fn set_recv_options(&mut self, _opt: ()) {}
// }

#[async_trait(?Send)]
impl<Index, Message> Transport<Index, Message> for Client
where
    Index: AsRef<[u8]> + Display,
    Message: Into<Vec<u8>> + From<IotaMessage>,
{
    async fn send_message(&mut self, index: Index, msg: Message) -> Result<()>
    where
        Message: 'async_trait,
        Index: 'async_trait,
    {
        self.client()
            .message()
            .with_index(index)
            .with_data(msg.into())
            .finish()
            .await?;
        Ok(())
    }

    async fn recv_messages(&mut self, index: &Index) -> Result<Vec<Message>> {
        let msg_ids = self.client().get_message().index(index).await?;
        ensure!(!msg_ids.is_empty(), "no message found at index '{}'", index);

        let msgs = try_join_all(
            msg_ids
                .iter()
                .map(|msg| self.client().get_message().data(msg).map_ok(Into::into)),
        )
        .await?;
        Ok(msgs)
    }

    // async fn recv_message(&mut self, address: Address) -> Result<Message> {
    //     let mut msgs = self.recv_messages(link).await?;
    //     if let Some(msg) = msgs.pop() {
    //         try_or!(msgs.is_empty(), MessageNotUnique(link.to_string()))?;
    //         Ok(msg)
    //     } else {
    //         err!(MessageLinkNotFoundInTangle(link.to_string()))
    //     }
    // }
}

// TODO: REMOVE
// #[async_trait(?Send)]
// impl TransportDetails<TangleAddress> for Client {
//     type Details = Details;
//     async fn get_link_details(&mut self, link: &TangleAddress) -> Result<Self::Details> {
//         async_get_link_details(&self.client, link).await
//     }
// }

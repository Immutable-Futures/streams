use crate::{
    address::Address,
    error::{Error, Result},
    message::TransportMessage,
    transport::Transport,
};
use alloc::{boxed::Box, vec::Vec};
use async_trait::async_trait;
use futures::FutureExt;
use serde::__private::PhantomData;
use sqlx::mysql::MySqlPool;
#[cfg(feature = "did")]
use crate::id::{Ed25519Pub, Ed25519Sig, Identifier};

pub struct Client<StreamsMessage = TransportMessage, DbMessage = SqlMessage>(
    MySqlPool,
    PhantomData<(StreamsMessage, DbMessage)>,
);

impl<SM, DM> Client<SM, DM> {
    pub async fn new(url: &str) -> Result<Client> {
        Ok(Client(
            MySqlPool::connect(url)
                .await
                .map_err(|e| Error::MySqlClient("building client", e))?,
            PhantomData,
        ))
    }
}

impl<SM, DM> Client<SM, DM> {
    async fn insert_message(&mut self, msg: SqlMessage) -> Result<()> {
        let sql_msg: SqlMessage = msg.into();
        Ok(sqlx::query!(
            r#"INSERT INTO messages (msg_id, raw_content, timestamp) VALUES (?, ?, ?)"#,
            sql_msg.msg_id,
            sql_msg.raw_content,
            sql_msg.timestamp
        )
        .execute(&self.0)
        .await
        .map_err(|e| Error::MySqlClient("inserting message", e))
        .and_then(|r| {
            if r.rows_affected() == 0 {
                Err(Error::MySqlNotInserted)
            } else {
                Ok(())
            }
        })?)
    }

    async fn retrieve_message(&mut self, address: Address) -> Result<SqlMessage> {
        let mut msg_id_bytes = address.base().as_bytes().to_vec();
        msg_id_bytes.extend_from_slice(address.relative().as_bytes());
        Ok(
            sqlx::query_as!(SqlMessage, r#"SELECT * FROM messages WHERE msg_id = ?"#, msg_id_bytes)
                .fetch_one(&self.0)
                .await
                .map_err(|e| Error::MySqlClient("fetching message", e))?,
        )
    }
}

#[async_trait]
impl<StreamsMessage, DbMessage> Transport<'_> for Client<StreamsMessage, DbMessage>
where
    StreamsMessage: From<SqlMessage> + Into<SqlMessage> + Send + Sync,
    DbMessage: From<SqlMessage> + Clone + Send + Sync,
{
    type Msg = StreamsMessage;
    type SendResponse = DbMessage;

    #[cfg(not(feature = "did"))]
    async fn send_message(&mut self, address: Address, msg: StreamsMessage) -> Result<Self::SendResponse>
    where
        StreamsMessage: 'async_trait,
    {
        let db_msg = msg.into().with_address(address);
        self.insert_message(db_msg.clone()).await?;
        Ok(db_msg.into())
    }

    /// This function stands as a DON alternative for sending that includes the public key and
    /// verifiable signature of the message for inclusion as a Data message within the network
    /// Signatures are conducted using ED25519 keys so the method uses that as a baseline assumption
    /// for sending and retrieval.
    /// TODO: Make this function more ubiquitous for use in other protocols, or with other signature formats
    #[cfg(feature = "did")]
    async fn send_message(&mut self, address: Address, msg: StreamsMessage, public_key: Ed25519Pub, signature: Ed25519Sig) -> Result<Self::SendResponse>
        where
            StreamsMessage: 'async_trait,
    {
        let db_msg = msg.into()
            .with_address(address)
            .with_public_key(public_key)
            .with_signature(signature);
        self.insert_message(db_msg.clone()).await?;
        Ok(db_msg.into())
    }

    async fn recv_messages(&mut self, address: Address) -> Result<Vec<Self::Msg>>
    where
        StreamsMessage: 'async_trait,
    {
        let msg = self.retrieve_message(address).await?;
        #[cfg(feature = "did")]
        {
            println!("Verifying message");
            let mut bytes = [0u8;32];
            bytes.clone_from_slice(&msg.public_key);
            let pk = Ed25519Pub::try_from_bytes(bytes)?;
            pk.verify(&Ed25519Sig::from_bytes(msg.signature), &msg.raw_content)?;
        }
        Ok(vec![msg.into()])
    }
}

#[derive(sqlx::FromRow, Clone, Default)]
pub struct SqlMessage {
    msg_id: Vec<u8>,
    raw_content: Vec<u8>,
    timestamp: chrono::DateTime<chrono::Utc>,
    #[cfg(feature = "did")]
    public_key: [u8;32],
    #[cfg(feature = "did")]
    signature: [u8;64],
}

impl SqlMessage {
    fn new() -> SqlMessage {
        SqlMessage::default()
    }

    fn with_timestamp(mut self, timestamp: chrono::DateTime<chrono::Utc>) -> SqlMessage {
        self.timestamp = timestamp;
        self
    }

    fn with_content(mut self, raw_content: Vec<u8>) -> Self {
        self.raw_content = raw_content;
        self
    }

    fn with_address(mut self, address: Address) -> Self {
        self.msg_id = address.base().as_bytes().to_vec();
        self.msg_id.extend_from_slice(address.relative().as_bytes());
        self
    }

    #[cfg(feature = "did")]
    fn with_public_key(mut self, public_key: Ed25519Pub) -> Self {
        self.public_key = public_key.to_bytes();
        self
    }

    #[cfg(feature = "did")]
    fn with_signature(mut self, signature: Ed25519Sig) -> Self {
        self.signature = signature.into();
        self
    }

}

impl AsRef<[u8]> for SqlMessage {
    fn as_ref(&self) -> &[u8] {
        self.raw_content.as_slice()
    }
}

impl From<TransportMessage> for SqlMessage {
    fn from(msg: TransportMessage) -> SqlMessage {
        Self::new()
            .with_content(msg.into_body())
            .with_timestamp(chrono::Utc::now())
    }
}

impl From<SqlMessage> for TransportMessage {
    fn from(msg: SqlMessage) -> TransportMessage {
        Self::new(msg.raw_content)
    }
}

#[cfg(test)]
mod tests {
    use chrono::Utc;

    use crate::{
        address::{Address, AppAddr, MsgId},
        id::Identifier,
        message::{Topic, TransportMessage},
    };

    use super::*;

    #[tokio::test]
    async fn send_and_recv_message() -> Result<()> {
        // This test requires that there be an existing db running on mysql. Credentials can be updated here
        let mut client = Client::<SqlMessage>::new("mysql://user:password@localhost/db").await?;
        let address = Address::new(
            AppAddr::default(),
            MsgId::gen(
                AppAddr::default(),
                &Identifier::default(),
                &Topic::default(),
                Utc::now().timestamp_millis() as usize,
            ),
        );
        let msg = TransportMessage::new(vec![12; 1024]);
        client.send_message(address, msg.clone().into()).await?;

        let response = client.recv_message(address).await?;
        assert_eq!(msg, response);
        Ok(())
    }
}

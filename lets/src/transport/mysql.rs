use crate::{
    error::{Result, Error},
    message::TransportMessage,
    transport::Transport,
};
use sqlx::{mysql::MySqlPool, Row};
use serde::__private::PhantomData;
use alloc::vec::Vec;
use crate::address::Address;
use core::convert::TryFrom;
use async_trait::async_trait;
use alloc::boxed::Box;

pub struct Client<Message = TransportMessage, SendResponse = TransportMessage>(MySqlPool, PhantomData<(Message, SendResponse)>);



impl<Message, SendResponse> Client<Message, SendResponse> {
    pub async fn new(url: &str) -> Result<Client> {
        Ok(Client(MySqlPool::connect(url).await.map_err(|e| Error::MySqlClient("building client", e))?, PhantomData))
    }
}


#[async_trait]
impl<M, SR> Transport<'_> for Client<M, SR>
where
    M: AsRef<[u8]> + TryFrom<TransportMessage, Error = crate::error::Error> + Send + Sync,
    SR: AsRef<[u8]> + TryFrom<TransportMessage> + Send + Sync
{
    type Msg = M;
    type SendResponse = SR;

    async fn send_message(&mut self, address: Address, msg: M) -> Result<Self::SendResponse>
        where M: 'async_trait
    {
        unimplemented!()
    }

    async fn recv_messages(&mut self, address: Address) -> Result<Vec<Self::Msg>>
        where M: 'async_trait
    {
        unimplemented!()
    }
}




#[derive(sqlx::FromRow)]
pub struct SqlMessage {
    msg_id: Vec<u8>,
    raw_content: Vec<u8>,
    timestamp: chrono::DateTime<chrono::Utc>
}

impl SqlMessage {
    fn new(msg_id: Vec<u8>, raw_content: Vec<u8>, timestamp: chrono::DateTime<chrono::Utc>) -> SqlMessage {
        SqlMessage { msg_id, raw_content, timestamp }
    }
}

async fn insert_message<M, SR>(address: Address, msg: &[u8], client: &mut Client<M, SR>) -> Result<bool> {
    let mut msg_id_bytes = address.base().as_bytes().to_vec();
    msg_id_bytes.extend_from_slice(address.relative().as_bytes());
    let now = chrono::prelude::Utc::now();
    Ok(sqlx::query!(r#"INSERT INTO messages (msg_id, raw_content, timestamp) VALUES (?, ?, ?)"#, msg_id_bytes, msg, now)
        .execute(&client.0).await
        .and_then(|r| Ok(r.rows_affected() > 0))?)
}

async fn retrieve_message<M, SR>(address: Address, client: &mut Client<M, SR>) -> Result<SqlMessage> {
    let mut msg_id_bytes = address.base().as_bytes().to_vec();
    msg_id_bytes.extend_from_slice(address.relative().as_bytes());
    let now = chrono::prelude::Utc::now();
    Ok(sqlx::query_as!(SqlMessage, r#"SELECT * FROM messages WHERE msg_id = ?"#, msg_id_bytes)
        .fetch_one(&client.0).await?)
}

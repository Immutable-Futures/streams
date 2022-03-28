use core::{
    borrow::BorrowMut,
    fmt,
};

use crypto::keys::x25519;

use iota_streams_app::{
    id::Identifier,
    permission::Permission,
    message::Cursor,
};
use iota_streams_core::{
    err,
    prelude::{
        HashMap,
        Vec,
    },
    psk::{
        Psk,
        PskId,
    },
    Errors::BadIdentifier,
    Result,
};

#[derive(Debug)]
pub struct KeyStore<Link> {
    /// Map from user identity -- ed25519 pk -- to
    /// a precalculated corresponding x25519 pk and some additional Cursor.
    cursors: HashMap<Identifier, Cursor<Link>>,
    keys: HashMap<Identifier, x25519::PublicKey>,
    psks: HashMap<PskId, Psk>,
}

impl<Link> KeyStore<Link> {
    pub fn new() -> Self {
        Self {
            cursors: HashMap::new(),
            keys: HashMap::new(),
            psks: HashMap::new(),
        }
    }
}

impl<Link> KeyStore<Link> {
    pub fn filter<'a, I>(&self, ids: I) -> Vec<(Permission, Vec<u8>)>
    where
        I: IntoIterator<Item = &'a Permission>,
    {
        ids.into_iter()
            .filter_map(|p| match p.identifier() {
                Identifier::PskId(pskid) => self
                    .psks
                    .get_key_value(pskid)
                    .map(|(_, psk)| (p.clone(), psk.to_vec())),
                _ => self
                    .keys
                    .get_key_value(p.identifier())
                    .map(|(_, pk)| (p.clone(), pk.as_slice().to_vec())),
            })
            .collect()
    }

    pub fn contains_subscriber(&self, id: &Identifier) -> bool {
        self.cursors.contains_key(id)
    }

    pub fn get_cursor(&self, id: &Identifier) -> Option<&Cursor<Link>> {
        self.cursors.get(id)
    }

    pub fn get_cursor_mut(&mut self, id: &Identifier) -> Option<&mut Cursor<Link>> {
        self.cursors.get_mut(id)
    }

    pub fn insert_cursor(&mut self, id: Identifier, cursor: Cursor<Link>) {
        self.cursors.insert(id, cursor);
    }

    pub fn replace_cursors(&mut self, new_cursor: Cursor<Link>)
    where
        Link: Clone,
    {
        for (_id, cursor) in self.cursors.iter_mut() {
            *cursor = new_cursor.clone()
        }
    }

    pub fn contains_psk(&self, pskid: &PskId) -> bool {
        self.psks.contains_key(pskid)
    }

    pub fn get_psk(&self, pskid: &PskId) -> Option<&Psk> {
        self.psks.get(pskid)
    }

    pub fn insert_psk(&mut self, id: Identifier, psk: Psk) -> Result<()> {
        match &id {
            Identifier::PskId(pskid) => {
                self.psks.insert(*pskid, psk);
                Ok(())
            }
            _ => err(BadIdentifier),
        }
    }

    pub fn insert_keys(&mut self, id: Identifier, xkey: x25519::PublicKey) -> Result<()> {
        if !self.keys.contains_key(&id) {
            self.keys.insert(id, xkey);
        }
        Ok(())
    }

    pub fn exchange_keys(&self) -> Vec<(Identifier, Vec<u8>)> {
        self.keys
            .iter()
            .map(|(id, pk)| (*id, pk.as_slice().to_vec()))
            .chain(self.psks.iter().map(|(pskid, psk)| ((*pskid).into(), psk.to_vec())))
            .collect()
    }

    pub fn cursors(&self) -> impl Iterator<Item = (&Identifier, &Cursor<Link>)> {
        self.cursors.iter()
    }

    pub fn cursors_mut(&mut self) -> impl Iterator<Item = (&Identifier, &mut Cursor<Link>)> {
        self.cursors.iter_mut()
    }

    pub fn cursors_size(&self) -> usize {
        self.cursors.len()
    }

    pub fn remove(&mut self, id: &Identifier) {
        self.cursors.borrow_mut().remove(id);
        self.keys.borrow_mut().remove(id);
        if let Identifier::PskId(pskid) = id {
            self.psks.borrow_mut().remove(pskid);
        }
    }
}

impl<Link> Default for KeyStore<Link> {
    fn default() -> Self {
        Self::new()
    }
}

impl<Link: fmt::Display> fmt::Display for KeyStore<Link> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (id, cursor) in self.cursors.iter() {
            writeln!(f, "    <{}> => {}", hex::encode(&id.to_bytes()), cursor)?;
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq)]
pub enum Key {
    PK(x25519::PublicKey),
    Psk(Psk)
}

impl From<x25519::PublicKey> for Key {
    fn from(item: x25519::PublicKey) -> Self {
        Self::PK(item)
    }
}

impl From<Psk> for Key {
    fn from(item: Psk) -> Self {
        Self::Psk(item)
    }
}


#[derive(Debug)]
pub struct KeyStore2 {
    keys: HashMap<Identifier, Key>,
}

impl KeyStore2 {
    pub fn add_key(&mut self, identifier: Identifier, key: impl Into::<Key>) -> Result<()>{
        let key_into = key.into();
        match (identifier, &key_into) {
            (Identifier::EdPubKey(_), &Key::PK(_)) | (Identifier::PskId(_), &Key::Psk(_)) => {
                self.keys.insert(identifier,  key_into);
                Ok(())
            },
            #[cfg(feature = "did")]
            (Identifier::DID(_), &Key::PK(_)) => {
                self.keys.insert(identifier,  key_into);
                Ok(())
            },
            _ => err(BadIdentifier)
        }
    }
}
use anyhow::Result;
//use std::string::ToString;

use super::*;
use iota_streams_protobuf3::command::unwrap;

/// Message context preparsed for unwrapping.
pub struct PreparsedMessage<'a, F, Link> {
    pub header: Header<Link>,
    pub(crate) ctx: unwrap::Context<F, &'a [u8]>,
}

impl<'a, F, Link> PreparsedMessage<'a, F, Link>
{
    pub fn check_content_type(&self, _content_type: &str) -> bool {
        panic!("not implemented");
        //(self.header.content_type.0).eq_str(content_type)
    }

    pub fn content_type(&self) -> String {
        panic!("not implemented");
        //(self.header.content_type.0).to_string()
    }

    pub fn unwrap<Store, Content>(
        mut self,
        store: &Store,
        mut content: Content,
    ) -> Result<UnwrappedMessage<F, Link, Content>>
    where
        Content: ContentUnwrap<F, Store>,
    {
        content.unwrap(&store, &mut self.ctx)?;
        // Discard what's left of `self.ctx.stream`
        Ok(UnwrappedMessage {
            link: self.header.link,
            content: content,
            spongos: self.ctx.spongos,
        })
    }
}

impl<'a, F, Link> Clone for PreparsedMessage<'a, F, Link>
where
    F: Clone,
    Link: Clone,
{
    fn clone(&self) -> Self {
        Self {
            header: self.header.clone(),
            ctx: self.ctx.clone(),
        }
    }
}

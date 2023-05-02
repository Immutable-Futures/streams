# Streams LETS layer: Message building and Identity logic.

## LETS 
The `lets` crate houses message-oriented cryptographic protocols. Identification, transportation and generic message 
handling protocols in these modules can be used to build streaming applications. Signature and encryption operations 
are handled via the `id` module, while `message` encoding operations are managed via the `message` module. Messages are 
indexed by an `Address` composed of an `Application Address` and `Message Identifier`, and the library provides a 
`Transport` trait to allow for agnostic transport client creation.

## Customization
The foundational Streams message types `HDF` and `PCF` are described in the `message` module of this crate, while the 
cryptographic and identification logic is within the `id` module. If new logic is desired, for example a new variable to
process within the header frame, it is important to note that the [Content](src/message/content.rs) traits must be 
implemented. For custom `Identity` extensions, ensure that there is an appropriate `IdentityKind` and `Identifier` type defined with 
content traits implemented.

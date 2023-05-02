# Spongos
The Spongos crate houses core functionality for `DDML` and sponge based cryptographic
operations. The core module houses trait bounds for `Pseudo-Random Permutation` instances (the
default implementation used in this library is `Keccak-f[1600]`), as well as the custom
`Spongos` wrapper, which makes up the foundation of state management and `DDML` command
operations. The ddml module houses `Spongos` based commands for
encoding/decoding/encryption/signature functionality.

## Customization
It is possible to create new `DDML` commands to extend the spongos functionality if it is desired. New core types can 
also be added to the `DDML` types module, but make sure to implement the appropriate `wrap`/`unwrap`/`sizeof` command 
implementations for these new types. 
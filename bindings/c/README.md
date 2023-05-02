# IOTA Streams Application layer: C bindings

## Instructions

Check out `CMakeLists.txt` and change the 3 options to your preference:

- `IOTA_CLIENT`: Enable transport via streams utangle implementation, otherwise the client will default to a testing Bucket client instance
- `STATIC`: Build static library when ON, otherwise dynamic library
- `RELEASE`: Build in release or debug mode (when ON, builds release, when OFF, build debug)

Optional: Edit your seed in `main.c`, commenting out the line `rand_seed(seed, sizeof(seed));` to use a predefined seed.

run `cmake .` in this folder (for Windows, use `cmake . -G "Unix Makefiles"` to build a unix based MakeFile for building)

Then run `make` to build the rust code.

A binary will be generated which you can run depending on your STATIC setting
- ON:  `iota_streams_c_static`
- OFF: `libiota_streams_c.so`(Unix), `iota_streams_c.dll`(Windows) and the executable `iota_streams_c`

You can then run the static build or the dynamic executable. 

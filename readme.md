# Rust TAPS Implementation

Rust implementation of the IETF's Transport Services (TAPS) API (https://datatracker.ietf.org/doc/draft-ietf-taps-arch/). 

This implementation makes use of Tokio for asynchrony and supports the TCP, TLS TCP and QUIC transport protocols.

## Build instructions

To incorporate the API into an existing project, add it as a dependency in cargo.toml:

	taps = {git = "https://github.com/PaulTraynor/Rust-TAPS-Implementation", package = "rust-taps-api"}

For the code to work, Tokio must also be added as a dependency in cargo.toml as follows: 

	tokio = "1.17.0"

### Requirements

The Rust compiler must be installed to use the API. Version 1.55 was used for this project but any version since the release of Rust 2018 will work.

### Build steps

To build the API in your project, run: 

	cargo build

### Test steps

Run the unit tests, run: 

	cargo test
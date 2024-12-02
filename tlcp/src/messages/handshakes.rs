mod certificate;
mod certificate_verify;
mod client_hello;
mod client_key_exchange;
mod finished;
mod server_hello;
mod server_hello_done;
mod server_key_exchange;

pub use certificate::*;
pub use client_hello::*;
pub use client_key_exchange::*;
pub use finished::*;
pub use server_hello::*;
pub use server_hello_done::*;
pub use server_key_exchange::*;

use opengm_crypto::cryptobyte::Parser;


// There are two type of handshake messages: XyzMsgOwned and XyzMsgBorrow.
// One is owned the raw data, and the other is by reference.
// The latter one is for parsing a received message and void
// copying the memory.

fn parse_handshake_msg_header(
    record_payload: &[u8],
) -> Option<(u8, &[u8])> {
    let mut parser = Parser::new(record_payload);
    let msg_type = parser.read_u8()?;
    let body = parser.read_u24_length_prefixed()?;
    Some((msg_type, body))
}

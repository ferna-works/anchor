mod document;
mod error;
mod id;
mod resolve;

pub use document::{build_document, control_key_id, device_key_id};
pub use error::DidError;
pub use id::{parse_did, to_did};
pub use resolve::{Resolution, resolve, to_json_pretty};
pub use ssi::dids::{DIDBuf, document::Document};

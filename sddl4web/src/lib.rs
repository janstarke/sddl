mod utils;
mod error;

use wasm_bindgen::prelude::*;
use sddl::{SecurityDescriptor, Sid};

#[wasm_bindgen]
pub fn convert(sddl: &str, domain_sid: &str) -> Result<String, error::Error> {

    let sid = Sid::try_from(domain_sid)?;
    let sub_authorities = sid.sub_authority();
    let domain_rid = if sub_authorities.len() > 2 {
        Some(&sub_authorities[1..sub_authorities.len()-1])
    } else {
        None
    };
    let sd = SecurityDescriptor::from_sddl(sddl, domain_rid)?;
    Ok(serde_json::to_string_pretty(&sd)?)
}
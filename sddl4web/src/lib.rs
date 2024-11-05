mod utils;
mod error;

use wasm_bindgen::prelude::*;
use sddl::{SecurityDescriptor, Sid};
/*
#[wasm_bindgen(getter_with_clone)]
pub struct WebSecurityDescriptor {
    pub security_descriptor: SecurityDescriptor
}

 */
#[wasm_bindgen]
pub fn convert(sddl: &str, domain_sid: &str) -> Result<String, error::Error> {

    let sid = Sid::try_from(domain_sid)?;
    let sub_authorities = sid.sub_authority();
    let domain_rid = &sub_authorities[0..sub_authorities.len()];
    let sd = SecurityDescriptor::from_sddl(sddl, Some(domain_rid))?;
    Ok(serde_json::to_string_pretty(&sd)?)
}
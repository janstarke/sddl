mod utils;

use wasm_bindgen::prelude::*;
use sddl::SecurityDescriptor;

#[wasm_bindgen]
pub fn convert(sddl: &str) -> String {

    match SecurityDescriptor::from_sddl(sddl, None) {
        Err(why) => format!("ERROR: {why}"),
        Ok(sd) => serde_json::to_string_pretty(&sd).unwrap()
    }
}

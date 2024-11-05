use thiserror::Error;
use wasm_bindgen::JsValue;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    SddlError(#[from] sddl::Error),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error)
}

impl From<Error> for JsValue {
    fn from(val: Error) -> Self {
        JsValue::from_str(&val.to_string())
    }
}
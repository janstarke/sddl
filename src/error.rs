use lalrpop_util::ParseError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("ParseError: {0}")]
    ParseError(String),

    #[error("IllegalSid: '{0}' (reason: {1})")]
    IllegalSidFormat(String, &'static str),

    #[error("this SID alias cannot be parsed without a domain RID")]
    MissingDomainInformation,

    #[error("Error while parsing the binary security descriptor: {0}")]
    BinReadError(#[from] binrw::Error)
}

impl<L, T, E> From<ParseError<L, T, E>> for Error 
where
    L: core::fmt::Display,
    T: core::fmt::Display,
    E: core::fmt::Display {
    fn from(value: ParseError<L, T, E>) -> Self {
        Self::ParseError(format!("{value}"))
    }
}
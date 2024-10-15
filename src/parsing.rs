use lalrpop_util::{lexer::Token, ParseError};

use crate::{Error, Sid};

pub(crate) trait NewDomainSid<L, T> {
    fn new_domain_sid(&self, rid: u32) -> Result<Sid, ParseError<usize, T, Error>>;
}

impl<'input> NewDomainSid<usize, Token<'input>> for Option<&[u32]> {
    fn new_domain_sid(&self, rid: u32) -> Result<Sid, ParseError<usize, Token<'input>, Error>> {
        self.map(|domain| crate::Sid::new_with_domain(rid, domain))
            .ok_or(ParseError::User {
                error: crate::Error::MissingDomainInformation,
            })
    }
}

use sddl::{parser, AccessMask};

#[test]
fn calculator1() {
    let x = parser::TermParser::new().parse("22");
    assert!(parser::TermParser::new().parse("22").is_ok());
    assert!(parser::TermParser::new().parse("(22)").is_ok());
    assert!(parser::TermParser::new().parse("((((22))))").is_ok());
    assert!(parser::TermParser::new().parse("((22)").is_err());
}

#[test]
fn test_access_mask() {
    assert_eq!(AccessMask::try_from("0x80000000").unwrap(), AccessMask::GENERIC_READ);
    assert_ne!(AccessMask::try_from("0x80000001").unwrap(), AccessMask::GENERIC_READ);
}
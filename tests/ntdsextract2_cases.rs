use base64::prelude::*;
use sddl::SecurityDescriptor;

#[test]
fn testcase1() {
    let _sd = SecurityDescriptor::from_bytes(&BASE64_STANDARD.decode("AQAEgDAAAAA8AAAAAAAAABQAAAACABwAAQAAAAADFAD/////AQEAAAAAAAEAAAAAAQEAAAAAAAEAAAAAAQEAAAAAAAEAAAAA").unwrap()).unwrap();
}

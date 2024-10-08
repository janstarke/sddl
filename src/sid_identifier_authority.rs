use std::fmt::Display;

use binrw::binrw;
use getset::Getters;

/// <https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-sid_identifier_authority>
#[binrw]
#[derive(Eq, PartialEq, Getters)]
#[getset(get = "pub")]
pub struct SidIdentifierAuthority {
    value: [u8; 6],
}

impl Display for SidIdentifierAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes = [
            0u8,
            0u8,
            self.value()[0],
            self.value()[1],
            self.value()[2],
            self.value()[3],
            self.value()[4],
            self.value()[5],
        ];
        u64::from_be_bytes(bytes).fmt(f)
    }
}

macro_rules! predefined_authority {
    ($name: ident, $value: expr) => {
        #[allow(unused)]
        pub const $name: SidIdentifierAuthority = SidIdentifierAuthority {
            value: [0, 0, 0, 0, 0, $value],
        };
    };
}

predefined_authority!(SECURITY_NULL_SID_AUTHORITY, 0);
predefined_authority!(SECURITY_WORLD_SID_AUTHORITY, 1);
predefined_authority!(SECURITY_LOCAL_SID_AUTHORITY, 2);
predefined_authority!(SECURITY_CREATOR_SID_AUTHORITY, 3);
predefined_authority!(SECURITY_NON_UNIQUE_AUTHORITY, 4);
predefined_authority!(SECURITY_NT_AUTHORITY, 5);
predefined_authority!(SECURITY_MANDATORY_LABEL_AUTHORITY, 6);
predefined_authority!(SECURITY_RESOURCE_MANAGER_AUTHORITY, 9);

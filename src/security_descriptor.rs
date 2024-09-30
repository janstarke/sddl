use binrw::binrw;

use crate::ControlFlags;

/// <https://github.com/microsoft/referencesource/blob/master/mscorlib/system/security/accesscontrol/securitydescriptor.cs>
#[binrw]
pub struct SecurityDescriptor {
    flags: ControlFlags,

    #[br(ignore)]
    _reserved1: u8,

    revision: u8,

    owner: u32,
    group: u32,
    sacl: u32,
    dacl: u32
}

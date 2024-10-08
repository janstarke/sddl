use binrw::binrw;
use getset::Getters;

use crate::ControlFlags;

/// <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/2918391b-75b9-4eeb-83f0-7fdc04a5c6c9>
#[binrw]
#[derive(Eq, PartialEq, Getters)]
#[getset(get = "pub")]
pub struct SecurityDescriptor {
    #[br(assert(revision == 1))]
    #[bw(assert(*revision == 1))]
    revision: u8,
    
    #[br(ignore)]
    #[getset(skip)]
    _reserved1: u8,

    flags: ControlFlags,

    #[brw(big)]
    owner_offset: u32,

    #[brw(big)]
    group_offset: u32,

    #[brw(big)]
    sacl_offset: u32,

    #[brw(big)]
    dacl_offset: u32,
}

use binrw::binrw;

use crate::ControlFlags;

#[binrw]
pub struct SecurityDescriptor {
    flags: ControlFlags,

    #[br(ignore)]
    _reserved1: u8,
}

use binrw::{binread, BinRead, FilePtr};
use getset::Getters;

use crate::{Acl, ControlFlags, Sid};

/// <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/2918391b-75b9-4eeb-83f0-7fdc04a5c6c9>
#[binread]
#[derive(Eq, PartialEq, Getters)]
#[getset(get = "pub")]
pub struct SecurityDescriptor {
    sd_offset: Offset,

    #[br(assert(revision == 1))]
    #[bw(assert(*revision == 1))]
    revision: u8,
    
    #[getset(skip)]
    _reserved1: u8,

    flags: ControlFlags,

    #[brw(little, offset=sd_offset.0)]
    owner_ref: FilePtr<u32, Sid>,

    #[brw(little, offset=sd_offset.0)]
    group_ref: FilePtr<u32, Sid>,

    #[brw(little, offset=sd_offset.0)]
    sacl_ref: FilePtr<u32, Acl>,

    #[brw(little, offset=sd_offset.0)]
    dacl_ref: FilePtr<u32, Acl>,
}

#[derive(Eq, PartialEq, Copy, Clone)]
struct Offset(u64);
impl BinRead for Offset {
    type Args<'a> = ();

    fn read_options<R: std::io::Read + std::io::Seek>(
        reader: &mut R,
        _endian: binrw::Endian,
        _args: Self::Args<'_>,
    ) -> binrw::BinResult<Self> {
        let offset = reader.stream_position()?;
        Ok(Self(offset))
    }
}
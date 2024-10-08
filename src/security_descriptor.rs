use std::fmt::Display;

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

impl SecurityDescriptor {
    pub fn owner(&self) -> &Sid {
        &self.owner_ref.value
    }

    pub fn group(&self) -> &Sid {
        &self.group_ref.value
    }

    pub fn sacl(&self) -> &Acl {
        &self.sacl_ref.value
    }

    pub fn dacl(&self) -> &Acl {
        &self.dacl_ref.value
    }

    pub fn sacl_as_string(&self) -> Option<String> {
        if self.flags().contains(ControlFlags::SystemAclPresent) {
            let mut flags = String::with_capacity(32);
            if self.flags().contains(ControlFlags::SystemAclProtected) {
                flags.push('P');
            }
            if self.flags().contains(ControlFlags::SystemAclAutoInheritRequired) {
                flags.push_str("AR");
            }
            if self.flags().contains(ControlFlags::SystemAclAutoInherited) {
                flags.push_str("AI");
            }
            let aces = self.sacl();
            Some(format!("S:{flags}{aces}"))
        } else {
            None
        }
    }

    pub fn dacl_as_string(&self) -> Option<String> {
        if self.flags().contains(ControlFlags::DiscretionaryAclPresent) {
            let mut flags = String::with_capacity(32);
            if self.flags().contains(ControlFlags::DiscretionaryAclProtected) {
                flags.push('P');
            }
            if self.flags().contains(ControlFlags::DiscretionaryAclAutoInheritRequired) {
                flags.push_str("AR");
            }
            if self.flags().contains(ControlFlags::DiscretionaryAclAutoInherited) {
                flags.push_str("AI");
            }
            let aces = self.sacl();
            Some(format!("D:{flags}{aces}"))
        } else {
            None
        }
    }
}

impl Display for SecurityDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}
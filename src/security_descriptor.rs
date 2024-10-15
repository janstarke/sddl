use std::fmt::Display;

use binrw::{binread, FilePtr};
use getset::Getters;

use crate::{sddl_h::*, Acl, AclType, ControlFlags, Offset, Sid};

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
    #[br(temp)]
    _reserved1: u8,

    flags: ControlFlags,

    #[br(little,
        offset=sd_offset.0,
        if(! flags.contains(ControlFlags::OwnerDefaulted)))
        ]
    owner_ref: Option<FilePtr<u32, Sid>>,

    #[br(little,
        offset=sd_offset.0,
        if(! flags.contains(ControlFlags::GroupDefaulted)))
        ]
    group_ref: Option<FilePtr<u32, Sid>>,

    #[br(little,
        offset=sd_offset.0,
        map(|d: FilePtr<u32, Acl>| if flags.contains(ControlFlags::SystemAclPresent) {Some(d)} else { None }),
        args{inner: (flags, AclType::SACL)})
        ]
    sacl_ref: Option<FilePtr<u32, Acl>>,

    #[br(little,
        offset=sd_offset.0,
        map(|d: FilePtr<u32, Acl>| if flags.contains(ControlFlags::DiscretionaryAclPresent) {Some(d)} else { None }),
        args{inner: (flags, AclType::DACL)})
        ]
    dacl_ref: Option<FilePtr<u32, Acl>>,
}

impl SecurityDescriptor {
    pub fn owner(&self) -> Option<&Sid> {
        self.owner_ref.as_ref().map(|d| &d.value)
    }

    pub fn group(&self) -> Option<&Sid> {
        self.group_ref.as_ref().map(|d| &d.value)
    }

    pub fn sacl(&self) -> Option<&Acl> {
        self.sacl_ref.as_ref().map(|d| &d.value)
    }

    pub fn dacl(&self) -> Option<&Acl> {
        self.dacl_ref.as_ref().map(|d| &d.value)
    }

    pub fn sacl_as_sddl_string(&self) -> Option<String> {
        self.sacl().map(|sacl| {
            let mut flags = String::with_capacity(5);
            if self.flags().contains(ControlFlags::SystemAclProtected) {
                flags.push_str(SDDL_PROTECTED);
            }
            if self
                .flags()
                .contains(ControlFlags::SystemAclAutoInheritRequired)
            {
                flags.push_str(SDDL_AUTO_INHERIT_REQ);
            }
            if self.flags().contains(ControlFlags::SystemAclAutoInherited) {
                flags.push_str(SDDL_AUTO_INHERITED);
            }
            format!("{SDDL_SACL}{SDDL_DELIMINATOR}{flags}{sacl}")
        })
    }

    pub fn dacl_as_sddl_string(&self) -> Option<String> {
        self.dacl().map(|dacl| {
            let mut flags = String::with_capacity(5);
            if self
                .flags()
                .contains(ControlFlags::DiscretionaryAclProtected)
            {
                flags.push_str(SDDL_PROTECTED);
            }
            if self
                .flags()
                .contains(ControlFlags::DiscretionaryAclAutoInheritRequired)
            {
                flags.push_str(SDDL_AUTO_INHERIT_REQ);
            }
            if self
                .flags()
                .contains(ControlFlags::DiscretionaryAclAutoInherited)
            {
                flags.push_str(SDDL_AUTO_INHERITED);
            }
            format!("{SDDL_DACL}{SDDL_DELIMINATOR}{flags}{dacl}")
        })
    }
}

impl Display for SecurityDescriptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(owner) = self.owner() {
            write!(f, "{SDDL_OWNER}{SDDL_DELIMINATOR}{owner}")?;
        }
        if let Some(group) = self.group() {
            write!(f, "{SDDL_GROUP}{SDDL_DELIMINATOR}{group}")?;
        }
        if let Some(sacl) = self.sacl_as_sddl_string() {
            write!(f, "{sacl}")?;
        }
        if let Some(dacl) = self.dacl_as_sddl_string() {
            write!(f, "{dacl}")?;
        }
        Ok(())
    }
}

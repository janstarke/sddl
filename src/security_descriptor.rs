use std::{fmt::Display, io::Cursor};

use binrw::{binread, FilePtr, BinReaderExt};
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

    #[br(dbg)]
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
    /// parses a binary security descriptor
    /// 
    /// ```rust
    /// use sddl::{ControlFlags, SecurityDescriptor, Acl};
    /// 
    /// let binary_data = [0x01, 0x00, 0x14, 0xb0, 0x90, 0x00, 0x00,
    ///     0x00, 0xa0, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00,
    ///     0x00, 0x02, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x80, 0x14,
    ///     0x00, 0x00, 0x00, 0x00, 0x80, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    ///     0x01, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x60, 0x00, 0x04, 0x00, 0x00,
    ///     0x00, 0x00, 0x03, 0x18, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x01, 0x02, 0x00,
    ///     0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x21, 0x02, 0x00,
    ///     0x00, 0x00, 0x03, 0x18, 0x00, 0x00, 0x00, 0x00, 0x10, 0x01, 0x02, 0x00,
    ///     0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00,
    ///     0x00, 0x00, 0x03, 0x14, 0x00, 0x00, 0x00, 0x00, 0x10, 0x01, 0x01, 0x00,
    ///     0x00, 0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00, 0x00, 0x03, 0x14,
    ///     0x00, 0x00, 0x00, 0x00, 0x10, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
    ///     0x03, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    ///     0x05, 0x20, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00, 0x00, 0x01, 0x02, 0x00,
    ///     0x00, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00, 0x00, 0x20, 0x02, 0x00,
    ///     0x00];
    /// let security_descriptor = SecurityDescriptor::from_bytes(&binary_data).unwrap();
    /// 
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::Error> {
        let mut cursor = Cursor::new(bytes);
        Ok(cursor.read_le()?)
    }

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

impl TryFrom<&[u8]> for SecurityDescriptor {
    type Error = crate::Error;

    fn try_from(value: &[u8]) -> Result<SecurityDescriptor, Self::Error> {
        Self::from_bytes(value)
    }
}

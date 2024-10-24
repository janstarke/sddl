use std::{fmt::Display, io::Cursor};

use binrw::{binread, FilePtr, BinReaderExt};
use getset::Getters;
use serde::Serialize;

use crate::{sddl_h::*, Acl, AclType, ControlFlags, Offset, Sid};

/// <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/2918391b-75b9-4eeb-83f0-7fdc04a5c6c9>
#[binread]
#[derive(Eq, PartialEq, Getters, Serialize)]
#[getset(get = "pub")]
pub struct SecurityDescriptor {
    #[serde(skip)]
    sd_offset: Offset,

    #[br(assert(revision == 1))]
    #[bw(assert(*revision == 1))]
    revision: u8,

    #[getset(skip)]
    #[br(temp)]
    #[serde(skip)]
    _reserved1: u8,

    flags: ControlFlags,

    #[serde(skip)]
    #[br(little,temp,
        offset=sd_offset.0,
        if(! flags.contains(ControlFlags::OwnerDefaulted)))
        ]
    owner_ref: Option<FilePtr<u32, Sid>>,

    #[serde(skip)]
    #[br(little,temp,
        offset=sd_offset.0,
        if(! flags.contains(ControlFlags::GroupDefaulted)))
        ]
    group_ref: Option<FilePtr<u32, Sid>>,

    #[serde(skip)]
    #[br(little,temp,
        offset=sd_offset.0,
        if(flags.contains(ControlFlags::SystemAclPresent)),
        args{inner: (flags, AclType::SACL)})
        ]
    sacl_ref: Option<FilePtr<u32, Acl>>,

    #[serde(skip)]
    #[br(temp, if(! flags.contains(ControlFlags::SystemAclPresent), 0))]
    _sacl_ref: u32,

    #[serde(skip)]
    #[br(little,temp,
        offset=sd_offset.0,
        if(flags.contains(ControlFlags::DiscretionaryAclPresent)),
        args{inner: (flags, AclType::DACL)})
        ]
    dacl_ref: Option<FilePtr<u32, Acl>>,

    #[serde(skip)]
    #[br(temp, if(! flags.contains(ControlFlags::DiscretionaryAclPresent), 0))]
    _dacl_ref: u32,

    #[br(calc=owner_ref.as_ref().map(|d| d.value.clone()))]
    owner: Option<Sid>,

    #[br(calc=group_ref.as_ref().map(|d| d.value.clone()))]
    group: Option<Sid>,

    #[br(calc=dacl_ref.as_ref().map(|d| d.value.clone()))]
    dacl: Option<Acl>,

    #[br(calc=sacl_ref.as_ref().map(|d| d.value.clone()))]
    sacl: Option<Acl>,
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

    pub fn new(owner: Option<Sid>, group: Option<Sid>, dacl: Option<Acl>, sacl: Option<Acl>) -> Self {
        let mut flags = ControlFlags::empty();
        if owner.is_some() {
            flags |= ControlFlags::OwnerDefaulted
        }
        if group.is_some() {
            flags |= ControlFlags::GroupDefaulted
        }
        if let Some(dacl) = &dacl {
            flags |= *dacl.control_flags() | ControlFlags::DiscretionaryAclPresent;
        }
        if let Some(sacl) = &sacl {
            flags |= *sacl.control_flags() | ControlFlags::SystemAclPresent;
        }
        Self {
            sd_offset: Offset(0),
            revision: 1,
            flags,
            owner,
            group,
            sacl,
            dacl,
        }
    }

    pub fn sacl_as_sddl_string(&self) -> Option<String> {
        self.sacl().as_ref().map(|sacl| {
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
        self.dacl().as_ref().map(|dacl| {
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

    pub fn from_sddl(value: &str, domain_rid: Option<&[u32]>) -> Result<Self, crate::Error> {
        Ok(crate::parser::SecurityDescriptorParser::new().parse(domain_rid, value)?)
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


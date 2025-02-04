use binrw::{binrw, BinRead, BinReaderExt, BinWrite, BinWriterExt};
use bitflags::bitflags;
use getset::Getters;
use serde::Serialize;
use strum::Display;

use crate::{sddl_h::*, AccessMask};

pub const ACE_HEADER_SIZE: u16 = 8;

#[binrw]
#[derive(Eq, PartialEq, Getters, Clone, Copy, Debug, Serialize)]
#[getset(get = "pub")]
pub struct AceHeader {
    /// An unsigned 8-bit integer that specifies a set of ACE type-specific
    /// control flags.
    ace_flags: AceHeaderFlags,

    /// An unsigned 16-bit integer that specifies the size, in bytes, of the
    /// ACE. The AceSize field can be greater than the sum of the individual
    /// fields, but MUST be a multiple of 4 to ensure alignment on a DWORD
    /// boundary. In cases where the AceSize field encompasses additional data
    /// for the callback ACEs types, that data is implementation-specific.
    /// Otherwise, this additional data is not interpreted and MUST be ignored.
    #[brw(assert(ace_size%4 == 0))]
    #[serde(skip)]
    ace_size: u16,

    mask: AccessMask,

    #[br(calc=std::cmp::min(0, 4-(ace_size%4)))]
    #[bw(ignore)]
    #[serde(skip)]
    expected_padding: u16,
}

impl AceHeader {
    pub fn new(ace_flags: AceHeaderFlags, ace_size_without_header: u16, mask: AccessMask) -> Self {
        // make sure the size is a multiple of 4

        let expected_padding = std::cmp::min(0, 4 - (ace_size_without_header % 4));
        
        let ace_size = ACE_HEADER_SIZE + ace_size_without_header + expected_padding;
        Self {
            ace_flags,
            ace_size,
            mask,
            expected_padding
        }
    }
}

/// <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586>
#[repr(u8)]
#[binrw]
#[brw(repr=u8)]
#[allow(non_camel_case_types)]
#[derive(Eq, PartialEq, Display, Clone, Copy, Debug, Serialize)]
pub enum AceType {
    /// Access-allowed ACE that uses the ACCESS_ALLOWED_ACE (section 2.4.4.2)
    /// structure.
    ACCESS_ALLOWED_ACE_TYPE = 0x00,

    /// Access-denied ACE that uses the ACCESS_DENIED_ACE (section 2.4.4.4)
    /// structure.
    ACCESS_DENIED_ACE_TYPE = 0x01,

    /// System-audit ACE that uses the SYSTEM_AUDIT_ACE (section 2.4.4.10)
    /// structure.
    SYSTEM_AUDIT_ACE_TYPE = 0x02,

    /// Reserved for future use.
    SYSTEM_ALARM_ACE_TYPE = 0x03,

    /// Reserved for future use.
    ACCESS_ALLOWED_COMPOUND_ACE_TYPE = 0x04,

    /// Object-specific access-allowed ACE that uses the
    /// ACCESS_ALLOWED_OBJECT_ACE (section 2.4.4.3) structure.
    ACCESS_ALLOWED_OBJECT_ACE_TYPE = 0x05,

    /// Object-specific access-denied ACE that uses the ACCESS_DENIED_OBJECT_ACE
    /// (section 2.4.4.5) structure.
    ACCESS_DENIED_OBJECT_ACE_TYPE = 0x06,

    /// Object-specific system-audit ACE that uses the SYSTEM_AUDIT_OBJECT_ACE
    /// (section 2.4.4.11) structure.
    SYSTEM_AUDIT_OBJECT_ACE_TYPE = 0x07,

    /// Reserved for future use.
    SYSTEM_ALARM_OBJECT_ACE_TYPE = 0x08,

    /// Access-allowed callback ACE that uses the ACCESS_ALLOWED_CALLBACK_ACE
    /// (section 2.4.4.6) structure.
    ACCESS_ALLOWED_CALLBACK_ACE_TYPE = 0x09,

    /// Access-denied callback ACE that uses the ACCESS_DENIED_CALLBACK_ACE
    /// (section 2.4.4.7) structure.
    ACCESS_DENIED_CALLBACK_ACE_TYPE = 0x0a,

    /// Object-specific access-allowed callback ACE that uses the
    /// ACCESS_ALLOWED_CALLBACK_OBJECT_ACE (section 2.4.4.8) structure.
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE = 0x0b,

    /// Object-specific access-denied callback ACE that uses the
    /// ACCESS_DENIED_CALLBACK_OBJECT_ACE (section 2.4.4.9) structure.
    ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE = 0x0c,

    /// System-audit callback ACE that uses the SYSTEM_AUDIT_CALLBACK_ACE
    /// (section 2.4.4.12) structure.
    SYSTEM_AUDIT_CALLBACK_ACE_TYPE = 0x0d,

    /// Reserved for future use.
    SYSTEM_ALARM_CALLBACK_ACE_TYPE = 0x0e,

    /// System-audit callback ACE that uses the SYSTEM_AUDIT_CALLBACK_ACE
    /// (section 2.4.4.12) structure.
    SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE = 0x0f,

    /// Reserved for future use.
    SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE = 0x10,

    /// Object-specific system-audit callback ACE that uses the
    /// SYSTEM_AUDIT_CALLBACK_OBJECT_ACE (section 2.4.4.14) structure.
    SYSTEM_MANDATORY_LABEL_ACE_TYPE = 0x11,

    /// Reserved for future use.
    SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE = 0x12,

    /// Mandatory label ACE that uses the SYSTEM_MANDATORY_LABEL_ACE
    /// (section 2.4.4.13) structure.
    SYSTEM_SCOPED_POLICY_ID_ACE_TYPE = 0x13,
}

bitflags! {
    ///
    /// <https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586>
    #[derive(Eq, PartialEq, Clone, Copy, Debug, Serialize)]
    pub struct AceHeaderFlags: u8 {
        /// Child objects that are containers, such as directories, inherit the
        /// ACE as an effective ACE. The inherited ACE is inheritable unless the
        /// NO_PROPAGATE_INHERIT_ACE bit flag is also set.
        const CONTAINER_INHERIT_ACE = 0x02;

        /// Used with system-audit ACEs in a system access control list (SACL)
        /// to generate audit messages for failed access attempts.
        const FAILED_ACCESS_ACE_FLAG = 0x80;

        /// Indicates an inherit-only ACE, which does not control access to the
        /// object to which it is attached. If this flag is not set, the ACE is
        /// an effective ACE that controls access to the object to which it is
        /// attached.
        ///
        /// Both effective and inherit-only ACEs can be inherited depending on
        /// the state of the other inheritance flags.
        const INHERIT_ONLY_ACE = 0x08;

        /// Used to indicate that the ACE was inherited.<54> See section 2.5.3.5
        /// for processing rules for setting this flag.
        const INHERITED_ACE = 0x10;

        /// If the ACE is inherited by a child object, the system clears the
        /// OBJECT_INHERIT_ACE and CONTAINER_INHERIT_ACE flags in the inherited
        /// ACE. This prevents the ACE from being inherited by subsequent
        /// generations of objects.
        const NO_PROPAGATE_INHERIT_ACE = 0x04;

        /// Noncontainer child objects inherit the ACE as an effective ACE.
        ///
        /// For child objects that are containers, the ACE is inherited as an
        /// inherit-only ACE unless the NO_PROPAGATE_INHERIT_ACE bit flag is
        /// also set.
        const OBJECT_INHERIT_ACE = 0x01;

        /// Used with system-audit ACEs in a SACL to generate audit messages for
        /// successful access attempts.
        const SUCCESSFUL_ACCESS_ACE_FLAG = 0x40;

        const CRITICAL = 0x20;
        const TRUST_PROTECTED_FILTER = 0x40;
    }
}

impl AceHeaderFlags {
    pub fn sddl_string(&self) -> String {
        let mut sddl = String::with_capacity(16);
        let mut flag = |f: AceHeaderFlags, s: &str| {
            if self.contains(f) { sddl.push_str(s);}
        };
        flag(Self::OBJECT_INHERIT_ACE, SDDL_OBJECT_INHERIT);
        flag(Self::CONTAINER_INHERIT_ACE, SDDL_CONTAINER_INHERIT);
        flag(Self::NO_PROPAGATE_INHERIT_ACE, SDDL_NO_PROPAGATE);
        flag(Self::INHERIT_ONLY_ACE, SDDL_INHERIT_ONLY);
        flag(Self::INHERITED_ACE, SDDL_INHERITED);
        flag(Self::SUCCESSFUL_ACCESS_ACE_FLAG, SDDL_AUDIT_SUCCESS);
        flag(Self::FAILED_ACCESS_ACE_FLAG, SDDL_AUDIT_FAILURE);
        flag(Self::CRITICAL, SDDL_CRITICAL);
        flag(Self::OBJECT_INHERIT_ACE, SDDL_TRUST_PROTECTED_FILTER);
        sddl
    }
}

impl BinRead for AceHeaderFlags {
    type Args<'a> = ();

    fn read_options<R: std::io::Read + std::io::Seek>(
        reader: &mut R,
        endian: binrw::Endian,
        args: Self::Args<'_>,
    ) -> binrw::BinResult<Self> {
        let raw_value: u8 = reader.read_type_args(endian, args)?;
        Ok(AceHeaderFlags::from_bits(raw_value).unwrap())
    }
}

impl BinWrite for AceHeaderFlags {
    type Args<'a> = ();

    fn write_options<W: std::io::Write + std::io::Seek>(
        &self,
        writer: &mut W,
        endian: binrw::Endian,
        args: Self::Args<'_>,
    ) -> binrw::BinResult<()> {
        let raw_value = self.bits();
        writer.write_type_args(&raw_value, endian, args)
    }
}


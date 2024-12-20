use binrw::BinRead;
use binrw::BinReaderExt;
use binrw::BinWrite;
use binrw::BinWriterExt;
use bitflags::bitflags;
use serde::Serialize;

use crate::sddl_h::SDDL_AUTO_INHERITED;
use crate::sddl_h::SDDL_AUTO_INHERIT_REQ;
use crate::sddl_h::SDDL_NULL_ACL;
use crate::sddl_h::SDDL_PROTECTED;
use crate::AclType;

bitflags! {
    /// <https://github.com/microsoft/referencesource/blob/master/mscorlib/system/security/accesscontrol/securitydescriptor.cs>
    #[derive(Eq, PartialEq, Debug, Copy, Clone, Serialize)]
    pub struct ControlFlags: u16 {
        const None                                = 0x0000;
        const OwnerDefaulted                      = 0x0001; // set by RM only
        const GroupDefaulted                      = 0x0002; // set by RM only
        const DiscretionaryAclPresent             = 0x0004; // set by RM or user, 'off' means DACL is null
        const DiscretionaryAclDefaulted           = 0x0008; // set by RM only
        const SystemAclPresent                    = 0x0010; // same as DiscretionaryAclPresent
        const SystemAclDefaulted                  = 0x0020; // sams as DiscretionaryAclDefaulted
        const DiscretionaryAclUntrusted           = 0x0040; // ignore this one
        const ServerSecurity                      = 0x0080; // ignore this one
        const DiscretionaryAclAutoInheritRequired = 0x0100; // ignore this one
        const SystemAclAutoInheritRequired        = 0x0200; // ignore this one
        const DiscretionaryAclAutoInherited       = 0x0400; // set by RM only
        const SystemAclAutoInherited              = 0x0800; // set by RM only
        const DiscretionaryAclProtected           = 0x1000; // when set, RM will stop inheriting
        const SystemAclProtected                  = 0x2000; // when set, RM will stop inheriting
        const RMControlValid                      = 0x4000; // the reserved 8 bits have some meaning
        const SelfRelative                        = 0x8000; // must always be on
    }
}

impl BinRead for ControlFlags {
    type Args<'a> = ();

    fn read_options<R: std::io::Read + std::io::Seek>(
        reader: &mut R,
        _endian: binrw::Endian,
        args: Self::Args<'_>,
    ) -> binrw::BinResult<Self> {
        let raw_value: u16 = reader.read_le_args(args)?;
        Ok(ControlFlags::from_bits(raw_value).unwrap())
    }
}

impl BinWrite for ControlFlags {
    type Args<'a> = ();

    fn write_options<W: std::io::Write + std::io::Seek>(
        &self,
        writer: &mut W,
        _endian: binrw::Endian,
        args: Self::Args<'_>,
    ) -> binrw::BinResult<()> {
        let raw_value = self.bits();
        writer.write_le_args(&raw_value, args)
    }
}

impl ControlFlags {
    pub fn sddl_string(&self, acl_type: AclType) -> String {
        if *self == Self::None {
            SDDL_NULL_ACL.into()
        } else {
            let mut sddl = String::with_capacity(32);
            let mut flag = |flag: ControlFlags, s: &str| {
                if self.contains(flag) {
                    sddl.push_str(s);
                }
            };

            match acl_type {
                AclType::SACL => {
                    flag(Self::SystemAclProtected, SDDL_PROTECTED);
                    flag(Self::SystemAclAutoInheritRequired, SDDL_AUTO_INHERIT_REQ);
                    flag(Self::SystemAclAutoInherited, SDDL_AUTO_INHERITED);
                }
                AclType::DACL => {
                    flag(Self::DiscretionaryAclProtected, SDDL_PROTECTED);
                    flag(
                        Self::DiscretionaryAclAutoInheritRequired,
                        SDDL_AUTO_INHERIT_REQ,
                    );
                    flag(Self::DiscretionaryAclAutoInherited, SDDL_AUTO_INHERITED);
                }
            }
            sddl
        }
    }
}


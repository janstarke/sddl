use binrw::{BinRead, BinReaderExt, BinWrite, BinWriterExt};
use bitflags::bitflags;
use constants::{
    FILE_ALL, FILE_EXECUTE, FILE_READ, FILE_WRITE, KEY_ALL, KEY_EXECUTE, KEY_READ, KEY_WRITE,
};

use crate::sddl_h::*;

pub mod constants {
    use super::AccessMask;
    use lazy_static::lazy_static;

    ///  A principal with a lower mandatory level than the object cannot
    ///  write to the object.
    pub const SYSTEM_MANDATORY_LABEL_NO_WRITE_UP: AccessMask = AccessMask::CREATE_CHILD;

    ///  A principal with a lower mandatory level than the object cannot
    ///  read the object.
    pub const SYSTEM_MANDATORY_LABEL_NO_READ_UP: AccessMask = AccessMask::DELETE_CHILD;

    ///  A principal with a lower mandatory level than the object cannot
    ///  execute the object.
    pub const SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP: AccessMask = AccessMask::LIST_CHILDREN;

    /// The ObjectType GUID identifies a type of child object. The ACE
    /// controls the trustee's right to create this type of child object.
    pub const ADS_RIGHT_DS_CREATE_CHILD: AccessMask = AccessMask::CREATE_CHILD;

    /// The ObjectType GUID identifies a type of child object. The ACE
    /// controls the trustee's right to delete this type of child object.
    pub const ADS_RIGHT_DS_DELETE_CHILD: AccessMask = AccessMask::DELETE_CHILD;
    pub const ADS_RIGHT_ACTRL_DS_LIST: AccessMask = AccessMask::LIST_CHILDREN;

    /// The ObjectType GUID identifies a validated write.
    pub const ADS_RIGHT_DS_SELF: AccessMask = AccessMask::SELF_WRITE;

    /// The ObjectType GUID identifies a property set or property of the
    /// object. The ACE controls the trustee's right to read the property
    /// or property set.
    pub const ADS_RIGHT_DS_READ_PROP: AccessMask = AccessMask::READ_PROPERTY;

    /// The ObjectType GUID identifies a property set or property of the
    /// object. The ACE controls the trustee's right to write the property
    /// or property set.
    pub const ADS_RIGHT_DS_WRITE_PROP: AccessMask = AccessMask::WRITE_PROPERTY;
    pub const ADS_RIGHT_DS_DELETE_TREE: AccessMask = AccessMask::DELETE_TREE;
    pub const ADS_RIGHT_DS_LIST_OBJECT: AccessMask = AccessMask::LIST_OBJECT;

    /// The ObjectType GUID identifies an extended access right.
    pub const ADS_RIGHT_DS_CONTROL_ACCESS: AccessMask = AccessMask::CONTROL_ACCESS;

    lazy_static! {
        pub static ref FILE_ALL: AccessMask = AccessMask::SYNCHRONIZE
            | AccessMask::WRITE_OWNER
            | AccessMask::WRITE_DACL
            | AccessMask::READ_CONTROL
            | AccessMask::DELETE
            | AccessMask::CONTROL_ACCESS
            | AccessMask::LIST_OBJECT
            | AccessMask::DELETE_TREE
            | AccessMask::WRITE_PROPERTY
            | AccessMask::READ_PROPERTY
            | AccessMask::SELF_WRITE
            | AccessMask::LIST_CHILDREN
            | AccessMask::DELETE_CHILD
            | AccessMask::CREATE_CHILD;
        pub static ref FILE_EXECUTE: AccessMask = AccessMask::SYNCHRONIZE
            | AccessMask::READ_CONTROL
            | AccessMask::LIST_OBJECT
            | AccessMask::WRITE_PROPERTY;
        pub static ref FILE_WRITE: AccessMask = AccessMask::SYNCHRONIZE
            | AccessMask::READ_CONTROL
            | AccessMask::CONTROL_ACCESS
            | AccessMask::READ_PROPERTY
            | AccessMask::LIST_CHILDREN
            | AccessMask::DELETE_CHILD;
        pub static ref FILE_READ: AccessMask = AccessMask::SYNCHRONIZE
            | AccessMask::READ_CONTROL
            | AccessMask::LIST_OBJECT
            | AccessMask::SELF_WRITE
            | AccessMask::CREATE_CHILD;
        pub static ref KEY_ALL: AccessMask = AccessMask::WRITE_OWNER
            | AccessMask::WRITE_DACL
            | AccessMask::READ_CONTROL
            | AccessMask::DELETE
            | AccessMask::WRITE_PROPERTY
            | AccessMask::READ_PROPERTY
            | AccessMask::SELF_WRITE
            | AccessMask::LIST_CHILDREN
            | AccessMask::DELETE_CHILD
            | AccessMask::CREATE_CHILD;
        pub static ref KEY_READ: AccessMask = AccessMask::READ_CONTROL
            | AccessMask::READ_PROPERTY
            | AccessMask::SELF_WRITE
            | AccessMask::CREATE_CHILD;
        pub static ref KEY_WRITE: AccessMask =
            AccessMask::READ_CONTROL | AccessMask::LIST_CHILDREN | AccessMask::DELETE_CHILD;
        pub static ref KEY_EXECUTE: AccessMask = AccessMask::READ_CONTROL
            | AccessMask::READ_PROPERTY
            | AccessMask::SELF_WRITE
            | AccessMask::CREATE_CHILD;
    }
}

bitflags! {
    #[derive(Eq, PartialEq, Debug, Copy, Clone)]
    pub struct AccessMask: u32 {

        /// **When used in an Access Request operation:** When read access to an
        /// object is requested, this bit is translated to a combination of
        /// bits. These are most often set in the lower 16 bits of the
        /// ACCESS_MASK. (Individual protocol specifications MAY specify a
        /// different configuration.) The bits that are set are implementation
        /// dependent. During this translation, the GR bit is cleared. The
        /// resulting ACCESS_MASK bits are the actual permissions that are
        /// checked against the ACE structures in the security descriptor that
        /// attached to the object.
        ///
        /// **When used to set the Security Descriptor on an object:** When the
        /// GR bit is set in an ACE that is to be attached to an object, it is
        /// translated into a combination of bits, which are usually set in the
        /// lower 16 bits of the ACCESS_MASK. (Individual protocol
        /// specifications MAY specify a different configuration.) The bits
        /// that are set are implementation dependent. During this translation,
        /// the GR bit is cleared. The resulting ACCESS_MASK bits are the actual
        /// permissions that are granted by this ACE.
        const GENERIC_READ = 0x80000000;

        /// **When used in an Access Request operation:** When write access to
        /// an object is requested, this bit is translated to a combination of
        /// bits, which are usually set in the lower 16 bits of the ACCESS_MASK.
        /// (Individual protocol specifications MAY specify a different
        /// configuration.) The bits that are set are implementation dependent.
        /// During this translation, the GW bit is cleared. The resulting
        /// ACCESS_MASK bits are the actual permissions that are checked against
        /// the ACE structures in the security descriptor that attached to the
        /// object.
        ///
        /// **When used to set the Security Descriptor on an object:** When the
        /// GW bit is set in an ACE that is to be attached to an object, it is
        /// translated into a combination of bits, which are usually set in the
        /// lower 16 bits of the ACCESS_MASK. (Individual protocol
        /// specifications MAY specify a different configuration.) The bits that
        /// are set are implementation dependent. During this translation, the
        /// GW bit is cleared. The resulting ACCESS_MASK bits are the actual
        /// permissions that are granted by this ACE.
        const GENERIC_WRITE = 0x4000000;

        /// **When used in an Access Request operation:** When execute access to
        /// an object is requested, this bit is translated to a combination of
        /// bits, which are usually set in the lower 16 bits of the ACCESS_MASK.
        /// (Individual protocol specifications MAY specify a different
        /// configuration.) The bits that are set are implementation dependent.
        /// During this translation, the GX bit is cleared. The resulting
        /// ACCESS_MASK bits are the actual permissions that are checked against
        /// the ACE structures in the security descriptor that attached to the
        /// object.
        ///
        /// **When used to set the Security Descriptor on an object:** When the
        /// GX bit is set in an ACE that is to be attached to an object, it is
        /// translated into a combination of bits, which are usually set in the
        /// lower 16 bits of the ACCESS_MASK. (Individual protocol
        /// specifications MAY specify a different configuration.) The bits that
        /// are set are implementation AdsAccessMaskdependent. During this
        /// translation, the GX bit is cleared. The resulting ACCESS_MASK bits
        /// are the actual permissions that are granted by this ACE.
        const GENERIC_EXECUTE = 0x20000000;

        /// **When used in an Access Request operation:** When all access
        /// permissions to an object are requested, this bit is translated to a
        /// combination of bits, which are usually set in the lower 16 bits of
        /// the ACCESS_MASK. (Individual protocol specifications MAY specify a
        /// different configuration.) Objects are free to include bits from the
        /// upper 16 bits in that translation as required by the objects
        /// semantics. The bits that are set are implementation dependent.
        /// During this translation, the GA bit is cleared. The resulting
        /// ACCESS_MASK bits are the actual permissions that are checked against
        /// the ACE structures in the security descriptor that attached to the
        /// object.
        ///
        /// **When used to set the Security Descriptor on an object:** When the
        /// GA bit is set in an ACE that is to be attached to an object, it is
        /// translated into a combination of bits, which are usually set in the
        /// lower 16 bits of the ACCESS_MASK. (Individual protocol
        /// specifications MAY specify a different configuration.) Objects are
        /// free to include bits from the upper 16 bits in that translation, if
        /// required by the objects semantics. The bits that are set are
        /// implementation dependent. During this translation, the GA bit is
        /// cleared. The resulting ACCESS_MASK bits are the actual permissions
        /// that are granted by this ACE.
        const GENERIC_ALL = 0x10000000;

        /// **When used in an Access Request operation:** When requested, this
        /// bit grants the requestor the maximum permissions allowed to the
        /// object through the Access Check Algorithm. This bit can only be
        /// requested; it cannot be set in an ACE.
        ///
        /// **When used to set the Security Descriptor on an object:**
        /// Specifying the Maximum Allowed bit in the SECURITY_DESCRIPTOR has no
        /// meaning. The MA bit SHOULD NOT be set and SHOULD be ignored when
        /// part of a SECURITY_DESCRIPTOR structure.
        const MAXIMUM_ALLOWED = 0x02000000;

        /// **When used in an Access Request operation:** When requested, this
        /// bit grants the requestor the right to change the SACL of an object.
        /// This bit MUST NOT be set in an ACE that is part of a DACL. When set
        /// in an ACE that is part of a SACL, this bit controls auditing of
        /// accesses to the SACL itself.
        const ACCESS_SYSTEM_SECURITY = 0x01000000;

        /// Specifies access to the object sufficient to synchronize or wait on
        /// the object.
        const SYNCHRONIZE = 0x00100000;

        /// Specifies access to change the owner of the object as listed in the
        /// security descriptor.
        const WRITE_OWNER = 0x00080000;

        /// Specifies access to change the discretionary access control list of
        /// the security descriptor of an object.
        const WRITE_DACL = 0x00040000;

        /// Specifies access to read the security descriptor of an object.
        const READ_CONTROL = 0x00020000;

        /// Specifies access to delete an object.
        const DELETE = 0x00010000;

        const CONTROL_ACCESS = 0x00000100;
        const LIST_OBJECT = 0x00000080;
        const DELETE_TREE = 0x00000040;
        const WRITE_PROPERTY = 0x00000020;
        const READ_PROPERTY = 0x00000010;
        const SELF_WRITE = 0x00000008;
        const LIST_CHILDREN = 0x00000004;
        const DELETE_CHILD = 0x00000002;
        const CREATE_CHILD = 0x00000001;

        // The source may set any bits
        const _ = !0;
    }
}

impl AccessMask {
    pub fn sddl_string(&self) -> String {
        if *self == *FILE_ALL {
            SDDL_FILE_ALL.into()
        } else if *self == *FILE_READ {
            SDDL_FILE_READ.into()
        } else if *self == *FILE_WRITE {
            SDDL_FILE_WRITE.into()
        } else if *self == *FILE_EXECUTE {
            SDDL_FILE_EXECUTE.into()
        } else if *self == *KEY_ALL {
            SDDL_KEY_ALL.into()
        } else if *self == *KEY_READ {
            SDDL_KEY_READ.into()
        } else if *self == *KEY_WRITE {
            SDDL_KEY_WRITE.into()
        } else if *self == *KEY_EXECUTE {
            SDDL_KEY_EXECUTE.into()
        } else {
            let mut sddl = String::with_capacity(32);
            let mut flag = |mask: AccessMask, s: &str| {
                if self.contains(mask) {
                    sddl.push_str(s);
                }
            };

            flag(Self::GENERIC_READ, SDDL_GENERIC_READ);
            flag(Self::GENERIC_WRITE, SDDL_GENERIC_WRITE);
            flag(Self::GENERIC_EXECUTE, SDDL_GENERIC_EXECUTE);
            flag(Self::GENERIC_ALL, SDDL_GENERIC_ALL);
            flag(Self::MAXIMUM_ALLOWED, "MA");
            flag(Self::ACCESS_SYSTEM_SECURITY, "AS");
            flag(Self::SYNCHRONIZE, "SY");
            flag(Self::WRITE_OWNER, SDDL_WRITE_OWNER);
            flag(Self::WRITE_DACL, SDDL_WRITE_DAC);
            flag(Self::READ_CONTROL, SDDL_READ_CONTROL);
            flag(Self::DELETE, SDDL_STANDARD_DELETE);
            sddl
        }
    }
}

impl BinRead for AccessMask {
    type Args<'a> = ();

    fn read_options<R: std::io::Read + std::io::Seek>(
        reader: &mut R,
        endian: binrw::Endian,
        args: Self::Args<'_>,
    ) -> binrw::BinResult<Self> {
        let raw_value: u32 = reader.read_type_args(endian, args)?;
        Ok(AccessMask::from_bits(raw_value).unwrap())
    }
}

impl From<u32> for AccessMask {
    fn from(value: u32) -> Self {
        AccessMask::from_bits(value).unwrap()
    }
}

impl<'input> TryFrom<&'input str> for AccessMask {
    type Error = crate::Error;

    fn try_from(value: &'input str) -> Result<Self, Self::Error> {
        Ok(crate::parser::AccessMaskParser::new().parse(None, value)?)
    }
}

impl BinWrite for AccessMask {
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

impl serde::Serialize for AccessMask {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        bitflags_serde_legacy::serialize(self, "AccessMask", serializer)
    }
}

impl<'de> serde::Deserialize<'de> for AccessMask {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        bitflags_serde_legacy::deserialize("AccessMask", deserializer)
    }
}

#[cfg(test)]
mod tests {
    use crate::AccessMask;

    use super::constants::*;

    #[test]
    fn test_simple_mask() {
        assert_eq!(
            AccessMask::try_from("0x80000000").unwrap(),
            AccessMask::GENERIC_READ
        );
        assert_ne!(
            AccessMask::try_from("0x80000001").unwrap(),
            AccessMask::GENERIC_READ
        );
    }

    #[test]
    fn test_complex_mask1() {
        assert_eq!(
            AccessMask::try_from("GRGXWP").unwrap(),
            AccessMask::GENERIC_READ | AccessMask::GENERIC_EXECUTE | AccessMask::WRITE_PROPERTY
        );
    }

    #[test]
    fn test_complex_mask2() {
        assert_eq!(AccessMask::try_from("FA").unwrap(), *FILE_ALL);
    }

    #[test]
    fn test_statics() {
        assert_eq!(FILE_ALL.bits(), 0x001F01FF);
        assert_eq!(FILE_EXECUTE.bits(), 0x001200A0);
        assert_eq!(FILE_WRITE.bits(), 0x00120116);
        assert_eq!(FILE_READ.bits(), 0x00120089);
        assert_eq!(KEY_ALL.bits(), 0x000F003F);
        assert_eq!(KEY_READ.bits(), 0x00020019);
        assert_eq!(KEY_EXECUTE.bits(), 0x00020019);
        assert_eq!(KEY_WRITE.bits(), 0x00020006);
    }
}

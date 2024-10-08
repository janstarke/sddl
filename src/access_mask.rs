use binrw::{BinRead, BinReaderExt, BinWrite, BinWriterExt};
use bitflags::bitflags;

bitflags! {
    #[derive(Eq, PartialEq, Debug)]
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
        /// are set are implementation dependent. During this translation, the
        /// GX bit is cleared. The resulting ACCESS_MASK bits are the actual
        /// permissions that are granted by this ACE.
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

        // The source may set any bits
        const _ = !0;
    }
}

impl AccessMask {
    /// returns the lower 16 bits of the access mask
    ///
    /// ```rust
    /// use sddl::AccessMask;
    /// assert_eq!(AccessMask::GENERIC_READ.object_specific_flags(), 0);
    /// assert_eq!((AccessMask::GENERIC_READ | AccessMask::GENERIC_WRITE).object_specific_flags(), 0);
    ///
    /// assert_eq!(AccessMask::from_bits(0x80000000).unwrap(), AccessMask::GENERIC_READ);
    /// assert_eq!(AccessMask::from_bits(0x80001234).unwrap().object_specific_flags(), 0x1234);
    /// assert_eq!(AccessMask::from_bits(0x00001234).unwrap().object_specific_flags(), 0x1234);
    /// ```
    pub fn object_specific_flags(&self) -> u16 {
        let bytes = self.bits().to_be_bytes();
        u16::from_be_bytes([bytes[2], bytes[3]])
    }
}

bitflags! {
    #[derive(Eq, PartialEq, Debug)]
    pub struct AdsAccessMask: u16 {

        /// The ObjectType GUID identifies an extended access right.
        const ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100;

        /// The ObjectType GUID identifies a type of child object. The ACE
        /// controls the trustee's right to create this type of child object.
        const ADS_RIGHT_DS_CREATE_CHILD = 0x00000001;

        /// The ObjectType GUID identifies a type of child object. The ACE
        /// controls the trustee's right to delete this type of child object.
        const ADS_RIGHT_DS_DELETE_CHILD = 0x00000002;

        /// The ObjectType GUID identifies a property set or property of the
        /// object. The ACE controls the trustee's right to read the property
        /// or property set.
        const ADS_RIGHT_DS_READ_PROP = 0x00000010;

        /// The ObjectType GUID identifies a property set or property of the
        /// object. The ACE controls the trustee's right to write the property
        /// or property set.
        const ADS_RIGHT_DS_WRITE_PROP = 0x00000020;

        /// The ObjectType GUID identifies a validated write.
        const ADS_RIGHT_DS_SELF = 0x00000008;
        const _ = !0;
    }
}

bitflags! {
    #[derive(Eq, PartialEq, Debug)]
    pub struct MandatoryAccessMask: u16 {
        ///  A principal with a lower mandatory level than the object cannot
        ///  write to the object. 
        const SYSTEM_MANDATORY_LABEL_NO_WRITE_UP = 0x01;

        ///  A principal with a lower mandatory level than the object cannot
        ///  read the object. 
        const SYSTEM_MANDATORY_LABEL_NO_READ_UP = 0x02;

        ///  A principal with a lower mandatory level than the object cannot
        ///  execute the object. 
        const SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP = 0x04;
        const _ = !0;
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

impl From<&AccessMask> for AdsAccessMask {
    fn from(value: &AccessMask) -> Self {
        Self::from_bits(value.object_specific_flags()).unwrap()
    }
}

impl From<&AccessMask> for MandatoryAccessMask {
    fn from(value: &AccessMask) -> Self {
        Self::from_bits(value.object_specific_flags()).unwrap()
    }
}

use std::mem;

use binrw::binrw;
use getset::Getters;

use crate::{AccessMask, AceHeader, AceType, AdsAccessMask, Guid, MandatoryAccessMask, Sid};

/// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586
#[binrw]
#[derive(Eq, PartialEq, Getters)]
#[getset(get = "pub")]
pub struct Ace {
    header: AceHeader,

    mask: AccessMask,

    #[br(args(&header, &mask))]
    #[bw(args(header, mask))]
    data: AceData,
}

#[binrw]
#[brw(import(header: &AceHeader, ace_mask: &AccessMask))]
#[derive(Eq, PartialEq)]
#[allow(non_camel_case_types)]
pub enum AceData {
    /// The ACCESS_ALLOWED_ACE structure defines an ACE for the discretionary
    /// access control list (DACL) that controls access to an object. An
    /// access-allowed ACE allows access to an object for a specific trustee
    /// identified by a security identifier (SID).
    #[brw(assert(*header.ace_type() == AceType::ACCESS_ALLOWED_ACE_TYPE))]
    ACCESS_ALLOWED_ACE {
        /// The SID of a trustee.
        #[brw(assert(sid.len() % 4 == 0))]
        sid: Sid,
    },

    /// The ACCESS_ALLOWED_OBJECT_ACE structure defines an ACE that controls
    /// allowed access to an object, a property set, or property. The ACE
    /// contains a set of access rights, a GUID that identifies the type of
    /// object, and a SID that identifies the trustee to whom the system will
    /// grant access. The ACE also contains a GUID and a set of flags that
    /// control inheritance of the ACE by child objects.
    #[brw(assert(*header.ace_type() == AceType::ACCESS_ALLOWED_OBJECT_ACE_TYPE))]
    ACCESS_ALLOWED_OBJECT_ACE {
        #[br(calc(ace_mask.into()))]
        #[bw(ignore)]
        mask: AdsAccessMask,

        /// A GUID that identifies a property set, property, extended right, or
        /// type of child object. The purpose of this GUID depends on the user
        /// rights specified in the Mask field. This field is valid only if the
        /// ACE_OBJECT_TYPE_PRESENT bit is set in the Flags field. Otherwise,
        /// the ObjectType field is ignored. For information on access rights
        /// and for a mapping of the control access rights to the corresponding
        /// GUID value that identifies each right, see [MS-ADTS] sections
        /// 5.1.3.2 and 5.1.3.2.1.
        ///
        /// ACCESS_MASK bits are not mutually exclusive. Therefore, the
        /// ObjectType field can be set in an ACE with any ACCESS_MASK. If the
        /// AccessCheck algorithm calls this ACE and does not find an
        /// appropriate GUID, then that ACE will be ignored. For more
        /// information on access checks and object access, see [MS-ADTS]
        /// section 5.1.3.3.3.
        object_type: Guid,

        /// A GUID that identifies the type of child object that can inherit the
        /// ACE. Inheritance is also controlled by the inheritance flags in the
        /// ACE_HEADER, as well as by any protection against inheritance placed
        /// on the child objects. This field is valid only if the
        /// ACE_INHERITED_OBJECT_TYPE_PRESENT bit is set in the Flags member.
        /// Otherwise, the InheritedObjectType field is ignored.
        inherited_object_type: Guid,

        /// The SID of a trustee. The length of the SID MUST be a multiple of 4.
        #[brw(assert(sid.len() % 4 == 0))]
        sid: Sid,
    },

    /// The ACCESS_DENIED_ACE structure defines an ACE for the DACL that
    /// controls access to an object. An access-denied ACE denies access to an
    /// object for a specific trustee identified by a SID.
    #[brw(assert(*header.ace_type() == AceType::ACCESS_DENIED_ACE_TYPE))]
    ACCESS_DENIED_ACE {
        /// The SID of a trustee.
        #[brw(assert(sid.len() % 4 == 0))]
        sid: Sid,
    },

    /// The ACCESS_DENIED_OBJECT_ACE structure defines an ACE that controls
    /// denied access to an object, a property set, or a property. The ACE
    /// contains a set of access rights, a GUID that identifies the type of
    /// object, and a SID that identifies the trustee to whom the system will
    /// deny access. The ACE also contains a GUID and a set of flags that
    /// control inheritance of the ACE by child objects.
    #[brw(assert(*header.ace_type() == AceType::ACCESS_DENIED_OBJECT_ACE_TYPE))]
    ACCESS_DENIED_OBJECT_ACE {
        #[br(calc(ace_mask.into()))]
        #[bw(ignore)]
        mask: AdsAccessMask,
        object_type: Guid,
        inherited_object_type: Guid,

        ///  The SID of a trustee.
        #[brw(assert(sid.len() % 4 == 0))]
        sid: Sid,
    },

    /// The ACCESS_ALLOWED_CALLBACK_ACE structure defines an ACE for the DACL
    /// that controls access to an object. An access-allowed ACE allows access
    /// to an object for a specific trustee identified by a SID.
    #[brw(assert(*header.ace_type() == AceType::ACCESS_ALLOWED_CALLBACK_ACE_TYPE))]
    ACCESS_ALLOWED_CALLBACK_ACE {
        ///  The SID of a trustee.
        #[brw(assert(sid.len() % 4 == 0))]
        sid: Sid,

        /// Optional application data. The size of the application data is
        /// determined by the AceSize field of the ACE_HEADER.
        #[br(count=*header.ace_size() as usize - sid.len())]
        application_data: Vec<u8>,

        /// Conditional ACEs are a form of CALLBACK ACEs with a special format
        /// of the application data. A Conditional ACE allows a conditional
        /// expression to be evaluated when an access check (as specified in
        /// section 2.5.3.2) is performed.
        #[br(calc(if application_data.len() >= 4 {application_data[0..4] == [0x61, 0x72, 0x74, 0x78]} else {false}))]
        #[bw(ignore)]
        is_conditional: bool,
    },

    /// The ACCESS_DENIED_CALLBACK_ACE structure defines an ACE for the DACL
    /// that controls access to an object. An access-denied ACE denies access to
    /// an object for a specific trustee identified by a SID.
    #[brw(assert(*header.ace_type() == AceType::ACCESS_DENIED_CALLBACK_ACE_TYPE))]
    ACCESS_DENIED_CALLBACK_ACE {
        ///  The SID of a trustee.
        #[brw(assert(sid.len() % 4 == 0))]
        sid: Sid,

        /// Optional application data. The size of the application data is
        /// determined by the AceSize field of the ACE_HEADER.
        #[br(count=*header.ace_size() as usize - sid.len())]
        application_data: Vec<u8>,

        /// Conditional ACEs are a form of CALLBACK ACEs with a special format
        /// of the application data. A Conditional ACE allows a conditional
        /// expression to be evaluated when an access check (as specified in
        /// section 2.5.3.2) is performed.
        #[br(calc(if application_data.len() >= 4 {application_data[0..4] == [0x61, 0x72, 0x74, 0x78]} else {false}))]
        #[bw(ignore)]
        is_conditional: bool,
    },

    /// The ACCESS_ALLOWED_CALLBACK_OBJECT_ACE structure defines an ACE that
    /// controls allowed access to an object, property set, or property. The ACE
    /// contains a set of user rights, a GUID that identifies the type of
    /// object, and a SID that identifies the trustee to whom the system will
    /// grant access. The ACE also contains a GUID and a set of flags that
    /// control inheritance of the ACE by child objects.
    #[brw(assert(*header.ace_type() == AceType::ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE))]
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE {
        #[br(calc(ace_mask.into()))]
        #[bw(ignore)]
        mask: AdsAccessMask,
        /// A GUID that identifies a property set, property, extended right, or
        /// type of child object. The purpose of this GUID depends on the user
        /// rights specified in the Mask field. This field is valid only if the
        /// ACE _OBJECT_TYPE_PRESENT bit is set in the Flags field. Otherwise,
        /// the ObjectType field is ignored.
        object_type: Guid,

        /// A GUID that identifies the type of child object that can inherit the
        /// ACE. Inheritance is also controlled by the inheritance flags in the
        /// ACE_HEADER, as well as by any protection against inheritance placed
        /// on the child objects. This field is valid only if the
        /// ACE_INHERITED_OBJECT_TYPE_PRESENT bit is set in the Flags member.
        /// Otherwise, the InheritedObjectType field is ignored.
        inherited_object_type: Guid,

        ///  The SID of a trustee.
        #[brw(assert(sid.len() % 4 == 0))]
        sid: Sid,

        /// Optional application data. The size of the application data is
        /// determined by the AceSize field of the ACE_HEADER.
        #[br(count=*header.ace_size() as usize - (mem::size_of::<Guid>() + mem::size_of::<Guid>() + sid.len()))]
        application_data: Vec<u8>,

        /// Conditional ACEs are a form of CALLBACK ACEs with a special format
        /// of the application data. A Conditional ACE allows a conditional
        /// expression to be evaluated when an access check (as specified in
        /// section 2.5.3.2) is performed.
        #[br(calc(if application_data.len() >= 4 {application_data[0..4] == [0x61, 0x72, 0x74, 0x78]} else {false}))]
        #[bw(ignore)]
        is_conditional: bool,
    },

    /// The ACCESS_DENIED_CALLBACK_OBJECT_ACE structure defines an ACE that
    /// controls denied access to an object, a property set, or property. The
    /// ACE contains a set of user rights, a GUID that identifies the type of
    /// object, and a SID that identifies the trustee to whom the system will
    /// deny access. The ACE also contains a GUID and a set of flags that
    /// control inheritance of the ACE by child objects.
    #[brw(assert(*header.ace_type() == AceType::ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE))]
    ACCESS_DENIED_CALLBACK_OBJECT_ACE {
        #[br(calc(ace_mask.into()))]
        #[bw(ignore)]
        mask: AdsAccessMask,

        /// A GUID that identifies a property set, property, extended right, or
        /// type of child object. The purpose of this GUID depends on the user
        /// rights specified in the Mask field. This field is valid only if the
        /// ACE _OBJECT_TYPE_PRESENT bit is set in the Flags field. Otherwise,
        /// the ObjectType field is ignored.
        object_type: Guid,

        /// A GUID that identifies the type of child object that can inherit the
        /// ACE. Inheritance is also controlled by the inheritance flags in the
        /// ACE_HEADER, as well as by any protection against inheritance placed
        /// on the child objects. This field is valid only if the
        /// ACE_INHERITED_OBJECT_TYPE_PRESENT bit is set in the Flags member.
        /// Otherwise, the InheritedObjectType field is ignored.
        inherited_object_type: Guid,

        ///  The SID of a trustee.
        #[brw(assert(sid.len() % 4 == 0))]
        sid: Sid,

        /// Optional application data. The size of the application data is
        /// determined by the AceSize field of the ACE_HEADER.
        #[br(count=*header.ace_size() as usize - (mem::size_of::<Guid>() + mem::size_of::<Guid>() + sid.len()))]
        application_data: Vec<u8>,

        /// Conditional ACEs are a form of CALLBACK ACEs with a special format
        /// of the application data. A Conditional ACE allows a conditional
        /// expression to be evaluated when an access check (as specified in
        /// section 2.5.3.2) is performed.
        #[br(calc(if application_data.len() >= 4 {application_data[0..4] == [0x61, 0x72, 0x74, 0x78]} else {false}))]
        #[bw(ignore)]
        is_conditional: bool,
    },

    /// The SYSTEM_AUDIT_ACE structure defines an access ACE for the system
    /// access control list (SACL) that specifies what types of access cause
    /// system-level notifications. A system-audit ACE causes an audit message
    /// to be logged when a specified trustee attempts to gain access to an
    /// object. The trustee is identified by a SID.
    #[brw(assert(*header.ace_type() == AceType::SYSTEM_AUDIT_ACE_TYPE))]
    SYSTEM_AUDIT_ACE {
        ///  The SID of a trustee. The length of the SID MUST be a multiple of
        ///  4. An access attempt of a kind specified by the Mask field by any
        ///  trustee whose SID matches the Sid field causes the system to
        ///  generate an audit message. If an application does not specify a SID
        ///  for this field, audit messages are generated for the specified
        ///  access rights for all trustees.
        #[brw(assert(sid.len() % 4 == 0))]
        sid: Sid,
    },

    /// The SYSTEM_AUDIT_OBJECT_ACE structure defines an ACE for a SACL. The ACE
    /// can audit access to an object or subobjects, such as property sets or
    /// properties. The ACE contains a set of user rights, a GUID that
    /// identifies the type of object or subobject, and a SID that identifies
    /// the trustee for whom the system will audit access. The ACE also contains
    /// a GUID and a set of flags that control inheritance of the ACE by child
    /// objects.
    #[brw(assert(*header.ace_type() == AceType::SYSTEM_AUDIT_OBJECT_ACE_TYPE))]
    SYSTEM_AUDIT_OBJECT_ACE {
        #[br(calc(ace_mask.into()))]
        #[bw(ignore)]
        mask: AdsAccessMask,

        /// A GUID that identifies a property set, a property, an extended
        /// right, or a type of child object. The purpose of this GUID depends
        /// on the user rights specified in the Mask field. This field is valid
        /// only if the ACE_OBJECT_TYPE_PRESENT bit is set in the Flags field.
        /// Otherwise, the ObjectType field is ignored. 
        object_type: Guid,

        /// A GUID that identifies the type of child object that can inherit the
        /// ACE. Inheritance is also controlled by the inheritance flags in the
        /// ACE_HEADER, as well as by any protection against inheritance placed
        /// on the child objects. This field is valid only if the
        /// ACE_INHERITED_OBJECT_TYPE_PRESENT bit is set in the Flags member.
        /// Otherwise, the InheritedObjectType field is ignored.
        inherited_object_type: Guid,

        ///  The SID of a trustee.
        #[brw(assert(sid.len() % 4 == 0))]
        sid: Sid,

        /// Optional application data. The size of the application data is
        /// determined by the AceSize field of the ACE_HEADER.
        #[br(count=*header.ace_size() as usize - (mem::size_of::<Guid>() + mem::size_of::<Guid>() + sid.len()))]
        application_data: Vec<u8>,
    },

    /// The SYSTEM_AUDIT_CALLBACK_ACE structure defines an ACE for the SACL that
    /// specifies what types of access cause system-level notifications. A
    /// system-audit ACE causes an audit message to be logged when a specified
    /// trustee attempts to gain access to an object. The trustee is identified
    /// by a SID.
    #[brw(assert(*header.ace_type() == AceType::SYSTEM_AUDIT_CALLBACK_ACE_TYPE))]
    SYSTEM_AUDIT_CALLBACK_ACE {
        ///  The SID of a trustee. The length of the SID MUST be a multiple of
        ///  4. An access attempt of a kind specified by the Mask field by any
        ///  trustee whose SID matches the Sid field causes the system to
        ///  generate an audit message. If an application does not specify a SID
        ///  for this field, audit messages are generated for the specified
        ///  access rights for all trustees.
        #[brw(assert(sid.len() % 4 == 0))]
        sid: Sid,

        /// Optional application data. The size of the application data is
        /// determined by the AceSize field of the ACE_HEADER.
        #[br(count=*header.ace_size() as usize - sid.len())]
        application_data: Vec<u8>,

        /// Conditional ACEs are a form of CALLBACK ACEs with a special format
        /// of the application data. A Conditional ACE allows a conditional
        /// expression to be evaluated when an access check (as specified in
        /// section 2.5.3.2) is performed.
        #[br(calc(if application_data.len() >= 4 {application_data[0..4] == [0x61, 0x72, 0x74, 0x78]} else {false}))]
        #[bw(ignore)]
        is_conditional: bool,
    },

    /// The SYSTEM_MANDATORY_LABEL_ACE structure defines an ACE for the SACL
    /// that specifies the mandatory access level and policy for a securable
    /// object
    #[brw(assert(*header.ace_type() == AceType::SYSTEM_MANDATORY_LABEL_ACE_TYPE))]
    SYSTEM_MANDATORY_LABEL_ACE {
        #[br(calc(ace_mask.into()))]
        #[bw(ignore)]
        mask: MandatoryAccessMask,

        ///  The SID of a trustee. The length of the SID MUST be a multiple of
        ///  4. The identifier authority of the SID must be
        ///  SECURITY_MANDATORY_LABEL_AUTHORITY. The RID of the SID specifies
        ///  the mandatory integrity level of the object associated with the
        ///  SACL that contains this ACE. The RID must be one of the following
        ///  values.
        #[brw(assert(sid.len() % 4 == 0 && sid.identifier_authority() == &crate::SECURITY_MANDATORY_LABEL_AUTHORITY))]
        sid: Sid,
    },

    /// The SYSTEM_AUDIT_CALLBACK_OBJECT_ACE structure defines an ACE for a
    /// SACL. The ACE can audit access to an object or subobjects, such as
    /// property sets or properties. The ACE contains a set of user rights, a
    /// GUID that identifies the type of object or subobject, and a SID that
    /// identifies the trustee for whom the system will audit access. The ACE
    /// also contains a GUID and a set of flags that control inheritance of the
    /// ACE by child objects.
    #[brw(assert(*header.ace_type() == AceType::SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE))]
    SYSTEM_AUDIT_CALLBACK_OBJECT_ACE {
        #[br(calc(ace_mask.into()))]
        #[bw(ignore)]
        mask: AdsAccessMask,

        /// A GUID that identifies a property set, property, extended right, or
        /// type of child object. The purpose of this GUID depends on the user
        /// rights specified in the Mask field. This field is valid only if the
        /// ACE_OBJECT_TYPE_PRESENT bit is set in the Flags field. Otherwise,
        /// the ObjectType field is ignored. 
        object_type: Guid,

        /// A GUID that identifies the type of child object that can inherit the
        /// ACE. Inheritance is also controlled by the inheritance flags in the
        /// ACE_HEADER, as well as by any protection against inheritance placed
        /// on the child objects. This field is valid only if the
        /// ACE_INHERITED_OBJECT_TYPE_PRESENT bit is set in the Flags member.
        /// Otherwise, the InheritedObjectType field is ignored.
        inherited_object_type: Guid,

        ///  The SID of a trustee.
        #[brw(assert(sid.len() % 4 == 0))]
        sid: Sid,

        /// Optional application data. The size of the application data is
        /// determined by the AceSize field of the ACE_HEADER.
        #[br(count=*header.ace_size() as usize - (mem::size_of::<Guid>() + mem::size_of::<Guid>() + sid.len()))]
        application_data: Vec<u8>,
    },

    /// The SYSTEM_RESOURCE_ATTRIBUTE_ACE structure defines an ACE for the
    /// specification of a resource attribute associated with an object. A
    /// SYSTEM_RESOURCE_ATTRIBUTE_ACE is used in conditional ACEs in specifying
    /// access or audit policy for the resource.
    #[brw(assert(*header.ace_type() == AceType::SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE))]
    SYSTEM_RESOURCE_ATTRIBUTE_ACE {
        object_type: Guid,

        inherited_object_type: Guid,

        ///  The SID corresponding to the Everyone SID (S-1-1-0) in binary form.
        #[brw(assert(sid.len() % 4 == 0))]
        sid: Sid,

        /// Data describing a resource attribute type, name, and value(s). This
        /// data MUST be encoded in CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1 format
        /// as described in section 2.4.10.1
        #[br(count=*header.ace_size() as usize - sid.len())]
        application_data: Vec<u8>,
    },

    /// The SYSTEM_SCOPED_POLICY_ID_ACE structure defines an ACE for the purpose
    /// of applying a central access policy to the resource.
    #[brw(assert(*header.ace_type() == AceType::SYSTEM_SCOPED_POLICY_ID_ACE_TYPE))]
    SYSTEM_SCOPED_POLICY_ID_ACE {
        ///  A SID that identifies a central access policy. For a
        ///  SYSTEM_SCOPED_POLICY_ID_ACE to be applicable on a resource, this
        ///  SID MUST match a CAPID of a CentralAccessPolicy contained in the
        ///  CentralAccessPoliciesList (as specified in [MS-GPCAP] section
        ///  3.2.1.1) of the machine on which the access evaluation will be
        ///  performed.
        #[brw(assert(sid.len() % 4 == 0))]
        sid: Sid,
    },
}

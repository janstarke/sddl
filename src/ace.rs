use binrw::binrw;
use getset::Getters;

use crate::{AceHeader, AceType, Guid, Sid};

/// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/628ebb1d-c509-4ea0-a10f-77ef97ca4586
#[binrw]
#[derive(Eq, PartialEq, Getters)]
#[getset(get = "pub")]
pub struct Ace {
    header: AceHeader,

    #[brw(args(*header.ace_type()))]
    data: AceData,
}

#[binrw]
#[brw(import(ace_type: AceType))]
#[derive(Eq, PartialEq)]
#[allow(non_camel_case_types)]
pub enum AceData {
    /// The ACCESS_ALLOWED_ACE structure defines an ACE for the discretionary
    /// access control list (DACL) that controls access to an object. An
    /// access-allowed ACE allows access to an object for a specific trustee
    /// identified by a security identifier (SID).
    #[brw(assert(ace_type == AceType::ACCESS_ALLOWED_ACE_TYPE))]
    ACCESS_ALLOWED_ACE {
        /// The SID of a trustee.
        sid: Sid,
    },

    /// The ACCESS_ALLOWED_OBJECT_ACE structure defines an ACE that controls
    /// allowed access to an object, a property set, or property. The ACE
    /// contains a set of access rights, a GUID that identifies the type of
    /// object, and a SID that identifies the trustee to whom the system will
    /// grant access. The ACE also contains a GUID and a set of flags that
    /// control inheritance of the ACE by child objects.
    #[brw(assert(ace_type == AceType::ACCESS_ALLOWED_OBJECT_ACE_TYPE))]
    ACCESS_ALLOWED_OBJECT_ACE {
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
        sid: Sid,
    },

    /// The ACCESS_DENIED_ACE structure defines an ACE for the DACL that
    /// controls access to an object. An access-denied ACE denies access to an
    /// object for a specific trustee identified by a SID.
    #[brw(assert(ace_type == AceType::ACCESS_DENIED_ACE_TYPE))]
    ACCESS_DENIED_ACE {
        /// The SID of a trustee.
        sid: Sid,
    },

    /// The ACCESS_DENIED_OBJECT_ACE structure defines an ACE that controls
    /// denied access to an object, a property set, or a property. The ACE
    /// contains a set of access rights, a GUID that identifies the type of
    /// object, and a SID that identifies the trustee to whom the system will
    /// deny access. The ACE also contains a GUID and a set of flags that
    /// control inheritance of the ACE by child objects.
    #[brw(assert(ace_type == AceType::ACCESS_DENIED_OBJECT_ACE_TYPE))]
    ACCESS_DENIED_OBJECT_ACE {
        object_type: Guid,
        inherited_object_type: Guid,
        sid: Sid,
    }
}

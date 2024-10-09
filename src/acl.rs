use std::fmt::Display;

use binrw::binrw;
use getset::Getters;

use crate::Ace;
use crate::sddl_h::*;

/// The ACL structure is the header of an access control list (ACL). A complete
/// ACL consists of an ACL structure followed by an ordered list of zero or more
/// access control entries (ACEs).
/// 
/// <https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-acl>
#[binrw]
#[derive(Eq, PartialEq, Getters)]
#[getset(get="pub")]
#[brw(little)]
pub struct Acl {

    /// Specifies the revision level of the ACL. This value should be
    /// ACL_REVISION, unless the ACL contains an object-specific ACE, in which
    /// case this value must be ACL_REVISION_DS. All ACEs in an ACL must be at
    /// the same revision level.
    acl_revision: AclRevision,

    /// Specifies a zero byte of padding that aligns the AclRevision member on a
    /// 16-bit boundary.
    #[br(temp)]
    #[bw(calc(0))]
    #[getset(skip)]
    _sbz1: u8,

    /// Specifies the size, in bytes, of the ACL. This value includes the ACL
    /// structure, all the ACEs, and the potential unused memory.
    acl_size: u16,

    /// Specifies the number of ACEs stored in the ACL.
    ace_count: u16,

    /// Specifies two zero-bytes of padding that align the ACL structure on a
    /// 32-bit boundary.
    #[br(temp)]
    #[bw(calc(0))]
    #[getset(skip)]
    _sbz2: u16,

    #[br(count=ace_count)]
    ace_list: Vec<Ace>,
}

impl Display for Acl {
    /// <https://learn.microsoft.com/de-de/windows/win32/secauthz/security-descriptor-string-format>
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for ace in self.ace_list() {
            write!(f, "{SDDL_ACE_BEGIN}{ace}{SDDL_ACE_END}")?;
        }
        Ok(())
    }
}

#[binrw]
#[derive(Eq, PartialEq, Clone, Copy, Default)]
#[allow(non_camel_case_types)]
#[brw(repr=u8)]
pub enum AclRevision {
    /// When set to 0x02, only AceTypes 0x00, 0x01, 0x02, 0x03, 0x11, 0x12, and
    /// 0x13 can be present in the ACL. An AceType of 0x11 is used for SACLs but
    /// not for DACLs. For more information about ACE types, see section
    /// 2.4.4.1.
    #[default]
    ACL_REVISION = 0x02,

    /// When set to 0x04, AceTypes 0x05, 0x06, 0x07, 0x08, and 0x11 are allowed.
    /// ACLs of revision 0x04 are applicable only to directory service objects.
    /// An AceType of 0x11 is used for SACLs but not for DACLs.
    ACL_REVISION_DS = 0x04,
}
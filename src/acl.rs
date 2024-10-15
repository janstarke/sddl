use std::fmt::Display;

use crate::raw_size::RawSize;
use crate::sddl_h::*;
use crate::Ace;
use crate::ControlFlags;
use binrw::binrw;
use derivative::Derivative;
use getset::Getters;

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
pub enum AclType {
    SACL,
    DACL,
}

impl AclType {
    pub fn sddl_string(&self) -> &'static str {
        match self {
            AclType::SACL => "S",
            AclType::DACL => "D",
        }
    }
}

pub const ACL_HEADER_SIZE: u16 = 1 + 1 + 2 + 2 + 2;

/// The ACL structure is the header of an access control list (ACL). A complete
/// ACL consists of an ACL structure followed by an ordered list of zero or more
/// access control entries (ACEs).
///
/// <https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-acl>
#[binrw]
#[derive(Derivative, Getters, Debug)]
#[derivative(Eq, PartialEq)]
#[getset(get = "pub")]
#[brw(little,import(control_flags: ControlFlags, acl_type: AclType))]
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

    #[br(calc=acl_type)]
    #[bw(ignore)]
    acl_type: AclType,

    #[br(calc=control_flags)]
    #[bw(ignore)]

    // this flag field might contain information about the whole security
    // descriptor, which might differ from the SD where the other
    // ACL came from. So, ACLs which are equal can be part of SDs with
    // different control flags. This is the reason we ignore this pseudo-field
    // here
    #[derivative(PartialEq="ignore")]
    control_flags: ControlFlags,
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
#[derive(Eq, PartialEq, Clone, Copy, Default, Debug)]
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

impl Acl {
    pub fn new(
        acl_revision: AclRevision,
        acl_type: AclType,
        control_flags: ControlFlags,
        ace_list: Vec<Ace>,
    ) -> Self {
        let acl_size = ACL_HEADER_SIZE + ace_list.iter().map(|ace| ace.raw_size()).sum::<u16>();
        let ace_count = ace_list.len().try_into().unwrap();
        Self {
            acl_revision,
            acl_size,
            ace_count,
            ace_list,
            acl_type,
            control_flags,
        }
    }

    /// parses an SDDL string
    /// 
    /// # Example
    /// ```rust
    /// use sddl::{Acl, AclType};
    /// let acl = Acl::from_sddl("D:P(A;CIOI;GRGX;;;BU)(A;CIOI;GA;;;BA)(A;CIOI;GA;;;SY)(A;CIOI;GA;;;CO)", None).unwrap();
    /// 
    /// assert_eq!(*acl.acl_type(), AclType::DACL);
    /// assert_eq!(*acl.ace_count(), 4);
    /// ```
    pub fn from_sddl(value: &str, domain_rid: Option<&[u32]>) -> Result<Self, crate::Error> {
        Ok(crate::parser::AclParser::new().parse(domain_rid, value)?)
    }

    pub fn sddl_string(&self) -> String {
        let ace_list = self
            .ace_list()
            .iter()
            .map(|ace: &Ace| format!("{SDDL_ACE_BEGIN}{ace}{SDDL_ACE_END}"))
            .fold(String::new(), |a, b| a + &b);

        let acl_type = self.acl_type().sddl_string();
        let flags = self.control_flags().sddl_string(*self.acl_type());
        format!("{acl_type}{SDDL_DELIMINATOR}{flags}{ace_list}")
    }
}

/*
#[cfg(test)]
mod tests {
    use super::Acl;

    #[test]
    fn test_minimal_sacl() {
        let _acl = Acl::try_from("S:(;;;)").unwrap();
    }
}
     */

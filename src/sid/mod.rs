use std::fmt::{Debug, Display};
use std::mem;

use binrw::binrw;
use getset::Getters;

mod identifier_authority;

pub use identifier_authority::*;

use crate::sddl_h::*;

#[allow(unused)]
enum SidNameUse {
    User = 1,
    Group = 2,
    Domain = 3,
    Alias = 4,
    WellKnownGroup = 5,
    DeletedAccount = 6,
    Invalid = 7,
    Unknown = 8,
    Computer = 9,
}

pub const MAX_SUB_AUTHORITIES: u8 = 15;

/// <https://github.com/microsoft/referencesource/blob/master/mscorlib/system/security/principal/sid.cs>
///
/// <https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-sid>
///
/// <https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-components>
#[binrw]
#[derive(Eq, PartialEq, Getters)]
#[getset(get = "pub")]
pub struct Sid {
    revision: u8,

    #[br(dbg, assert(sub_authority_count <= MAX_SUB_AUTHORITIES))]
    #[bw(assert(*sub_authority_count <= MAX_SUB_AUTHORITIES))]
    sub_authority_count: u8,

    identifier_authority: IdentifierAuthority,

    #[br(count=sub_authority_count)]
    #[brw(big)]
    sub_authority: Vec<u32>,

    #[bw(ignore)]
    #[br(calc=Self::sddl_alias(&identifier_authority, &sub_authority))]
    alias: Option<&'static str>,
}

impl Display for Sid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let revision = self.revision();
        let identifier_authority = self.identifier_authority();
        let sub_authorities = self
            .sub_authority()
            .iter()
            .map(|u| u.to_string())
            .collect::<Vec<_>>()
            .join("-");
        write!(f, "S-{revision}-{identifier_authority}-{sub_authorities}")
    }
}

impl Sid {
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        mem::size_of::<u8>()
            + mem::size_of::<u8>()
            + mem::size_of::<IdentifierAuthority>()
            + (self.sub_authority().len() * mem::size_of::<u32>())
    }

    pub fn sddl_alias(
        identifier_authority: &IdentifierAuthority,
        sub_authority: &[u32],
    ) -> Option<&'static str> {
        const APPLICATION_PACKAGE_AUTHORITY: IdentifierAuthority = IdentifierAuthority::from(15);
        const MANDATORY_LABEL_AUTHORITY: IdentifierAuthority = IdentifierAuthority::from(16);
        const AUTHENTICATION_AUTHORITY: IdentifierAuthority = IdentifierAuthority::from(18);
        match *identifier_authority {
            SECURITY_WORLD_SID_AUTHORITY if sub_authority == [0] => Some(SDDL_EVERYONE),

            // S-1-3-*
            SECURITY_CREATOR_SID_AUTHORITY => match sub_authority {
                [0] => Some(SDDL_CREATOR_OWNER),
                [1] => Some(SDDL_CREATOR_GROUP),
                [4] => Some(SDDL_OWNER_RIGHTS),
                _ => None,
            },

            // S-1-5-*
            SECURITY_NT_AUTHORITY => match sub_authority {
                [7] => Some(SDDL_ANONYMOUS),
                [11] => Some(SDDL_AUTHENTICATED_USERS),
                [9] => Some(SDDL_ENTERPRISE_DOMAIN_CONTROLLERS),
                [4] => Some(SDDL_INTERACTIVE),
                [19] => Some(SDDL_LOCAL_SERVICE),
                [20] => Some(SDDL_NETWORK_SERVICE),
                [2] => Some(SDDL_NETWORK),
                [10] => Some(SDDL_PERSONAL_SELF),
                [12] => Some(SDDL_RESTRICTED_CODE),
                [6] => Some(SDDL_SERVICE),
                [18] => Some(SDDL_LOCAL_SYSTEM),
                [33] => Some(SDDL_WRITE_RESTRICTED_CODE),
                [84, 0, 0, 0, 0, 0] => Some(SDDL_USER_MODE_DRIVERS),
                _ => {
                    // map S-1-5-21-* to sddl_domain_alias()
                    // map S-1-5-32-* to sddl_builtin_alias()
                    sub_authority.first().and_then(|s0| match s0 {
                        21 => Self::sddl_domain_alias(sub_authority),
                        32 => Self::sddl_builtin_alias(sub_authority),
                        _ => None,
                    })
                }
            },

            // S-1-15-*
            APPLICATION_PACKAGE_AUTHORITY if sub_authority == [2, 1] => Some(SDDL_ALL_APP_PACKAGES),

            MANDATORY_LABEL_AUTHORITY => match sub_authority {
                [12288] => Some(SDDL_ML_HIGH),
                [4096] => Some(SDDL_ML_LOW),
                [8192] => Some(SDDL_ML_MEDIUM),
                [8448] => Some(SDDL_ML_MEDIUM_PLUS),
                [16384] => Some(SDDL_ML_SYSTEM),
                _ => None,
            },

            // S-1-18-*
            AUTHENTICATION_AUTHORITY => match sub_authority {
                [1] => Some(SDDL_AUTHORITY_ASSERTED),
                [2] => Some(SDDL_SERVICE_ASSERTED),
                _ => None,
            },
            _ => None,
        }
    }

    fn sddl_domain_alias(sub_authority: &[u32]) -> Option<&'static str> {
        assert_eq!(*sub_authority.first().unwrap(), 21);
        if let Some(last) = sub_authority.last() {
            match last {
                525 => Some(SDDL_PROTECTED_USERS),
                517 => Some(SDDL_CERT_SERV_ADMINISTRATORS),
                522 => Some(SDDL_CLONEABLE_CONTROLLERS),
                512 => Some(SDDL_DOMAIN_ADMINISTRATORS),
                515 => Some(SDDL_DOMAIN_COMPUTERS),
                516 => Some(SDDL_DOMAIN_DOMAIN_CONTROLLERS),
                514 => Some(SDDL_DOMAIN_GUESTS),
                513 => Some(SDDL_DOMAIN_USERS),
                519 => Some(SDDL_ENTERPRISE_ADMINS),
                527 => Some(SDDL_ENTERPRISE_KEY_ADMINS),
                526 => Some(SDDL_KEY_ADMINS),
                500 => Some(SDDL_LOCAL_ADMIN),
                501 => Some(SDDL_LOCAL_GUEST),
                520 => Some(SDDL_GROUP_POLICY_ADMINS),
                498 => Some(SDDL_ENTERPRISE_RO_DCs),
                553 => Some(SDDL_RAS_SERVERS),
                518 => Some(SDDL_SCHEMA_ADMINISTRATORS),
                _ => None,
            }
        } else {
            None
        }
    }

    fn sddl_builtin_alias(sub_authority: &[u32]) -> Option<&'static str> {
        assert_eq!(sub_authority.len(), 2);
        assert_eq!(*sub_authority.first().unwrap(), 32);

        if let Some(last) = sub_authority.last() {
            match last {
                579 => Some(SDDL_ACCESS_CONTROL_ASSISTANCE_OPS),
                548 => Some(SDDL_ACCOUNT_OPERATORS),
                544 => Some(SDDL_BUILTIN_ADMINISTRATORS),
                546 => Some(SDDL_BUILTIN_GUESTS),
                551 => Some(SDDL_BUILTIN_GUESTS),
                545 => Some(SDDL_BUILTIN_USERS),
                574 => Some(SDDL_CERTSVC_DCOM_ACCESS),
                569 => Some(SDDL_CRYPTO_OPERATORS),
                573 => Some(SDDL_EVENT_LOG_READERS),
                576 => Some(SDDL_RDS_ENDPOINT_SERVERS),
                578 => Some(SDDL_HYPER_V_ADMINS),
                568 => Some(SDDL_IIS_USERS),
                559 => Some(SDDL_PERFMON_USERS),
                577 => Some(SDDL_RDS_MANAGEMENT_SERVERS),
                558 => Some(SDDL_PERFMON_USERS),
                556 => Some(SDDL_NETWORK_CONFIGURATION_OPS),
                550 => Some(SDDL_PRINTER_OPERATORS),
                547 => Some(SDDL_POWER_USERS),
                575 => Some(SDDL_RDS_REMOTE_ACCESS_SERVERS),
                555 => Some(SDDL_REMOTE_DESKTOP),
                552 => Some(SDDL_REPLICATOR),
                580 => Some(SDDL_REMOTE_MANAGEMENT_USERS),
                554 => Some(SDDL_ALIAS_PREW2KCOMPACC),
                549 => Some(SDDL_SERVER_OPERATORS),
                _ => None,
            }
        } else {
            None
        }
    }
}

impl Debug for Sid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self}")
    }
}

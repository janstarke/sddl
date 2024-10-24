use std::fmt::{Debug, Display};
use std::mem;
use std::str::FromStr;

use binrw::binrw;
use getset::Getters;

mod identifier_authority;

pub use identifier_authority::constants::*;
pub use identifier_authority::*;
use lazy_regex::regex_captures;
use serde::Serialize;

use crate::{sddl_h::*, RawSize};

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
#[derive(Eq, PartialEq, Getters, Clone)]
#[getset(get = "pub")]
pub struct Sid {
    #[br(assert(revision == 1))]
    #[bw(assert(*revision == 1))]
    revision: u8,

    #[br(assert(sub_authority_count <= MAX_SUB_AUTHORITIES))]
    #[bw(assert(*sub_authority_count <= MAX_SUB_AUTHORITIES))]
    sub_authority_count: u8,

    identifier_authority: IdentifierAuthority,

    #[br(count=sub_authority_count)]
    #[brw(little)]
    sub_authority: Vec<u32>,

    #[bw(ignore)]
    #[br(calc=Self::sddl_alias(&identifier_authority, &sub_authority))]
    alias: Option<&'static str>,
}

impl Display for Sid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let revision = self.revision();
        let identifier_authority = self.identifier_authority();

        let mut sub_authorities = Vec::new();
        let mut iter = self.sub_authority().iter();
        sub_authorities.push(iter.next().unwrap().to_string());

        // the first and last sub authority will have no leading 0s
        if let Some(mut current) = iter.next() {
            for next in iter {
                sub_authorities.push(format!("{current:09}"));
                current = next;
            }
            sub_authorities.push(current.to_string());
        }
        let sub_authorities = sub_authorities.join("-");

        write!(f, "S-{revision}-{identifier_authority}-{sub_authorities}")
    }
}

impl Serialize for Sid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        serializer.serialize_str(&self.to_string())
    }
}

impl RawSize for Sid {
    fn raw_size(&self) -> u16 {
        self.len().try_into().unwrap()
    }
}

impl Sid {
    pub fn new(identifier_authority: IdentifierAuthority, sub_authority: &[u32]) -> Self {
        let alias = Self::sddl_alias(&identifier_authority, sub_authority);
        Self {
            revision: 1,
            sub_authority_count: sub_authority.len() as u8,
            identifier_authority,
            sub_authority: sub_authority.to_vec(),
            alias,
        }
    }

    pub fn new_with_domain(rid: u32, domain: &[u32]) -> Self {
        let mut d = vec![21];
        d.extend_from_slice(domain);
        d.push(rid);
        Self::new(crate::constants::SECURITY_NT_AUTHORITY, &d[..])
    }

    pub fn new_builtin(rid: u32) -> Self {
        Self::new(crate::constants::SECURITY_NT_AUTHORITY, &[32, rid])
    }

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
                551 => Some(SDDL_BACKUP_OPERATORS),
                545 => Some(SDDL_BUILTIN_USERS),
                574 => Some(SDDL_CERTSVC_DCOM_ACCESS),
                569 => Some(SDDL_CRYPTO_OPERATORS),
                573 => Some(SDDL_EVENT_LOG_READERS),
                576 => Some(SDDL_RDS_ENDPOINT_SERVERS),
                578 => Some(SDDL_HYPER_V_ADMINS),
                568 => Some(SDDL_IIS_USERS),
                559 => Some(SDDL_PERFLOG_USERS),
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

impl TryFrom<&str> for Sid {
    type Error = crate::Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if let Some((_, revision, authority, sub_authorities)) =
            regex_captures!(r#"^S-(1)-(\d+)((?:-\d+)*)$"#, value)
        {
            let revision = u8::from_str(revision).map_err(|_| {
                Self::Error::IllegalSidFormat(value.into(), "illegal revision number")
            })?;

            let authority: [u8; 8] = u64::from_str(authority)
                .map_err(|_| {
                    Self::Error::IllegalSidFormat(value.into(), "invalid authority format")
                })?
                .to_be_bytes();
            let identifier_authority = [
                authority[2],
                authority[3],
                authority[4],
                authority[5],
                authority[6],
                authority[7],
            ]
            .into();

            // we need place for at least the leading dash and one subauthority
            if sub_authorities.len() < 2 {
                return Err(Self::Error::IllegalSidFormat(
                    value.into(),
                    "too less sub authorities",
                ));
            }

            debug_assert_eq!(sub_authorities.chars().next().unwrap(), '-');
            let mut sub_authority = Vec::new();
            for part in sub_authorities[1..].split('-').map(u32::from_str) {
                match part {
                    Ok(p) => sub_authority.push(p),
                    Err(_) => {
                        return Err(Self::Error::IllegalSidFormat(
                            value.into(),
                            "illegal sub authority format",
                        ));
                    }
                }
            }

            let sub_authority_count = u8::try_from(sub_authority.len()).map_err(|_| {
                Self::Error::IllegalSidFormat(value.into(), "illegal number of sub authorities")
            })?;
            let alias = Self::sddl_alias(&identifier_authority, &sub_authority);
            Ok(Self {
                revision,
                identifier_authority,
                sub_authority_count,
                sub_authority,
                alias,
            })
        } else {
            Err(Self::Error::IllegalSidFormat(
                value.into(),
                "SID does not match the expected pattern",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::Sid;
    use crate::parser::SidParser;

    #[test]
    fn test_null_sid() {
        let my_sid = "S-1-1-0";
        assert_eq!(my_sid, Sid::try_from(my_sid).unwrap().to_string());
    }

    #[test]
    fn test_iisusrs() {
        let my_sid = "S-1-5-32-568";
        assert_eq!(my_sid, Sid::try_from(my_sid).unwrap().to_string());
    }

    #[test]
    fn test_domain_sid() {
        let my_sid = "S-1-5-21-2623811015-3361044348-030300820-1013";
        assert_eq!(my_sid, Sid::try_from(my_sid).unwrap().to_string());
    }

    #[test]
    fn test_all_aliases() {
        let aliases = ["AA", "AC", "AN", "AO", "AP", "AS", "AU",
            "BA","BG","BO","BU","CA","CD","CG","CN","CO","CY","DA","DC","DD",
            "DG","DU","EA","ED","EK","ER","ES","HA","HI","IS","IU","KA","LA",
            "LG","LS","LU","LW","ME","MP","MS","MU","NO","NS","NU","OW","PA",
            "PO","PS","PU","RA","RC","RD","RE","RM","RO","RS","RU","SA","SI",
            "SO","SS","SU","SY","UD","WD","WR"];
        let domain=[2623811015, 3361044348, 30300820];
        let parser = SidParser::new();
        for alias in aliases {
            let sid = parser.parse(Some(&domain), alias).unwrap();
            assert_eq!(sid.alias().unwrap_or_else(|| panic!("missing alias for '{alias}'")), alias);
        }
    }
}

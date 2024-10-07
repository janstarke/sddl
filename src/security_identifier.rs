use std::fmt::Display;

use binrw::binrw;
use getset::Getters;

use crate::SidIdentifierAuthority;

#[allow(clippy::enum_variant_names, unused)]
enum IdentifierAuthority {
    NullAuthority = 0,
    WorldAuthority = 1,
    LocalAuthority = 2,
    CreatorAuthority = 3,
    NonUniqueAuthority = 4,
    NTAuthority = 5,
    SiteServerAuthority = 6,
    InternetSiteAuthority = 7,
    ExchangeAuthority = 8,
    ResourceManagerAuthority = 9,
}

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

/// <https://github.com/microsoft/referencesource/blob/master/mscorlib/system/security/principal/sid.cs#L61>
#[allow(unused)]
pub enum WellKnownSidType {
    NullSid = 0,
    WorldSid = 1,
    LocalSid = 2,
    CreatorOwnerSid = 3,
    CreatorGroupSid = 4,
    CreatorOwnerServerSid = 5,
    CreatorGroupServerSid = 6,
    NTAuthoritySid = 7,
    DialupSid = 8,
    NetworkSid = 9,
    BatchSid = 10,
    InteractiveSid = 11,
    ServiceSid = 12,
    AnonymousSid = 13,
    ProxySid = 14,
    EnterpriseControllersSid = 15,
    SelfSid = 16,
    AuthenticatedUserSid = 17,
    RestrictedCodeSid = 18,
    TerminalServerSid = 19,
    RemoteLogonIdSid = 20,
    LogonIdsSid = 21,
    LocalSystemSid = 22,
    LocalServiceSid = 23,
    NetworkServiceSid = 24,
    BuiltinDomainSid = 25,
    BuiltinAdministratorsSid = 26,
    BuiltinUsersSid = 27,
    BuiltinGuestsSid = 28,
    BuiltinPowerUsersSid = 29,
    BuiltinAccountOperatorsSid = 30,
    BuiltinSystemOperatorsSid = 31,
    BuiltinPrintOperatorsSid = 32,
    BuiltinBackupOperatorsSid = 33,
    BuiltinReplicatorSid = 34,
    BuiltinPreWindows2000CompatibleAccessSid = 35,
    BuiltinRemoteDesktopUsersSid = 36,
    BuiltinNetworkConfigurationOperatorsSid = 37,
    AccountAdministratorSid = 38,
    AccountGuestSid = 39,
    AccountKrbtgtSid = 40,
    AccountDomainAdminsSid = 41,
    AccountDomainUsersSid = 42,
    AccountDomainGuestsSid = 43,
    AccountComputersSid = 44,
    AccountControllersSid = 45,
    AccountCertAdminsSid = 46,
    AccountSchemaAdminsSid = 47,
    AccountEnterpriseAdminsSid = 48,
    AccountPolicyAdminsSid = 49,
    AccountRasAndIasServersSid = 50,
    NtlmAuthenticationSid = 51,
    DigestAuthenticationSid = 52,
    SChannelAuthenticationSid = 53,
    ThisOrganizationSid = 54,
    OtherOrganizationSid = 55,
    BuiltinIncomingForestTrustBuildersSid = 56,
    BuiltinPerformanceMonitoringUsersSid = 57,
    BuiltinPerformanceLoggingUsersSid = 58,
    BuiltinAuthorizationAccessSid = 59,
    WinBuiltinTerminalServerLicenseServersSid = 60,
}

pub const MAX_SUB_AUTHORITIES: u8 = 15;

/// <https://github.com/microsoft/referencesource/blob/master/mscorlib/system/security/principal/sid.cs>
/// 
/// <https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-sid>
/// 
/// <https://learn.microsoft.com/en-us/windows/win32/secauthz/sid-components>
#[binrw]
#[derive(Eq, PartialEq, Getters)]
#[getset(get="pub")]
pub struct Sid {
    revision: u8,
    
    #[br(assert(sub_authority_count <= MAX_SUB_AUTHORITIES))]
    #[bw(assert(*sub_authority_count <= MAX_SUB_AUTHORITIES))]
    sub_authority_count: u8,
    identifier_authority: SidIdentifierAuthority,

    #[br(count=sub_authority_count)]
    #[brw(big)]
    sub_authority: Vec<u32>,
}

impl Display for Sid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let revision = self.revision();
        let identifier_authority = self.identifier_authority();
        let sub_authorities = self.sub_authority().iter().map(|u| u.to_string()).collect::<Vec<_>>().join("-");
        write!(f, "S-{revision}-{identifier_authority}-{sub_authorities}")
    }
}
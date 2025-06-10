use serde::Serialize;
use strum::{EnumMessage, IntoStaticStr};
use strum_macros::EnumString;

#[derive(Clone, Copy, Debug, Eq, PartialEq, EnumString, EnumMessage, IntoStaticStr, Hash)]
#[strum(use_phf, serialize_all = "SCREAMING_SNAKE_CASE")]
pub enum SidAlias {
    #[strum(message=r"BUILTIN\Access Control Assistence Operators")]
    AA,

    #[strum(message=r"APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES")]
    AC,

    #[strum(message=r"NT AUTHORITY\ANONYMOUS LOGON")]
    AN,

    #[strum(message=r"BUILTIN\Account Operators")]
    AO,

    #[strum(message=r"<DOMAIN>\Protected Users")]
    AP,

    #[strum(message=r"Authentication authority asserted identity")]
    AS,

    #[strum(message=r"NT AUTHORITY\Authenticated Users")]
    AU,

    #[strum(message=r"BUILTIN\Administrators")]
    BA,

    #[strum(message=r"UILTIN\Guest")]
    BG,

    #[strum(message=r"BUILTIN\Backup Operators")]
    BO,

    #[strum(message=r"BUILTIN\Users")]
    BU,

    #[strum(message=r"<DOMAIN>\Cert Publishers")]
    CA,

    #[strum(message=r"BUILTIN\Certificate Service DCOM Access")]
    CD,

    #[strum(message=r"CREATOR GROUP")]
    CG,

    #[strum(message=r"<DOMAIN>\Cloneable Domain Controllers")]
    CN,

    #[strum(message=r"CREATOR OWNER")]
    CO,

    #[strum(message=r"BUILTIN\Cryptographic Operators")]
    CY,

    #[strum(message=r"<DOMAIN>\Domain Admins")]
    DA,

    #[strum(message=r"<DOMAIN>\Domain Computers")]
    DC,

    #[strum(message=r"<DOMAIN>\Domain Controllers")]
    DD,

    #[strum(message=r"<DOMAIN>\Domain Guests")]
    DG,

    #[strum(message=r"<DOMAIN>\Domain Users")]
    DU,

    #[strum(message=r"<DOMAIN>\Enterprise Admins")]
    EA,

    #[strum(message=r"NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS")]
    ED,

    #[strum(message=r"<DOMAIN>\Enterprise Key Admins")]
    EK,

    #[strum(message=r"BUILTIN\Event Log Readers")]
    ER,

    #[strum(message=r"BUILTIN\RDS Endpoint Servers")]
    ES,

    #[strum(message=r"BUILTIN\Hyper-V Administrators")]
    HA,

    #[strum(message=r"Mandatory Label\High Mandatory Level")]
    HI,

    #[strum(message=r"<DOMAIN>\Hardware Operators")]
    HO,

    #[strum(message=r"BUILTIN\IIS_IUSRS")]
    IS,

    #[strum(message=r"NT AUTHORITY\INTERACTIVE")]
    IU,

    #[strum(message=r"<DOMAIN>\Key Admins")]
    KA,

    #[strum(message=r"<DOMAIN>\Administrator")]
    LA,

    #[strum(message=r"<DOMAIN>\Guests")]
    LG,

    #[strum(message=r"NT AUTHORITY\LOCAL SERVICE")]
    LS,

    #[strum(message=r"BUILTIN\Performance Log Users")]
    LU,

    #[strum(message=r"Mandatory Label\Low Mandatory Level")]
    LW,

    #[strum(message=r"Mandatory Label\Medium Mandatory Level")]
    ME,

    #[strum(message=r"Mandatory Label\Medium Plus Mandatory Level")]
    MP,

    #[strum(message=r"BUILTIN\RDS Management Servers")]
    MS,

    #[strum(message=r"BUILTIN\Performance Monitor Users")]
    MU,

    #[strum(message=r"BUILTIN\Network Configuration Operators")]
    NO,

    #[strum(message=r"NT AUTHORITY\NETWORK SERVICE")]
    NS,

    #[strum(message=r"NT AUTHORITY\NETWORK")]
    NU,

    #[strum(message=r"OWNER RIGHTS")]
    OW,

    #[strum(message=r"<DOMAIN>\Group Policy Creator Owners")]
    PA,

    #[strum(message=r"BUILTIN\Print Operators")]
    PO,

    #[strum(message=r"NT AUTHORITY\SELF")]
    PS,

    #[strum(message=r"BUILTIN\Power Users")]
    PU,

    #[strum(message=r"BUILTIN\RDS Remote Access Servers")]
    RA,

    #[strum(message=r"NT AUTHORITY\RESTRICTED")]
    RC,

    #[strum(message=r"BUILTIN\Remote Desktop Users")]
    RD,

    #[strum(message=r"BUILTIN\Replicator")]
    RE,

    #[strum(message=r"BUILTIN\Remote Management Users")]
    RM,

    #[strum(message=r"<DOMAIN>\Enterprise Read-only Domain Controllers")]
    RO,

    #[strum(message=r"<DOMAIN>\RAS and IAS Servers")]
    RS,

    #[strum(message=r"BUILTIN\Pre-Windows 2000 Compatible Access")]
    RU,

    #[strum(message=r"<DOMAIN>\Schema Admins")]
    SA,

    #[strum(message=r"<DOMAIN>\OpenSSH Users")]
    SH,

    #[strum(message=r"Mandatory Label\System Mandatory Level")]
    SI,

    #[strum(message=r"BUILTIN\Server Operators")]
    SO,

    #[strum(message=r"Service asserted identity")]
    SS,

    #[strum(message=r"NT AUTHORITY\SERVICE")]
    SU,

    #[strum(message=r"NT AUTHORITY\SYSTEM")]
    SY,

    #[strum(message=r"NT AUTHORITY\USER MODE DRIVERS")]
    UD,

    #[strum(message=r"Everyone")]
    WD,

    #[strum(message=r"NT AUTHORITY\WRITE RESTRICTED")]
    WR,
}

impl SidAlias {
    pub fn long_name(&self) -> &'static str {
        self.get_message().unwrap()
    }

    pub fn short_name(&self) -> &'static str {
        let s: &'static str = self.into();
        s
    }
}

impl Serialize for SidAlias {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer {
        serializer.serialize_str(self.short_name())
    }
}

#![allow(unused)]
/// Owner tag
pub const SDDL_OWNER: &str = "O";
/// Group tag
pub const SDDL_GROUP: &str = "G";
/// DACL tag
pub const SDDL_DACL: &str = "D";
/// SACL tag
pub const SDDL_SACL: &str = "S";
/// DACL or SACL Protected
pub const SDDL_PROTECTED: &str = "P";
/// Auto inherit request
pub const SDDL_AUTO_INHERIT_REQ: &str = "AR";
/// DACL/SACL are auto inherited
pub const SDDL_AUTO_INHERITED: &str = "AI";
/// Null ACL
pub const SDDL_NULL_ACL: &str = "NO_ACCESS_CONTROL";
/// Access allowed
pub const SDDL_ACCESS_ALLOWED: &str = "A";
/// Access denied
pub const SDDL_ACCESS_DENIED: &str = "D";
/// Object access allowed
pub const SDDL_OBJECT_ACCESS_ALLOWED: &str = "OA";
/// Object access denied
pub const SDDL_OBJECT_ACCESS_DENIED: &str = "OD";
/// Audit
pub const SDDL_AUDIT: &str = "AU";
/// Alarm
pub const SDDL_ALARM: &str = "AL";
/// Object audit
pub const SDDL_OBJECT_AUDIT: &str = "OU";
/// Object alarm
pub const SDDL_OBJECT_ALARM: &str = "OL";
/// Integrity label
pub const SDDL_MANDATORY_LABEL: &str = "ML";
/// Process trust label
pub const SDDL_PROCESS_TRUST_LABEL: &str = "TL";
/// Callback access allowed
pub const SDDL_CALLBACK_ACCESS_ALLOWED: &str = "XA";
/// Callback access denied
pub const SDDL_CALLBACK_ACCESS_DENIED: &str = "XD";
/// Resource attribute
pub const SDDL_RESOURCE_ATTRIBUTE: &str = "RA";
/// Scoped policy
pub const SDDL_SCOPED_POLICY_ID: &str = "SP";
/// Callback audit
pub const SDDL_CALLBACK_AUDIT: &str = "XU";
/// Callback object access allowed
pub const SDDL_CALLBACK_OBJECT_ACCESS_ALLOWED: &str = "ZA";
/// Signed integer
pub const SDDL_INT: &str = "TI";
/// Unsigned integer
pub const SDDL_UINT: &str = "TU";
/// Wide string
pub const SDDL_WSTRING: &str = "TS";
/// SID
pub const SDDL_SID: &str = "TD";
/// Octet String
pub const SDDL_BLOB: &str = "TX";
/// Boolean
pub const SDDL_BOOLEAN: &str = "TB";
/// Container inherit
pub const SDDL_CONTAINER_INHERIT: &str = "CI";
/// Object inherit
pub const SDDL_OBJECT_INHERIT: &str = "OI";
/// Inherit no propagate
pub const SDDL_NO_PROPAGATE: &str = "NP";
/// Inherit only
pub const SDDL_INHERIT_ONLY: &str = "IO";
/// Inherited
pub const SDDL_INHERITED: &str = "ID";
/// Audit success
pub const SDDL_AUDIT_SUCCESS: &str = "SA";
/// Audit failure
pub const SDDL_AUDIT_FAILURE: &str = "FA";
pub const SDDL_READ_PROPERTY: &str = "RP";
pub const SDDL_WRITE_PROPERTY: &str = "WP";
pub const SDDL_CREATE_CHILD: &str = "CC";
pub const SDDL_DELETE_CHILD: &str = "DC";
pub const SDDL_LIST_CHILDREN: &str = "LC";
pub const SDDL_SELF_WRITE: &str = "SW";
pub const SDDL_LIST_OBJECT: &str = "LO";
pub const SDDL_DELETE_TREE: &str = "DT";
pub const SDDL_CONTROL_ACCESS: &str = "CR";
pub const SDDL_READ_CONTROL: &str = "RC";
pub const SDDL_WRITE_DAC: &str = "WD";
pub const SDDL_WRITE_OWNER: &str = "WO";
pub const SDDL_STANDARD_DELETE: &str = "SD";
pub const SDDL_GENERIC_ALL: &str = "GA";
pub const SDDL_GENERIC_READ: &str = "GR";
pub const SDDL_GENERIC_WRITE: &str = "GW";
pub const SDDL_GENERIC_EXECUTE: &str = "GX";
pub const SDDL_FILE_ALL: &str = "FA";
pub const SDDL_FILE_READ: &str = "FR";
pub const SDDL_FILE_WRITE: &str = "FW";
pub const SDDL_FILE_EXECUTE: &str = "FX";
pub const SDDL_KEY_ALL: &str = "KA";
pub const SDDL_KEY_READ: &str = "KR";
pub const SDDL_KEY_WRITE: &str = "KW";
pub const SDDL_KEY_EXECUTE: &str = "KX";
pub const SDDL_NO_WRITE_UP: &str = "NW";
pub const SDDL_NO_READ_UP: &str = "NR";
pub const SDDL_NO_EXECUTE_UP: &str = "NX";
/// Domain admins
pub const SDDL_DOMAIN_ADMINISTRATORS: &str = "DA";
/// Domain guests
pub const SDDL_DOMAIN_GUESTS: &str = "DG";
/// Domain users
pub const SDDL_DOMAIN_USERS: &str = "DU";
/// Enterprise domain controllers
pub const SDDL_ENTERPRISE_DOMAIN_CONTROLLERS: &str = "ED";
/// Domain domain controllers
pub const SDDL_DOMAIN_DOMAIN_CONTROLLERS: &str = "DD";
/// Domain computers
pub const SDDL_DOMAIN_COMPUTERS: &str = "DC";
/// Builtin (local ) administrators
pub const SDDL_BUILTIN_ADMINISTRATORS: &str = "BA";
/// Builtin (local ) guests
pub const SDDL_BUILTIN_GUESTS: &str = "BG";
/// Builtin (local ) users
pub const SDDL_BUILTIN_USERS: &str = "BU";
/// Local administrator account
pub const SDDL_LOCAL_ADMIN: &str = "LA";
/// Local group account
pub const SDDL_LOCAL_GUEST: &str = "LG";
/// Account operators
pub const SDDL_ACCOUNT_OPERATORS: &str = "AO";
/// Backup operators
pub const SDDL_BACKUP_OPERATORS: &str = "BO";
/// Printer operators
pub const SDDL_PRINTER_OPERATORS: &str = "PO";
/// Server operators
pub const SDDL_SERVER_OPERATORS: &str = "SO";
/// Authenticated users
pub const SDDL_AUTHENTICATED_USERS: &str = "AU";
/// Personal self
pub const SDDL_PERSONAL_SELF: &str = "PS";
/// Creator owner
pub const SDDL_CREATOR_OWNER: &str = "CO";
/// Creator group
pub const SDDL_CREATOR_GROUP: &str = "CG";
/// Local system
pub const SDDL_LOCAL_SYSTEM: &str = "SY";
/// Power users
pub const SDDL_POWER_USERS: &str = "PU";
/// Everyone ( World )
pub const SDDL_EVERYONE: &str = "WD";
/// Replicator
pub const SDDL_REPLICATOR: &str = "RE";
/// Interactive logon user
pub const SDDL_INTERACTIVE: &str = "IU";
/// Nework logon user
pub const SDDL_NETWORK: &str = "NU";
/// Service logon user
pub const SDDL_SERVICE: &str = "SU";
/// Restricted code
pub const SDDL_RESTRICTED_CODE: &str = "RC";
/// Write Restricted code
pub const SDDL_WRITE_RESTRICTED_CODE: &str = "WR";
/// Anonymous Logon
pub const SDDL_ANONYMOUS: &str = "AN";
/// Schema Administrators
pub const SDDL_SCHEMA_ADMINISTRATORS: &str = "SA";
/// Certificate Server Administrators
pub const SDDL_CERT_SERV_ADMINISTRATORS: &str = "CA";
/// RAS servers group
pub const SDDL_RAS_SERVERS: &str = "RS";
/// Enterprise administrators
pub const SDDL_ENTERPRISE_ADMINS: &str = "EA";
/// Group Policy administrators
pub const SDDL_GROUP_POLICY_ADMINS: &str = "PA";
/// alias to allow previous windows 2000
pub const SDDL_ALIAS_PREW2KCOMPACC: &str = "RU";
/// Local service account (for services)
pub const SDDL_LOCAL_SERVICE: &str = "LS";
/// Network service account (for services)
pub const SDDL_NETWORK_SERVICE: &str = "NS";
/// Remote desktop users (for terminal server)
pub const SDDL_REMOTE_DESKTOP: &str = "RD";
/// Network configuration operators ( to manage configuration of networking features)
pub const SDDL_NETWORK_CONFIGURATION_OPS: &str = "NO";
/// Performance Monitor Users
pub const SDDL_PERFMON_USERS: &str = "MU";
/// Performance Log Users
pub const SDDL_PERFLOG_USERS: &str = "LU";
/// Anonymous Internet Users
pub const SDDL_IIS_USERS: &str = "IS";
/// Crypto Operators
pub const SDDL_CRYPTO_OPERATORS: &str = "CY";
/// Owner Rights SID
pub const SDDL_OWNER_RIGHTS: &str = "OW";
/// Event log readers
pub const SDDL_EVENT_LOG_READERS: &str = "ER";
/// Users who can connect to certification authorities using DCOM
pub const SDDL_CERTSVC_DCOM_ACCESS: &str = "CD";
/// All applications running in an app package context
pub const SDDL_ALL_APP_PACKAGES: &str = "AC";
/// Servers in this group enable users of RemoteApp programs and personal virtual desktops access to these resources.
pub const SDDL_RDS_REMOTE_ACCESS_SERVERS: &str = "RA";
/// Servers in this group run virtual machines and host sessions where users RemoteApp programs and personal virtual desktops run.
pub const SDDL_RDS_ENDPOINT_SERVERS: &str = "ES";
/// Servers in this group can perform routine administrative actions on servers running Remote Desktop Services. 
pub const SDDL_RDS_MANAGEMENT_SERVERS: &str = "MS";
/// UserMode driver
pub const SDDL_USER_MODE_DRIVERS: &str = "UD";
/// Members of this group have complete and unrestricted access to all features of Hyper-V. 
pub const SDDL_HYPER_V_ADMINS: &str = "HA";
/// Members of this group that are domain controllers may be cloned. 
pub const SDDL_CLONEABLE_CONTROLLERS: &str = "CN";
/// Members of this group can remotely query authorization attributes and permissions for resources on this computer. 
pub const SDDL_ACCESS_CONTROL_ASSISTANCE_OPS: &str = "AA";
/// Members of this group can access WMI resources over management protocols (such as WS-Management via the Windows Remote Management service). This applies only to WMI namespaces that grant access to the user. 
pub const SDDL_REMOTE_MANAGEMENT_USERS: &str = "RM";
/// Authentication Authority Asserted
pub const SDDL_AUTHORITY_ASSERTED: &str = "AS";
/// Authentication Service Asserted
pub const SDDL_SERVICE_ASSERTED: &str = "SS";
/// Members of this group are afforded additional protections against authentication security threats.
pub const SDDL_PROTECTED_USERS: &str = "AP";
/// Members of this group have full control over all key credential objects in the domain
pub const SDDL_KEY_ADMINS: &str = "KA";
/// Members of this group have full control over all key credential objects in the forest
pub const SDDL_ENTERPRISE_KEY_ADMINS: &str = "EK";
/// Low mandatory level
pub const SDDL_ML_LOW: &str = "LW";
/// Medium mandatory level
pub const SDDL_ML_MEDIUM: &str = "ME";
/// Medium Plus mandatory level
pub const SDDL_ML_MEDIUM_PLUS: &str = "MP";
/// High mandatory level
pub const SDDL_ML_HIGH: &str = "HI";
/// System mandatory level
pub const SDDL_ML_SYSTEM: &str = "SI";
pub const SDDL_SEPERATORC: char = ';';
pub const SDDL_DELIMINATORC: char = ':';
pub const SDDL_ACE_BEGINC: char = '(';
pub const SDDL_ACE_ENDC: char = ')';
pub const SDDL_SPACEC: char = ' ';
pub const SDDL_ACE_COND_BEGINC: char = '(';
pub const SDDL_ACE_COND_ENDC: char = ')';
pub const SDDL_ACE_COND_STRING_BEGINC: char = '"';
pub const SDDL_ACE_COND_STRING_ENDC: char = '"';
pub const SDDL_ACE_COND_COMPOSITEVALUE_BEGINC: char = '{';
pub const SDDL_ACE_COND_COMPOSITEVALUE_ENDC: char = '}';
pub const SDDL_ACE_COND_COMPOSITEVALUE_SEPERATORC: char = ',';
pub const SDDL_ACE_COND_BLOB_PREFIXC: char = '#';
pub const SDDL_ACE_COND_SID_BEGINC: char = '(';
pub const SDDL_ACE_COND_SID_ENDC: char = ')';
pub const SDDL_SEPERATOR: &str = ";";
pub const SDDL_DELIMINATOR: &str = ":";
pub const SDDL_ACE_BEGIN: &str = "(";
pub const SDDL_ACE_END: &str = ")";
pub const SDDL_ACE_COND_BEGIN: &str = "(";
pub const SDDL_ACE_COND_END: &str = ")";
pub const SDDL_SPACE: &str = " ";
pub const SDDL_ACE_COND_BLOB_PREFIX: &str = "#";
pub const SDDL_ACE_COND_SID_PREFIX: &str = "SID";
pub const SDDL_ACE_COND_ATTRIBUTE_PREFIX: &str = "@";
pub const SDDL_ACE_COND_USER_ATTRIBUTE_PREFIX: &str = "@USER.";
pub const SDDL_ACE_COND_RESOURCE_ATTRIBUTE_PREFIX: &str = "@RESOURCE.";
pub const SDDL_ACE_COND_DEVICE_ATTRIBUTE_PREFIX: &str = "@DEVICE.";

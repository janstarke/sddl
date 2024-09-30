use bitflags::bitflags;

bitflags! {
    /// <https://github.com/microsoft/referencesource/blob/master/mscorlib/system/security/accesscontrol/securitydescriptor.cs>    
    pub struct ControlFlags: u16 {
        const None                                = 0x0000;
        const OwnerDefaulted                      = 0x0001; // set by RM only
        const GroupDefaulted                      = 0x0002; // set by RM only
        const DiscretionaryAclPresent             = 0x0004; // set by RM or user, 'off' means DACL is null
        const DiscretionaryAclDefaulted           = 0x0008; // set by RM only
        const SystemAclPresent                    = 0x0010; // same as DiscretionaryAclPresent
        const SystemAclDefaulted                  = 0x0020; // sams as DiscretionaryAclDefaulted
        const DiscretionaryAclUntrusted           = 0x0040; // ignore this one
        const ServerSecurity                      = 0x0080; // ignore this one
        const DiscretionaryAclAutoInheritRequired = 0x0100; // ignore this one
        const SystemAclAutoInheritRequired        = 0x0200; // ignore this one
        const DiscretionaryAclAutoInherited       = 0x0400; // set by RM only
        const SystemAclAutoInherited              = 0x0800; // set by RM only
        const DiscretionaryAclProtected           = 0x1000; // when set, RM will stop inheriting
        const SystemAclProtected                  = 0x2000; // when set, RM will stop inheriting
        const RMControlValid                      = 0x4000; // the reserved 8 bits have some meaning
        const SelfRelative                        = 0x8000; // must always be on
    }
}

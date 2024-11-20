use crate::{AccessMask, Ace, AceHeaderFlags, AceType, Guid, Sid};

pub(crate) struct ParsedAceContents {
    pub flags: AceHeaderFlags,
    pub mask: AccessMask,
    pub sid: Sid,
    pub object_type: Option<Guid>,
    pub inherited_object_type: Option<Guid>,
}

impl ParsedAceContents {
    pub(crate) fn into_ace(self, ace_type: AceType) -> Ace {
        let flags = self.flags;
        let mask = self.mask;
        let sid = self.sid;
        let object_type = self.object_type;
        let inherited_object_type = self.inherited_object_type;
        match ace_type {
            AceType::ACCESS_ALLOWED_ACE_TYPE => Ace::access_allowed(flags, mask, sid),
            AceType::ACCESS_DENIED_ACE_TYPE => Ace::access_denied(flags, mask, sid),
            AceType::SYSTEM_AUDIT_ACE_TYPE => Ace::system_audit(flags, mask, sid),
            AceType::SYSTEM_ALARM_ACE_TYPE => unimplemented!(),
            AceType::ACCESS_ALLOWED_COMPOUND_ACE_TYPE => unimplemented!(),
            AceType::ACCESS_ALLOWED_OBJECT_ACE_TYPE => {
                Ace::access_allowed_object(flags, mask, object_type, inherited_object_type, sid)
            }
            AceType::ACCESS_DENIED_OBJECT_ACE_TYPE => {
                Ace::access_denied_object(flags, mask, object_type, inherited_object_type, sid)
            }
            AceType::SYSTEM_AUDIT_OBJECT_ACE_TYPE => Ace::system_audit_object(
                flags,
                mask,
                object_type,
                inherited_object_type,
                sid,
                vec![],
            ),
            AceType::SYSTEM_ALARM_OBJECT_ACE_TYPE => unimplemented!(),
            AceType::ACCESS_ALLOWED_CALLBACK_ACE_TYPE => unimplemented!(),
            AceType::ACCESS_DENIED_CALLBACK_ACE_TYPE => unimplemented!(),
            AceType::ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE => unimplemented!(),
            AceType::ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE => unimplemented!(),
            AceType::SYSTEM_AUDIT_CALLBACK_ACE_TYPE => unimplemented!(),
            AceType::SYSTEM_ALARM_CALLBACK_ACE_TYPE => unimplemented!(),
            AceType::SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE => unimplemented!(),
            AceType::SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE => unimplemented!(),
            AceType::SYSTEM_MANDATORY_LABEL_ACE_TYPE => {
                Ace::system_mandatory_label(flags, mask, sid)
            }
            AceType::SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE => unimplemented!(),
            AceType::SYSTEM_SCOPED_POLICY_ID_ACE_TYPE => {
                Ace::system_scoped_policy_id(flags, mask, sid)
            }
        }
    }
}

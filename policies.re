# \file
# \brief  Default policies for Sudo microservices.
#
# This file is in the public domain.

# This is a list of default policy implementations. All rules fail by
# default.
# To allow a certain sudo action, implement the corresponding pre- and
# post- rules.

# User and group management {{{

 acPreSudoUserAdd(*userName, *initialAttr, *initialValue, *initialUnit, *policyKv) { fail; }
acPostSudoUserAdd(*userName, *initialAttr, *initialValue, *initialUnit, *policyKv) { fail; }

 acPreSudoUserRemove(*userName, *policyKv) { fail; }
acPostSudoUserRemove(*userName, *policyKv) { fail; }

 acPreSudoGroupAdd(*groupName, *initialAttr, *initialValue, *initialUnit, *policyKv) { fail; }
acPostSudoGroupAdd(*groupName, *initialAttr, *initialValue, *initialUnit, *policyKv) { fail; }

 acPreSudoGroupRemove(*groupName, *policyKv) { fail; }
acPostSudoGroupRemove(*groupName, *policyKv) { fail; }

 acPreSudoGroupMemberAdd(*groupName, *userName, *policyKv) { fail; }
acPostSudoGroupMemberAdd(*groupName, *userName, *policyKv) { fail; }

 acPreSudoGroupMemberRemove(*groupName, *userName, *policyKv) { fail; }
acPostSudoGroupMemberRemove(*groupName, *userName, *policyKv) { fail; }

# }}}
# ACL operations {{{

 acPreSudoObjAclSet(*recursive, *accessLevel, *otherName, *objPath, *policyKv) { fail; }
acPostSudoObjAclSet(*recursive, *accessLevel, *otherName, *objPath, *policyKv) { fail; }

# }}}
# Metadata operations {{{

 acPreSudoObjMetaSet(*objName, *objType, *attribute, *value, *unit, *policyKv) { fail; }
acPostSudoObjMetaSet(*objName, *objType, *attribute, *value, *unit, *policyKv) { fail; }

 acPreSudoObjMetaAdd(*objName, *objType, *attribute, *value, *unit, *policyKv) { fail; }
acPostSudoObjMetaAdd(*objName, *objType, *attribute, *value, *unit, *policyKv) { fail; }

 acPreSudoObjMetaRemove(*objName, *objType, *wildcards, *attribute, *value, *unit, *policyKv) { fail; }
acPostSudoObjMetaRemove(*objName, *objType, *wildcards, *attribute, *value, *unit, *policyKv) { fail; }

# }}}

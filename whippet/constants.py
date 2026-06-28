"""
whippet.constants — shared lookup tables.

Kept in one place so the loader, graph, query engine, and CLI all agree on
the BloodHound relationship vocabulary and the security-flag vocabulary
without importing each other.
"""
from __future__ import annotations

# ── Edge types that represent a privilege / control relationship ───────────────
#    (matches BloodHound's relationship model)
EDGE_TYPES = {
    # Group / session
    "MemberOf", "HasSession",
    # ACL-based
    "GenericAll", "GenericWrite", "WriteOwner", "WriteDacl",
    "AllExtendedRights", "ForceChangePassword", "AddMember", "Owns",
    "ReadLAPSPassword", "ReadGMSAPassword",
    "GetChanges", "GetChangesAll",
    # Delegation
    "AllowedToDelegate", "AllowedToAct",
    # GPO / OU
    "GPLink", "Contains", "AffectedBy",
    # Trust / special
    "DCSync", "AdminTo", "CanRDP", "CanPSRemote", "ExecuteDCOM",
    # BloodHound CE extras
    "HasSIDHistory", "TrustedBy",
}

HIGH_VALUE_NAMES = {
    "DOMAIN ADMINS", "ENTERPRISE ADMINS", "SCHEMA ADMINS",
    "ADMINISTRATORS", "ACCOUNT OPERATORS", "BACKUP OPERATORS",
    "DOMAIN CONTROLLERS",
}

# Boolean security-relevant flags carried in SharpHound user Properties.
# Maps the JSON property name → short label printed in listings / shown in the GUI.
USER_FLAGS = {
    "enabled":                 "enabled",
    "admincount":              "adminCount",
    "hasspn":                  "kerberoastable",
    "dontreqpreauth":          "asrep-roastable",
    "passwordnotreqd":         "pwdNotReqd",
    "pwdneverexpires":         "pwdNeverExpires",
    "unconstraineddelegation": "unconstrained",
    "trustedtoauth":           "constrained",   # trusted to auth for delegation
    "sensitive":               "sensitive",     # 'account is sensitive & cannot be delegated'
    "dontexpirepassword":      "pwdNeverExpires",
    "sidhistory":              "sidHistory",
}

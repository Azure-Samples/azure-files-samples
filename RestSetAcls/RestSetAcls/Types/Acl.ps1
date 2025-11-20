<#
.SYNOPSIS
This enum defines the ACL revision levels that are used in Windows security descriptors.
.LINK
https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/20233ed8-a6c6-4097-aafa-dd545ed24428
#>
enum AclRevision {
    # When set to 0x02, only AceTypes 0x00, 0x01, 0x02, 0x03, 0x11, 0x12, and 0x13 can be present in the ACL.
    # An AceType of 0x11 is used for SACLs but not for DACLs. For more information about ACE types, see MS-DTYP section
    # 2.4.4.1.
    ACL_REVISION = 0x00000002

    # When set to 0x04, AceTypes 0x05, 0x06, 0x07, 0x08, and 0x11 are allowed. ACLs of revision 0x04 are applicable 
    # only to directory service objects. An AceType of 0x11 is used for SACLs but not for DACLs.
    ACL_REVISION_DS = 0x00000004
}
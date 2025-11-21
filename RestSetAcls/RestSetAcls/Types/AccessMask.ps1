<#
.SYNOPSIS
Object-specific rights for files and folders.
#>
enum SpecificRights {
    FILE_READ_DATA        = 0x1
    FILE_LIST_DIRECTORY   = 0x1
    FILE_WRITE_DATA       = 0x2
    FILE_ADD_FILE         = 0x2
    FILE_APPEND_DATA      = 0x4
    FILE_ADD_SUBDIRECTORY = 0x4
    FILE_READ_EA          = 0x8
    FILE_WRITE_EA         = 0x10
    FILE_EXECUTE          = 0x20
    FILE_TRAVERSE         = 0x20
    FILE_DELETE_CHILD     = 0x40
    FILE_READ_ATTRIBUTES  = 0x80
    FILE_WRITE_ATTRIBUTES = 0x100
}

<#
.SYNOPSIS
Standard rights for any type of securable object (including files and folders).
#>
enum StandardRights {
    DELETE       = 0x00010000
    READ_CONTROL = 0x00020000
    WRITE_DAC    = 0x00040000
    WRITE_OWNER  = 0x00080000
    SYNCHRONIZE  = 0x00100000
}

<#
.SYNOPSIS
Standard rights for any type of securable object (including files and folders).
#>
enum GenericRights {
    GENERIC_READ    = 0x80000000
    GENERIC_WRITE   = 0x40000000
    GENERIC_EXECUTE = 0x20000000
    GENERIC_ALL     = 0x10000000
}

<#
.SYNOPSIS
These are the basic permissions, as displayed by the Windows File Explorer.
We have also been calling these "composite rights".
#>
enum BasicPermissions {
    # 278 is obtained via:
    #    [SpecificRights]::FILE_WRITE_DATA -bor
    #    [SpecificRights]::FILE_APPEND_DATA -bor
    #    [SpecificRights]::FILE_WRITE_EA -bor
    #    [SpecificRights]::FILE_WRITE_ATTRIBUTES
    WRITE = 278

    # 131209 is obtained via:
    #    [SpecificRights]::FILE_READ_DATA -bor
    #    [SpecificRights]::FILE_READ_EA -bor
    #    [SpecificRights]::FILE_READ_ATTRIBUTES -bor
    #    [StandardRights]::READ_CONTROL
    READ = 131209
    
    # 131241 is obtained via:
    #   [BasicPermissions]::READ -bor [SpecificRights]::FILE_EXECUTE
    READ_AND_EXECUTE = 131241

    # 197055 is obtained via:
    #   [BasicPermissions]::READ_AND_EXECUTE -bor
    #   [BasicPermissions]::WRITE -bor
    #   [StandardRights]::DELETE
    MODIFY = 197055

    # 2032127 is obtained via:
    #   [BasicPermissions]::MODIFY -bor
    #   [SpecificRights]::FILE_DELETE_CHILD -bor
    #   [StandardRights]::WRITE_DAC -bor
    #   [StandardRights]::WRITE_OWNER -bor
    #   [StandardRights]::SYNCHRONIZE
    FULL_CONTROL = 2032127
}

<#
.SYNOPSIS
Standard rights combinations for any type of securable object (including files and folders).

.LINK
https://learn.microsoft.com/en-us/windows/win32/secauthz/standard-access-rights
#>
enum StandardRightsCombination {
    # 2031616 is obtained via:
    #   [StandardRights]::DELETE -bor
    #   [StandardRights]::READ_CONTROL -bor
    #   [StandardRights]::WRITE_DAC -bor
    #   [StandardRights]::WRITE_OWNER -bor
    #   [StandardRights]::SYNCHRONIZE
    STANDARD_RIGHTS_ALL = 2031616
    STANDARD_RIGHTS_EXECUTE = [StandardRights]::READ_CONTROL
    STANDARD_RIGHTS_READ = [StandardRights]::READ_CONTROL
    # 983040 is obtained via:
    #   [StandardRights]::DELETE -bor
    #   [StandardRights]::READ_CONTROL -bor
    #   [StandardRights]::WRITE_DAC -bor
    #   [StandardRights]::WRITE_OWNER
    STANDARD_RIGHTS_REQUIRED = 983040
    STANDARD_RIGHTS_WRITE = [StandardRights]::READ_CONTROL
}


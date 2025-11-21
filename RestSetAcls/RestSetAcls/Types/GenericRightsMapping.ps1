
<#
.SYNOPSIS
This is a mapping of the generic rights to the specific rights for files and folders.

.LINK
https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights
#>
enum FileGenericRightsMapping {
    # FILE_GENERIC_READ is defined as the following, which evaluates to 1179785:
    #
    #   [SpecificRights]::FILE_READ_ATTRIBUTES -bor
    #   [SpecificRights]::FILE_READ_DATA -bor
    #   [SpecificRights]::FILE_READ_EA -bor
    #   [StandardRightsCombination]::STANDARD_RIGHTS_READ -bor
    #   [StandardRights]::SYNCHRONIZE
    FILE_GENERIC_READ = 1179785

    # FILE_GENERIC_WRITE is defined as the following, which evaluates to 1179926:
    #
    #   [SpecificRights]::FILE_APPEND_DATA -bor
    #   [SpecificRights]::FILE_WRITE_ATTRIBUTES -bor
    #   [SpecificRights]::FILE_WRITE_DATA -bor
    #   [SpecificRights]::FILE_WRITE_EA -bor
    #   [StandardRightsCombination]::STANDARD_RIGHTS_WRITE -bor
    #   [StandardRights]::SYNCHRONIZE
    FILE_GENERIC_WRITE = 1179926

    # FILE_GENERIC_EXECUTE is defined as the following, which evaluates to 1179808:
    #   [SpecificRights]::FILE_EXECUTE -bor
    #   [SpecificRights]::FILE_READ_ATTRIBUTES -bor
    #   [StandardRightsCombination]::STANDARD_RIGHTS_EXECUTE -bor
    #   [StandardRights]::SYNCHRONIZE
    FILE_GENERIC_EXECUTE = 1179808

    # FILE_ALL_ACCESS is not documented, but in practice it's the same as FULL_ACCESS
    FILE_ALL_ACCESS = 2032127
}
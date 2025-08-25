. $PSScriptRoot\SddlUtils.ps1 -Force
. $PSScriptRoot\Convert.ps1 -Force

$signature = @'
using System;
using System.Runtime.InteropServices;

[StructLayout(LayoutKind.Sequential)]
public struct GENERIC_MAPPING
{
    public uint GenericRead;
    public uint GenericWrite;
    public uint GenericExecute;
    public uint GenericAll;
}

public static class NativeMethods {
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CreatePrivateObjectSecurityEx(
        System.IntPtr ParentDescriptor,
        System.IntPtr CreatorDescriptor,
        out System.IntPtr NewDescriptor,
        System.IntPtr ObjectType,
        [MarshalAs(UnmanagedType.Bool)] bool IsContainerObject,
        uint AutoInheritFlags,
        System.IntPtr Token,
        ref GENERIC_MAPPING GenericMapping);
    
    [DllImport("advapi32.dll", SetLastError = false)]
    public static extern void MapGenericMask(
        ref uint accessMask,
        ref GENERIC_MAPPING genericMapping);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool DestroyPrivateObjectSecurity(ref IntPtr ObjectDescriptor);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern int GetSecurityDescriptorLength(System.IntPtr pSecurityDescriptor);
}
'@

if (-not ([System.Management.Automation.PSTypeName]'NativeMethods').Type) {
    Add-Type -TypeDefinition $signature -Language CSharp
}

function MarshalSecurityDescriptor {
    [CmdletBinding()]
    [OutputType([System.IntPtr])]
    param (
        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.GenericSecurityDescriptor]$SecurityDescriptor
    )

    $length = $SecurityDescriptor.BinaryLength
    $bytes = New-Object byte[] $length
    $SecurityDescriptor.GetBinaryForm($bytes, 0)
    $intPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($length)
    [System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $intPtr, $length)
    return $intPtr
}

function UnmarshalSecurityDescriptor {
    [CmdletBinding()]
    [OutputType([System.Security.AccessControl.CommonSecurityDescriptor])]
    param (
        [Parameter(Mandatory = $true)]
        [IntPtr]$IntPtr,

        [Parameter(Mandatory = $true)]
        [bool]$IsDirectory
    )

    if ($IntPtr -eq [System.IntPtr]::Zero) {
        return $null
    }

    $length = [NativeMethods]::GetSecurityDescriptorLength($IntPtr)
    $bytes = New-Object byte[] $length
    [System.Runtime.InteropServices.Marshal]::Copy($IntPtr, $bytes, 0, $length)

    return [System.Security.AccessControl.CommonSecurityDescriptor]::new($IsDirectory, $false, $bytes, 0)
}

function Get-FileGenericMapping {
    [CmdletBinding()]
    param ()

    # Build generic mapping object. Since this module only deals with file system objects,
    # we can hard-code the file generic rights mapping.
    # https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-generic_mapping
    $genericMapping = New-Object GENERIC_MAPPING
    $genericMapping.GenericRead = [FileGenericRightsMapping]::FILE_GENERIC_READ
    $genericMapping.GenericWrite = [FileGenericRightsMapping]::FILE_GENERIC_WRITE
    $genericMapping.GenericExecute = [FileGenericRightsMapping]::FILE_GENERIC_EXECUTE
    $genericMapping.GenericAll = [FileGenericRightsMapping]::FILE_ALL_ACCESS
    return $genericMapping
}

function Get-MappedAccessMask {
    [CmdletBinding()]
    [OutputType([int])]
    param (
        [Parameter(Mandatory = $true)]
        [int]$AccessMask
    )

    # Believe it or not, this is the only way of converting negative ints to uint in powershell...
    $bytes = [BitConverter]::GetBytes($AccessMask)
    $accessMaskUint = [BitConverter]::ToUInt32($bytes, 0)

    $genericMapping = Get-FileGenericMapping

    [NativeMethods]::MapGenericMask([ref] $accessMaskUint, [ref] $genericMapping)

    # Convert back from uint to int
    $bytes = [BitConverter]::GetBytes($accessMaskUint)
    return [BitConverter]::ToInt32($bytes, 0)
}

[Flags()]
enum AutoInheritFlags {
    # The new discretionary access control list (DACL) contains ACEs inherited from the DACL of ParentDescriptor, as
    # well as any explicit ACEs specified in the DACL of CreatorDescriptor. If this flag is not set, the new DACL does
    # not inherit ACEs.
    SEF_DACL_AUTO_INHERIT = 0x01

    # The new system access control list (SACL) contains ACEs inherited from the SACL of ParentDescriptor, as well as
    # any explicit ACEs specified in the SACL of CreatorDescriptor. If this flag is not set, the new SACL does not
    # inherit ACEs.
    SEF_SACL_AUTO_INHERIT = 0x02

    # CreatorDescriptor is the default descriptor for the type of object specified by ObjectType. As such,
    # CreatorDescriptor is ignored if ParentDescriptor has any object-specific ACEs for the type of object specified by
    # the ObjectType parameter. If no such ACEs are inherited, CreatorDescriptor is handled as though this flag were not
    # specified.
    SEF_DEFAULT_DESCRIPTOR_FOR_OBJECT = 0x04

    # The function does not perform privilege checking. If the SEF_AVOID_OWNER_CHECK flag is also set, the Token
    # parameter can be NULL. This flag is useful while implementing automatic inheritance to avoid checking privileges
    # on each child updated.
    SEF_AVOID_PRIVILEGE_CHECK = 0x08

    # The function does not check the validity of the owner in the resultant NewDescriptor as described in Remarks
    # below. If the SEF_AVOID_PRIVILEGE_CHECK flag is also set, the Token parameter can be NULL.
    SEF_AVOID_OWNER_CHECK = 0x10

    # The owner of NewDescriptor defaults to the owner from ParentDescriptor. If not set, the owner of NewDescriptor
    # defaults to the owner of the token specified by the Token parameter. The owner of the token is specified in the
    # token itself. In either case, if the CreatorDescriptor parameter is not NULL, the NewDescriptor owner is set to
    # the owner from CreatorDescriptor.
    SEF_DEFAULT_OWNER_FROM_PARENT = 0x20 

    # The group of NewDescriptor defaults to the group from ParentDescriptor. If not set, the group of NewDescriptor
    # defaults to the group of the token specified by the Token parameter. The group of the token is specified in the
    # token itself. In either case, if the CreatorDescriptor parameter is not NULL, the NewDescriptor group is set to
    # the group from CreatorDescriptor.
    SEF_DEFAULT_GROUP_FROM_PARENT = 0x40

    # When this flag is set, the mandatory label ACE in CreatorDescriptor is not used to create a mandatory label ACE
    # in NewDescriptor. Instead, a new SYSTEM_MANDATORY_LABEL_ACE with an access mask of 
    # SYSTEM_MANDATORY_LABEL_NO_WRITE_UP and the SID from the token's integrity SID is added to NewDescriptor.
    SEF_MACL_NO_WRITE_UP = 0x100

    # When this flag is set, the mandatory label ACE in CreatorDescriptor is not used to create a mandatory label ACE
    # in NewDescriptor. Instead, a new SYSTEM_MANDATORY_LABEL_ACE with an access mask of
    # SYSTEM_MANDATORY_LABEL_NO_READ_UP and the SID from the token's integrity SID is added to NewDescriptor.
    SEF_MACL_NO_READ_UP = 0x200

    # When this flag is set, the mandatory label ACE in CreatorDescriptor is not used to create a mandatory label ACE
    # in NewDescriptor. Instead, a new SYSTEM_MANDATORY_LABEL_ACE with an access mask of
    # SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP and the SID from the token's integrity SID is added to NewDescriptor.
    SEF_MACL_NO_EXECUTE_UP = 0x400

    # Any restrictions specified by the ParentDescriptor that would limit the caller's ability to specify a DACL in the
    # CreatorDescriptor are ignored.
    SEF_AVOID_OWNER_RESTRICTION = 0x1000
}

function CreatePrivateObjectSecurityEx {
    [CmdletBinding()]
    [OutputType([System.Security.AccessControl.GenericSecurityDescriptor])]
    param (
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [System.Security.AccessControl.GenericSecurityDescriptor]$ParentDescriptor,
        
        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.GenericSecurityDescriptor]$CreatorDescriptor,
        
        [Parameter(Mandatory = $true)]
        [bool]$IsDirectory
    )

    $parentSdIntPtr = [System.IntPtr]::Zero
    $creatorSdIntPtr = [System.IntPtr]::Zero
    $newDescriptorIntPtr = [System.IntPtr]::Zero

    try {
        # Parent is allowed to be null by this implementation.
        if ($null -ne $ParentDescriptor) {
            $parentSdIntPtr = MarshalSecurityDescriptor $ParentDescriptor
        }

        # Creator is not allowed to be null by this implementation.
        # This simplifying assumption is made to avoid having to deal with the token,
        # and is good enough for our use-case of computing inheritance on existing ACLs.
        $creatorSdIntPtr = MarshalSecurityDescriptor $CreatorDescriptor

        # Since we only deal with file system objects, we will never have object GUIDs.
        # We can safely set the object type to null.
        $objectTypeIntPtr = [System.IntPtr]::Zero

        [bool]$isContainerObject = $IsDirectory

        # We don't want to run this with a token, so set AVOID_PRIVILEGE_CHECK and AVOID_OWNER_CHECK.
        $autoInheritFlags = (
            [AutoInheritFlags]::SEF_AVOID_PRIVILEGE_CHECK -bor
            [AutoInheritFlags]::SEF_AVOID_OWNER_CHECK
        )     

        # TODO: this is a hack. This logic should be in the caller...
        # We want to opt in to ACL inheritance, so set the SEF_DACL_AUTO_INHERIT and SEF_SACL_AUTO_INHERIT flags if the DACL/SACL are not protected.
        if (-not ($CreatorDescriptor.ControlFlags -band [System.Security.AccessControl.ControlFlags]::DiscretionaryAclProtected)) {
            $autoInheritFlags = $autoInheritFlags -bor [AutoInheritFlags]::SEF_DACL_AUTO_INHERIT
        }

        if (-not ($CreatorDescriptor.ControlFlags -band [System.Security.AccessControl.ControlFlags]::SystemAclProtected)) {
            $autoInheritFlags = $autoInheritFlags -bor [AutoInheritFlags]::SEF_SACL_AUTO_INHERIT
        }

        # We do not allow CreatorDescriptor to be null in this implementation, so according to
        # MS-DTYP 2.5.3.4, the token will never be used. Hence we can safely set it to null.
        # This also makes things easier for us -- one less thing to marshal.
        # https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/0f0c6ffc-f57d-47f8-a6c8-63889e874e24
        $token = [System.IntPtr]::Zero

        $genericMapping = Get-FileGenericMapping

        $success = [NativeMethods]::CreatePrivateObjectSecurityEx(
            $parentSdIntPtr, 
            $creatorSdIntPtr, 
            [ref] $newDescriptorIntPtr, 
            $objectTypeIntPtr,
            $isContainerObject,
            [uint32]$autoInheritFlags,
            $token, 
            [ref] $genericMapping
        )

        if (-not $success) {
            $errorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Error "CreatePrivateObjectSecurityEx failed with result: $success, error code: $errorCode"
            return $null
        }

        return UnmarshalSecurityDescriptor $newDescriptorIntPtr -IsDirectory $IsDirectory
    } catch {
        Write-Error "Failure: $_"
        throw $_
    } finally {
        # Free all the allocated memory
        if ($parentSdIntPtr -ne [System.IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($parentSdIntPtr)
        }
        if ($creatorSdIntPtr -ne [System.IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($creatorSdIntPtr)
        }
        if ($newDescriptorIntPtr -ne [System.IntPtr]::Zero) {
            $success = [NativeMethods]::DestroyPrivateObjectSecurity([ref] $newDescriptorIntPtr)
            if (-not $success) {
                Write-Error "DestroyPrivateObjectSecurity failed with result: $success, error code: $errorCode" -ErrorAction Stop
            }
        }
    }
}
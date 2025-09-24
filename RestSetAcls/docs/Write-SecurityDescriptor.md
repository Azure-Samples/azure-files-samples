---
external help file: RestSetAcls-help.xml
Module Name: RestSetAcls
online version:
schema: 2.0.0
---

# Write-SecurityDescriptor

## SYNOPSIS
Displays a detailed, formatted view of a security descriptor including owner, group, control flags, and ACLs.

## SYNTAX

```
Write-SecurityDescriptor [-Acl] <Object> [-AclFormat <SecurityDescriptorFormat>]
 [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## DESCRIPTION
The Write-SecurityDescriptor function provides a comprehensive, human-readable display of a security descriptor's 
components It displays the owner, group, control flags, discretionary ACL (DACL), and system ACL (SACL) with
color-coded formatting for enhanced readability.
This function is particularly useful for debugging, auditing, and
understanding the structure of Windows security descriptors.

## EXAMPLES

### EXAMPLE 1
```
$acl = "O:BAG:SYD:(A;;FA;;;SY)(A;;0x1200a9;;;BU)"
PS> Write-SecurityDescriptor -Acl $acl -AclFormat Sddl
```

Displays a formatted view of the SDDL security descriptor, showing owner, group, control flags, and both 
discretionary and system ACLs with detailed access mask information.

### EXAMPLE 2
```
$context = Get-AzStorageContext -StorageAccountName "mystorageaccount" -StorageAccountKey "mykey"
PS> Get-AzFileAcl -Context $context -FileShareName "myshare" -FilePath "folder/file.txt" | Write-SecurityDescriptor
```

## PARAMETERS

### -Acl
Specifies the security descriptor or ACL to display.
This can be in various formats including SDDL (Security 
Descriptor Definition Language) string, base64-encoded binary, array of bytes, CommonSecurityDescriptor or
RawSecurityDescriptor objects.

```yaml
Type: Object
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: True (ByValue)
Accept wildcard characters: False
```

### -AclFormat
Specifies the format of the input ACL.
If not provided, the function will automatically infer the format. 
Supported formats include SDDL, Base64, Binary, and Raw.

```yaml
Type: SecurityDescriptorFormat
Parameter Sets: (All)
Aliases:
Accepted values: Sddl, Binary, Base64, Raw, FolderAcl, FileAcl

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ProgressAction
{{ Fill ProgressAction Description }}

```yaml
Type: ActionPreference
Parameter Sets: (All)
Aliases: proga

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### CommonParameters
This cmdlet supports the common parameters: -Debug, -ErrorAction, -ErrorVariable, -InformationAction, -InformationVariable, -OutVariable, -OutBuffer, -PipelineVariable, -Verbose, -WarningAction, and -WarningVariable. For more information, see [about_CommonParameters](http://go.microsoft.com/fwlink/?LinkID=113216).

## INPUTS

## OUTPUTS

### System.Void
### This function outputs formatted text to the console and does not return any objects.
## NOTES

## RELATED LINKS

[Get-AzFileAcl]()

[Convert-SecurityDescriptor]()


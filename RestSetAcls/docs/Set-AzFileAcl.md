---
external help file: RestSetAcls-help.xml
Module Name: RestSetAcls
online version:
schema: 2.0.0
---

# Set-AzFileAcl

## SYNOPSIS
Sets the Access Control List (ACL) for a specified Azure file or directory.

## SYNTAX

```
Set-AzFileAcl [-File] <AzureStorageBase> [-Acl] <Object> [[-AclFormat] <SecurityDescriptorFormat>]
 [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
The \`Set-AzFileAcl\` function applies an ACL to a specified Azure file or directory. 
It supports both SDDL (Security Descriptor Definition Language) and binary ACL formats. 
The function determines the ACL format if not explicitly provided and applies the ACL directly 
or via a permission key, depending on the size of the ACL.

## EXAMPLES

### EXAMPLE 1
```
$context = Get-AzStorageContext -StorageAccountName "mystorageaccount" -StorageAccountKey "mykey"
PS> $file = Get-AzStorageFile -Context $context -ShareName "myfileshare" -Path "myfolder/myfile.txt"
PS> Set-AzFileAcl -File $file -Acl "O:BAG:SYD:(A;;FA;;;SY)" -AclFormat Sddl
```

Sets the specified SDDL ACL on the given file.

### EXAMPLE 2
```
$context = Get-AzStorageContext -StorageAccountName "mystorageaccount" -StorageAccountKey "mykey"
PS> $file = Get-AzStorageFile -Context $context -ShareName "myfileshare" -Path "myfolder/myfile.txt"
PS> $binaryAcl = [byte[]](0x01, 0x02, 0x03, 0x04, ...)
PS> Set-AzFileAcl -File $file -Acl $binaryAcl -AclFormat Binary
```

Sets the specified binary ACL on the given file.

## PARAMETERS

### -File
Specifies the Azure storage file or directory on which to set the ACL.

```yaml
Type: AzureStorageBase
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: True (ByValue)
Accept wildcard characters: False
```

### -Acl
Specifies the ACL to be applied.
This can be in SDDL format, base64-encoded binary, binary array, or RawSecurityDescriptor.

```yaml
Type: Object
Parameter Sets: (All)
Aliases:

Required: True
Position: 2
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -AclFormat
Specifies the format of the ACL.
If not provided, the function will infer the format automatically. 
Supported formats include SDDL, Base64, and Binary.

```yaml
Type: SecurityDescriptorFormat
Parameter Sets: (All)
Aliases:
Accepted values: Sddl, Binary, Base64, Raw

Required: False
Position: 3
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -WhatIf
Shows what would happen if the cmdlet runs.
The cmdlet is not run.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: wi

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Confirm
Prompts you for confirmation before running the cmdlet.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases: cf

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

### System.String
### Returns the file permission key associated with the applied ACL.
## NOTES

## RELATED LINKS

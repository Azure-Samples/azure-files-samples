---
external help file: RestSetAcls-help.xml
Module Name: RestSetAcls
online version:
schema: 2.0.0
---

# New-AzFileAcl

## SYNOPSIS
Creates a new Azure File ACL (Access Control List) for a specified file share.

## SYNTAX

```
New-AzFileAcl [-Context] <IStorageContext> [-FileShareName] <String> [-Acl] <Object>
 [[-AclFormat] <SecurityDescriptorFormat>] [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm]
 [<CommonParameters>]
```

## DESCRIPTION
The \`New-AzFileAcl\` function creates a new ACL for an Azure file share.
It supports both SDDL (Security Descriptor Definition Language) and binary ACL formats.
The function determines the ACL format if not explicitly provided and uploads the ACL to the specified file share.

## EXAMPLES

### EXAMPLE 1
```
$context = Get-AzStorageContext -StorageAccountName "mystorageaccount" -StorageAccountKey "mykey"
PS> $acl = "O:BAG:SYD:(A;;FA;;;SY)"
PS> New-AzFileAcl -Context $context -FileShareName "myfileshare" -Acl $acl -AclFormat Sddl
```

Creates a new ACL in SDDL format for the specified file share and returns the file permission key.

### EXAMPLE 2
```
$context = Get-AzStorageContext -StorageAccountName "mystorageaccount" -StorageAccountKey "mykey"
PS> $acl = "<base64-encoded ACL>"
PS> New-AzFileAcl -Context $context -FileShareName "myfileshare" -Acl $acl  -AclFormat Base64
```

Creates a new ACL for the specified file share, inferring the ACL format automatically, and returns the file permission key.

## PARAMETERS

### -Context
Specifies the Azure storage context.
This is required to authenticate and interact with the Azure storage account.

```yaml
Type: IStorageContext
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -FileShareName
Specifies the name of the Azure file share where the ACL will be applied.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: 2
Default value: None
Accept pipeline input: False
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
Position: 3
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -AclFormat
Specifies the format of the ACL.
If not provided, the function will infer the format automatically.

```yaml
Type: SecurityDescriptorFormat
Parameter Sets: (All)
Aliases:
Accepted values: Sddl, Binary, Base64, Raw, FolderAcl, FileAcl

Required: False
Position: 4
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
### Returns the file permission key associated with the created ACL.
## NOTES

## RELATED LINKS

[Set-AzFileAclKey]()


---
external help file: RestSetAcls-help.xml
Module Name: RestSetAcls
online version:
schema: 2.0.0
---

# Get-AzFileAclFromKey

## SYNOPSIS
Retrieves the ACL (Access Control List) for a specified ACL key.

## SYNTAX

### Share
```
Get-AzFileAclFromKey -Key <String> -Share <AzureStorageFileShare> [-OutputFormat <SecurityDescriptorFormat>]
 [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

### FileShareName
```
Get-AzFileAclFromKey -Key <String> -Context <IStorageContext> -FileShareName <String>
 [-OutputFormat <SecurityDescriptorFormat>] [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm]
 [<CommonParameters>]
```

### ShareClient
```
Get-AzFileAclFromKey -Key <String> [-ShareClient <ShareClient>] [-OutputFormat <SecurityDescriptorFormat>]
 [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
The \`Get-AzFileAclFromKey\` function retrieves the ACL for a specified ACL key.
It supports retrieving the ACL in
various formats, including SDDL (Security Descriptor Definition Language) or binary formats.
The function supports
retrieving the ACL from a file share specified either directly or its name and context.

## EXAMPLES

### EXAMPLE 1
```
$context = Get-AzStorageContext -StorageAccountName "mystorageaccount" -StorageAccountKey "mykey"
PS> $file = Get-AzStorageFile -Context $context -ShareName "myfileshare" -Path "myfolder/myfile.txt"
PS> $key = Get-AzFileAclKey -File $file
PS> Get-AzFileAclFromKey -Key $key -Share $file.Share -OutputFormat Sddl
```

Retrieves the SDDL ACL for the specified file using the permission key.

## PARAMETERS

### -Key
Specifies the ACL key to be retrieved.
This is the key returned from the \`New-AzFileAcl\`, \`Set-AzFileAclKey\`,
or \`Get-AzFileAclKey\` functions.

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: True (ByValue)
Accept wildcard characters: False
```

### -Share
Specifies the Azure storage file share from which to retrieve the ACL key.

```yaml
Type: AzureStorageFileShare
Parameter Sets: Share
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Context
Specifies the Azure storage context.
This is required to authenticate and interact with the Azure storage account.

```yaml
Type: IStorageContext
Parameter Sets: FileShareName
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -FileShareName
Specifies the name of the Azure file share from which to retrieve the ACL key.

```yaml
Type: String
Parameter Sets: FileShareName
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ShareClient
Specifies the Azure storage file share client from which to retrieve the ACL key.

```yaml
Type: ShareClient
Parameter Sets: ShareClient
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -OutputFormat
Specifies the output format of the security descriptor.
Supported formats include SDDL, Base64, and Binary.

```yaml
Type: SecurityDescriptorFormat
Parameter Sets: (All)
Aliases:
Accepted values: Sddl, Binary, Base64, Raw

Required: False
Position: Named
Default value: Sddl
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
### Returns the ACL in the specified format. The default format is SDDL.
## NOTES

## RELATED LINKS

[New-AzFileAcl]()

[Set-AzFileAcl]()

[Set-AzFileAclKey]()


---
external help file: RestSetAcls-help.xml
Module Name: RestSetAcls
online version:
schema: 2.0.0
---

# Get-AzFileAcl

## SYNOPSIS
Retrieves the ACL (Access Control List) for a specified file or directory.

## SYNTAX

### File
```
Get-AzFileAcl -File <AzureStorageBase> [-OutputFormat <SecurityDescriptorFormat>]
 [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

### FilePath
```
Get-AzFileAcl -Context <IStorageContext> -FileShareName <String> -FilePath <String>
 [-OutputFormat <SecurityDescriptorFormat>] [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## DESCRIPTION
The \`Get-AzFileAcl\` function retrieves the ACL for a specified file or directory.
It supports retrieving the ACL in
various formats, including SDDL (Security Descriptor Definition Language) or binary formats.
The function supports
retrieving the ACL from a file share specified either directly or its name and context.

## EXAMPLES

### EXAMPLE 1
```
$context = Get-AzStorageContext -StorageAccountName "mystorageaccount" -StorageAccountKey "mykey"
PS> $file = Get-AzStorageFile -Context $context -ShareName "myfileshare" -Path "myfolder/myfile.txt"
PS> Get-AzFileAcl -File $file
```

Retrieves the SDDL ACL for the specified file using the permission key.

## PARAMETERS

### -File
Specifies the Azure storage file or directory from which to retrieve the ACL key.

```yaml
Type: AzureStorageBase
Parameter Sets: File
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
Parameter Sets: FilePath
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
Parameter Sets: FilePath
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -FilePath
Specifies the path to the file or directory from which to retrieve the ACL key.

```yaml
Type: String
Parameter Sets: FilePath
Aliases:

Required: True
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


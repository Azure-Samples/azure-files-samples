---
external help file: RestSetAcls-help.xml
Module Name: RestSetAcls
online version:
schema: 2.0.0
---

# Get-AzFileAclKey

## SYNOPSIS
Retrieves the permission key from a file or directory in an Azure file share.

## SYNTAX

### File
```
Get-AzFileAclKey -File <AzureStorageBase> [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

### FilePath
```
Get-AzFileAclKey -Context <IStorageContext> -FileShareName <String> -FilePath <String>
 [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## DESCRIPTION
The \`Get-AzFileAclKey\` function retrieves the ACL key for a given file or directory in an Azure file share. 
The ACL can be returned in various formats, including SDDL (Security Descriptor Definition Language) 
or binary formats.
The function supports retrieving the ACL from a file share specified either 
directly or by its name and context.

## EXAMPLES

### EXAMPLE 1
```
$context = Get-AzStorageContext -StorageAccountName "mystorageaccount" -StorageAccountKey "mykey"
PS> $file = Get-AzStorageFile -Context $context -ShareName "myfileshare" -Path "myfolder/myfile.txt"
PS> Get-AzFileAclKey -File $file
```

Retrieves the permission key for the specified file.

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
### Returns the file permission key associated with the specified file or directory.
## NOTES

## RELATED LINKS

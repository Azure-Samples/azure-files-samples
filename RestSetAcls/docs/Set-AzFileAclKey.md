---
external help file: RestSetAcls-help.xml
Module Name: RestSetAcls
online version:
schema: 2.0.0
---

# Set-AzFileAclKey

## SYNOPSIS
Sets the Azure File ACL key on a specified file or directory.

## SYNTAX

### File
```
Set-AzFileAclKey -File <AzureStorageBase> -Key <String> [-ProgressAction <ActionPreference>] [-WhatIf]
 [-Confirm] [<CommonParameters>]
```

### FilePath
```
Set-AzFileAclKey -Context <IStorageContext> -FileShareName <String> -FilePath <String> -Key <String>
 [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

### Client
```
Set-AzFileAclKey -Client <Object> -Key <String> [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm]
 [<CommonParameters>]
```

## DESCRIPTION
The \`Set-AzFileAclKey\` takes an ACL key, and sets it on a specified file or directory in Azure Files.

## EXAMPLES

### EXAMPLE 1
```
$context = Get-AzStorageContext -StorageAccountName "mystorageaccount" -StorageAccountKey "mykey"
PS> $key = New-AzFileAcl -Context $context -FileShareName "myfileshare" -Acl "O:BAG:SYD:(A;;FA;;;SY)" -AclFormat Sddl
PS> $file = Get-AzStorageFile -Context $context -ShareName "myfileshare" -Path "myfolder/myfile.txt"
PS> Set-AzFileAclKey -File $file -Key $key
```

Sets the specified ACL key on the given file.

## PARAMETERS

### -File
Specifies the Azure storage file or directory on which to set the ACL key.

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
Specifies the name of the Azure file share where the ACL will be applied.

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
Path to the file or directory on which to set the permission key

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

### -Client
Specifies the Azure storage file or directory client with which the ACL will be applied.

```yaml
Type: Object
Parameter Sets: Client
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Key
Specifies the ACL key to be applied.
This is the key returned from the \`New-AzFileAcl\` function.

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
### Note that this may differ from the key that was passed in, as the permission applied to the file may be different,
### due to inheritance rules defined on the parent directory.
## NOTES

## RELATED LINKS

[New-AzFileAcl]()


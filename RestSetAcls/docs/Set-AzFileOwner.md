---
external help file: RestSetAcls-help.xml
Module Name: RestSetAcls
online version:
schema: 2.0.0
---

# Set-AzFileOwner

## SYNOPSIS
Sets the owner for a specified Azure file or directory.

## SYNTAX

### File
```
Set-AzFileOwner -File <AzureStorageBase> -Owner <String> [-ProgressAction <ActionPreference>] [-WhatIf]
 [-Confirm] [<CommonParameters>]
```

### FilePath
```
Set-AzFileOwner -Context <IStorageContext> -FileShareName <String> -FilePath <String> -Owner <String>
 [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

### Client
```
Set-AzFileOwner [-Client <Object>] -Owner <String> [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm]
 [<CommonParameters>]
```

## DESCRIPTION
It supports both SID values and UPNs (User Principal Names) for specifying the owner.
The function can be used to set the owner for a file or directory in an Azure file share.

## EXAMPLES

### Example 1
```powershell
PS C:\> {{ Add example code here }}
```

{{ Add example description here }}

## PARAMETERS

### -File
Specifies the Azure storage file or directory on which to set the ACL.

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
Azure storage context

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
Name of the file share

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
Path to the file or directory within the share

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
Specifies the Azure storage file or directory client with which to set the ACL.

```yaml
Type: Object
Parameter Sets: Client
Aliases:

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Owner
Specifies the owner that should be set.
This can be a SID or a UPN (User Principal Name).

```yaml
Type: String
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
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

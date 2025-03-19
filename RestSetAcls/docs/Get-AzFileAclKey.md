---
external help file: RestSetAcls-help.xml
Module Name: RestSetAcls
online version: https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format
https://learn.microsoft.com/en-us/powershell/scripting/overview
schema: 2.0.0
---

# Get-AzFileAclKey

## SYNOPSIS
{{ Fill in the Synopsis }}

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
{{ Fill in the Description }}

## EXAMPLES

### Example 1
```powershell
PS C:\> {{ Add example code here }}
```

{{ Add example description here }}

## PARAMETERS

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

### -File
Azure storage file or directory

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

### None

## OUTPUTS

### System.String

## NOTES

## RELATED LINKS

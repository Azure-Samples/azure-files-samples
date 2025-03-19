---
external help file: RestSetAcls-help.xml
Module Name: RestSetAcls
online version: https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format
https://learn.microsoft.com/en-us/powershell/scripting/overview
schema: 2.0.0
---

# Get-AzFileAcl

## SYNOPSIS
{{ Fill in the Synopsis }}

## SYNTAX

### Share
```
Get-AzFileAcl -Key <String> -Share <AzureStorageFileShare> [-OutputFormat <SecurityDescriptorFormat>]
 [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

### FileShareName
```
Get-AzFileAcl -Key <String> -Context <IStorageContext> -FileShareName <String>
 [-OutputFormat <SecurityDescriptorFormat>] [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm]
 [<CommonParameters>]
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

### -Context
Azure storage context

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
Name of the file share

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

### -Key
{{ Fill Key Description }}

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

### -OutputFormat
Output format of the security descriptor

```yaml
Type: SecurityDescriptorFormat
Parameter Sets: (All)
Aliases:
Accepted values: Sddl, Binary, Base64, Raw

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Share
{{ Fill Share Description }}

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

### System.String

## OUTPUTS

### System.String

### System.Byte[]

## NOTES

## RELATED LINKS

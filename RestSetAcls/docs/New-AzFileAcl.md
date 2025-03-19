---
external help file: RestSetAcls-help.xml
Module Name: RestSetAcls
online version: https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format
https://learn.microsoft.com/en-us/powershell/scripting/overview
schema: 2.0.0
---

# New-AzFileAcl

## SYNOPSIS
{{ Fill in the Synopsis }}

## SYNTAX

### Sddl
```
New-AzFileAcl -Context <IStorageContext> -FileShareName <String> -Sddl <String>
 [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

### Binary
```
New-AzFileAcl -Context <IStorageContext> -FileShareName <String> -Binary <Byte[]>
 [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

### Base64
```
New-AzFileAcl -Context <IStorageContext> -FileShareName <String> -Base64 <String>
 [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

### RawSecurityDescriptor
```
New-AzFileAcl -Context <IStorageContext> -FileShareName <String> -SecurityDescriptor <RawSecurityDescriptor>
 [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm] [<CommonParameters>]
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

### -Base64
Security descriptor in base64-encoded self-relative binary format.

```yaml
Type: String
Parameter Sets: Base64
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Binary
Security descriptor in self-relative binary format.

```yaml
Type: Byte[]
Parameter Sets: Binary
Aliases:

Required: True
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

### -Context
Azure storage context

```yaml
Type: IStorageContext
Parameter Sets: (All)
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
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Sddl
File permission in the Security Descriptor Definition Language (SDDL).
SDDL must have an owner, group, and discretionary access control list (DACL).
The provided SDDL string format of the security descriptor should not have domain relative identifier (like 'DU', 'DA', 'DD' etc) in it.

```yaml
Type: String
Parameter Sets: Sddl
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -SecurityDescriptor
Security descriptor

```yaml
Type: RawSecurityDescriptor
Parameter Sets: RawSecurityDescriptor
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

### None

## OUTPUTS

### System.String

## NOTES

## RELATED LINKS

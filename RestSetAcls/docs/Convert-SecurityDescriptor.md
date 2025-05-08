---
external help file: RestSetAcls-help.xml
Module Name: RestSetAcls
online version:
schema: 2.0.0
---

# Convert-SecurityDescriptor

## SYNOPSIS
Converts a security descriptor between different formats (Sddl, Base64, Binary, Raw).

## SYNTAX

```
Convert-SecurityDescriptor [-InputDescriptor] <Object> [-From <SecurityDescriptorFormat>]
 -To <SecurityDescriptorFormat> [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
This script provides functionality to convert a security descriptor from one format to another. 
Supported formats include:
- SDDL (Security Descriptor Definition Language)
- Base64
- Binary
- RawSecurityDescriptor
- CommonSecurityDescriptor (for folders and files)

Security descriptors are used to define access control and permissions for resources. 
This script is useful for scenarios where you need to translate security descriptors 
into a format compatible with a specific system or API.

## EXAMPLES

### EXAMPLE 1
```
# Convert a security descriptor from SDDL to Base64
Convert-SecurityDescriptor "O:BAG:BAD:(A;;FA;;;SY)" -From Sddl -To Base64
```

## PARAMETERS

### -InputDescriptor
The security descriptor value in the format specified by the \`From\` parameter.

```yaml
Type: Object
Parameter Sets: (All)
Aliases: Input

Required: True
Position: 1
Default value: None
Accept pipeline input: True (ByValue)
Accept wildcard characters: False
```

### -From
Specifies the format of the input security descriptor. 
Accepted values: Sddl, Base64, Binary, Raw, FolderAcl, FileAcl.

```yaml
Type: SecurityDescriptorFormat
Parameter Sets: (All)
Aliases: InputFormat
Accepted values: Sddl, Binary, Base64, Raw, FolderAcl, FileAcl

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -To
Specifies the desired format for the output security descriptor. 
Accepted values: Sddl, Base64, Binary, Raw, FolderAcl, FileAcl.

```yaml
Type: SecurityDescriptorFormat
Parameter Sets: (All)
Aliases: OutputFormat
Accepted values: Sddl, Binary, Base64, Raw, FolderAcl, FileAcl

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

### System.Security.AccessControl.RawSecurityDescriptor
### System.String
### System.Byte[]
## NOTES

## RELATED LINKS

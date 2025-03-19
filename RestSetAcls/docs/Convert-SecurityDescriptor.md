---
external help file: RestSetAcls-help.xml
Module Name: RestSetAcls
online version: https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format
https://learn.microsoft.com/en-us/powershell/scripting/overview
schema: 2.0.0
---

# Convert-SecurityDescriptor

## SYNOPSIS
Converts a security descriptor between different formats (Sddl, Base64, Binary, Raw).

## SYNTAX

```
Convert-SecurityDescriptor [-InputDescriptor] <Object> -From <SecurityDescriptorFormat>
 -To <SecurityDescriptorFormat> [-ProgressAction <ActionPreference>] [<CommonParameters>]
```

## DESCRIPTION
This script provides functionality to convert a security descriptor from one format to another. 
Supported formats include:
- \[SDDL (Security Descriptor Definition Language)\](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language)
- Base64
- Binary
- Raw

Security descriptors are used to define access control and permissions for resources. 
This script is useful for scenarios where you need to translate security descriptors 
into a format compatible with a specific system or API.

## EXAMPLES

### EXAMPLE 1
```
# Convert a security descriptor from SDDL to Base64
Convert-SecurityDescriptor -InputFormat Sddl -OutputFormat Base64 -InputValue "O:BAG:BAD:(A;;FA;;;SY)"
```

### EXAMPLE 2
```
# Convert a security descriptor from Binary to SDDL and save to a file
Convert-SecurityDescriptor -InputFormat Binary -OutputFormat Sddl -InputValue "010004..." -OutputFile "C:\Output.txt"
```

## PARAMETERS

### -InputDescriptor
{{ Fill InputDescriptor Description }}

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
{{ Fill From Description }}

```yaml
Type: SecurityDescriptorFormat
Parameter Sets: (All)
Aliases: InputFormat
Accepted values: Sddl, Binary, Base64, Raw

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -To
{{ Fill To Description }}

```yaml
Type: SecurityDescriptorFormat
Parameter Sets: (All)
Aliases: OutputFormat
Accepted values: Sddl, Binary, Base64, Raw

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

### System.Security.AccessControl.RawSecurityDescriptor
### System.String
### System.Byte[]
## NOTES
Author: \[Your Name\]
Date: \[Date\]
Version: 1.0

This script is part of the Azure Files Samples and is located at:
/q:/Azure/Storage/azure-files-samples/RestSetAcls/RestSetAcls/Convert.ps1

Ensure you have the necessary permissions to access and modify security descriptors 
before using this script.

## RELATED LINKS

[https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format
https://learn.microsoft.com/en-us/powershell/scripting/overview](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format
https://learn.microsoft.com/en-us/powershell/scripting/overview)

[https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format
https://learn.microsoft.com/en-us/powershell/scripting/overview]()


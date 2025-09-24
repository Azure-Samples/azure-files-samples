---
external help file: RestSetAcls-help.xml
Module Name: RestSetAcls
online version:
schema: 2.0.0
---

# Write-AccessMask

## SYNOPSIS
Displays a detailed, formatted view of a ACE's access mask.

## SYNTAX

```
Write-AccessMask [-accessMask] <Int32> [-indent <Int32>] [-ShowFullList] [-ProgressAction <ActionPreference>]
 [<CommonParameters>]
```

## DESCRIPTION
The Write-AccessMask function provides a comprehensive, human-readable display of an ACE's access mask.

## EXAMPLES

### EXAMPLE 1
```
Write-AccessMask 0x1200a9
```

## PARAMETERS

### -accessMask
Specifies the access mask to display.

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: True
Position: 1
Default value: 0
Accept pipeline input: False
Accept wildcard characters: False
```

### -indent
{{ Fill indent Description }}

```yaml
Type: Int32
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: 0
Accept pipeline input: False
Accept wildcard characters: False
```

### -ShowFullList
If specified, the function will display the full list of individual permission bits in addition to the basic
permissions.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: False
Position: Named
Default value: False
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

### System.Void
### This function outputs formatted text to the console and does not return any objects.
## NOTES

## RELATED LINKS

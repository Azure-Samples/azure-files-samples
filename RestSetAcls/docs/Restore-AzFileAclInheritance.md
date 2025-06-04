---
external help file: RestSetAcls-help.xml
Module Name: RestSetAcls
online version:
schema: 2.0.0
---

# Restore-AzFileAclInheritance

## SYNOPSIS
Applies ACL inheritance from parent folders to child files or folders.

## SYNTAX

### Recursive
```
Restore-AzFileAclInheritance -Context <IStorageContext> -FileShareName <String> [-Recursive] -Path <String>
 [-Reset] [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

### Single
```
Restore-AzFileAclInheritance -Context <IStorageContext> -FileShareName <String> -ParentPath <String>
 -ChildPath <String> [-Reset] [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
The `Restore-AzFileAclInheritance` cmdlet applies the inheritance of ACLs from a parent directory to a child file
or directory, or recursively to all items within a directory.
This is useful to propagate inheritable permissions
from a parent directory to its children, according to NTFS inheritance rules.
The function supports both single
file/directory and recursive modes.

## EXAMPLES

### EXAMPLE 1
```
Restore-AzFileAclInheritance -Context $context -FileShareName "myshare" -ParentPath "folder1" -ChildPath "folder1/file.txt"
```

Restores ACL inheritance from 'folder1' to 'folder1/file.txt'.

### EXAMPLE 2
```
Restore-AzFileAclInheritance -Context $context -FileShareName "myshare" -Recursive -Path "folder1"
```

Recursively restores ACL inheritance for all files and directories under 'folder1'.

## PARAMETERS

### -Context
Specifies the Azure storage context.
This is required to authenticate and interact with the Azure storage account.

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
Specifies the name of the Azure file share containing the files or directories.

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

### -ParentPath
Specifies the path to the parent directory from which to inherit ACLs (used in single mode).

```yaml
Type: String
Parameter Sets: Single
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -ChildPath
Specifies the path to the child file or directory to which inheritance will be restored (used in single mode).

```yaml
Type: String
Parameter Sets: Single
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Recursive
Switch to enable recursive mode, restoring inheritance for all files and directories under the specified path.

```yaml
Type: SwitchParameter
Parameter Sets: Recursive
Aliases:

Required: True
Position: Named
Default value: False
Accept pipeline input: False
Accept wildcard characters: False
```

### -Path
Specifies the root directory path for recursive inheritance restoration.
Used in recursive mode.

```yaml
Type: String
Parameter Sets: Recursive
Aliases:

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Reset
If specified, resets the ACL of the child file(s) or directory(ies) before restoring inheritance.
Used in both
single and recursive modes.
This option is useful when you want child items to only have permissions obtained
through inheritance, and want to discard any permissions that they currently hold.

```yaml
Type: SwitchParameter
Parameter Sets: (All)
Aliases:

Required: True
Position: Named
Default value: False
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

### System.Security.AccessControl.GenericSecurityDescriptor
### In single mode, returns the updated ACL for the child file or directory.
## NOTES

## RELATED LINKS

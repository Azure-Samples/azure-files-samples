---
external help file: RestSetAcls-help.xml
Module Name: RestSetAcls
online version:
schema: 2.0.0
---

# Add-AzFileAce

## SYNOPSIS
Adds an Access Control Entry (ACE) to an Azure file or directory's ACL.

## SYNTAX

### File
```
Add-AzFileAce -File <AzureStorageBase> -Type <AccessControlType> -Principal <String>
 -AccessRights <FileSystemRights> [-InheritanceFlags <InheritanceFlags>] [-PropagationFlags <PropagationFlags>]
 [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

### FilePath
```
Add-AzFileAce -Context <IStorageContext> -FileShareName <String> -FilePath <String> -Type <AccessControlType>
 -Principal <String> -AccessRights <FileSystemRights> [-InheritanceFlags <InheritanceFlags>]
 [-PropagationFlags <PropagationFlags>] [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm]
 [<CommonParameters>]
```

### Client
```
Add-AzFileAce [-Client <Object>] -Type <AccessControlType> -Principal <String> -AccessRights <FileSystemRights>
 [-InheritanceFlags <InheritanceFlags>] [-PropagationFlags <PropagationFlags>]
 [-ProgressAction <ActionPreference>] [-WhatIf] [-Confirm] [<CommonParameters>]
```

## DESCRIPTION
The \`Add-AzFileAce\` cmdlet adds a new Access Control Entry (ACE) to the Access Control List (ACL) of a specified
Azure file or directory.
This function supports adding both Allow and Deny ACEs with various access rights and
inheritance settings.
The function can work with SIDs, UPNs (User Principal Names), object IDs, and display names
for specifying the principal.

## EXAMPLES

### EXAMPLE 1
```
Add-AzFileAce -Context $context -FileShareName "myshare" -FilePath "folder1/file.txt" -Type Allow -Principal "user@domain.com" -AccessRights Read
```

Adds an Allow ACE granting Read access to the specified user for the file 'folder1/file.txt'.

### EXAMPLE 2
```
Add-AzFileAce -Context $context -FileShareName "myshare" -FilePath "folder1" -Type Allow -Principal "S-1-5-21-123456789-987654321-111111111-1001" -AccessRights FullControl
```

Adds an Allow ACE granting FullControl access to the user with the specified SID for the directory 'folder1'.
Since this is a directory, inheritance flags will default to 'ContainerInherit, ObjectInherit'.

### EXAMPLE 3
```
Add-AzFileAce -Context $context -FileShareName "myshare" -FilePath "folder1" -Type Deny -Principal "Domain Users" -AccessRights Write
```

Adds a Deny ACE that prevents Write access for the "Domain Users" group on the directory 'folder1'.

### EXAMPLE 4
```
Add-AzFileAce -Context $context -FileShareName "myshare" -FilePath "folder1/subfolder" -Type Allow -Principal "user@domain.com" -AccessRights ReadAndExecute -InheritanceFlags ObjectInherit -PropagationFlags InheritOnly
```

Adds an Allow ACE with custom inheritance settings that will only apply to files (not subdirectories) within 'folder1/subfolder'.

## PARAMETERS

### -File
Specifies the Azure storage file or directory to which the ACE will be added.

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
Specifies the name of the Azure file share containing the file or directory.

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
Specifies the path to the file or directory within the share to which the ACE will be added.

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
Specifies the Azure storage file or directory client with which to add the ACE.

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

### -Type
Specifies the type of access control.
Valid values are 'Allow' and 'Deny'.

```yaml
Type: AccessControlType
Parameter Sets: (All)
Aliases:
Accepted values: Allow, Deny

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -Principal
Specifies the principal (user or group) for which the ACE is being added.
This can be a SID, UPN, object ID, or display name.

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

### -AccessRights
Specifies the file system rights to grant or deny.
Valid values include standard .NET FileSystemRights such as
'FullControl', 'ReadAndExecute', 'Write', 'Read', 'Synchronize', etc.

```yaml
Type: FileSystemRights
Parameter Sets: (All)
Aliases:
Accepted values: ReadData, ListDirectory, WriteData, CreateFiles, AppendData, CreateDirectories, ReadExtendedAttributes, WriteExtendedAttributes, ExecuteFile, Traverse, DeleteSubdirectoriesAndFiles, ReadAttributes, WriteAttributes, Write, Delete, ReadPermissions, Read, ReadAndExecute, Modify, ChangePermissions, TakeOwnership, Synchronize, FullControl

Required: True
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -InheritanceFlags
Specifies how the ACE is inherited by child objects.
Valid values are 'None', 'ContainerInherit', 'ObjectInherit',
or a combination.
For directories, defaults to 'ContainerInherit, ObjectInherit' if not specified.

```yaml
Type: InheritanceFlags
Parameter Sets: (All)
Aliases:
Accepted values: None, ContainerInherit, ObjectInherit

Required: False
Position: Named
Default value: None
Accept pipeline input: False
Accept wildcard characters: False
```

### -PropagationFlags
Specifies how inheritance is propagated to child objects.
Valid values are 'None', 'InheritOnly', and 'NoPropagateInherit'.
Defaults to 'None'.

```yaml
Type: PropagationFlags
Parameter Sets: (All)
Aliases:
Accepted values: None, NoPropagateInherit, InheritOnly

Required: False
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
### Returns the file permission key associated with the updated ACL.
## NOTES

## RELATED LINKS

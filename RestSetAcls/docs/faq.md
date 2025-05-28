# Frequently Asked Questions

## Why does Set-AzFileAclRecursive display a warning non-standard inheritance rules?

You may have seen Set-AzFileAclRecursive issue a warning like the following.

```
(⚠) Warning: The SDDL string has non-standard inheritance rules.
It is recommended to set OI (Object Inherit) and CI (Container Inherit) on every permission.
This ensures that the permissions are inherited by files and folders created in the future.

   Current:     O:SYG:SYD:(A;OICIIO;0x1200a9;;;AU)
   Recommended: O:SYG:SYD:(A;OICI;0x1200a9;;;AU)

Do you want to continue with the current SDDL? [Y/n]:
```

This warning exists to help prevent common pitfalls around permission inheritance.

> [!NOTE]
> There are valid scenarios in which you may want to ignore this warning. For instance, if you explicitly want future files/folders to have different permissions than the present ones, you may choose to override the warning. However, it is recommended to spend some time understanding the implications of this before doing so.

Here are the inheritance flags that you can set on a permission (also known as an Access Control Entry, or ACE). See the [Microsoft ACE flags documentation](https://learn.microsoft.com/en-us/windows/win32/secauthz/ace-inheritance-flags) for more detailed information.

| Flag  | Name                 | Description                                                                                     |
|-------|----------------------|-------------------------------------------------------------------------------------------------|
| `OI`  | Object Inherit       | ACE will be inherited by files (objects) within the folder.                                     |
| `CI`  | Container Inherit    | ACE will be inherited by subfolders (containers) within the folder.                             |
| `IO`  | Inherit Only         | ACE does not apply to the folder itself, only to its children.                                  |
| `NP`  | No Propagate Inherit | ACE will be inherited only by direct children, not by further descendants (grandchildren, etc). |

`Set-AzFileAclRecursive` recommends setting Object Inherit (`OI`) and Container Inherit (`CI`) on all ACEs, as this will lead to the most predictable result, i.e. that all present and future files/folders will have the exact same permissions.

The following subsections explain why the other inheritance flags (`IO` and `NP`) are not recommended in most cases. These sections will assume some basic familiarity with the [Security Descriptor Definition Language (SDDL)](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format).

### Why is Inherit Only (IO) not recommended?

To answer this, let's consider the following folder structure:

```
folder
├── subfolder
└── file1.txt
```

Let's suppose you set this SDDL recursively on all items under the top-level folder: `O:SYG:SYD:(A;OICIIO;FA;;;AU)`. Let's take a moment to understand the SDDL:

- Owner is `SY` (`NT AUTHORITY\SYSTEM`)
- Group is `SY` (`NT AUTHORITY\SYSTEM`)
- The permissions has a single ACE:
    - It Allows access (`A`)
    - It has inheritance flags `OI` (Object Inherit), `CI` (Container Inherit), and `IO` (Inherit Only)
    - It grants the permission `FA` (File All, also called "Modify")
    - It applies to `AU` (`NT AUTHORITY\Authenticated Users`)

The result of applying this permission recursively across the above folder structure would be:

```
folder          O:SYG:SYD:(A;OICIIO;FA;;;AU)
├── subfolder   O:SYG:SYD:(A;OICIIO;FA;;;AU)
└── file1.txt   O:SYG:SYD:
```

In other words, `folder` and `folder/subfolder` get the SDDL you set (as expected), but `folder/file1.txt` gets `O:SYG:SYD:`, i.e. it has an empty DACL, meaning that no one can access the file. This might seem surprising at first, but it makes sense when considering the meaning of IO. IO means that the ACE does not apply to the item itself, but should only apply to its children. Since `file1.txt` is a file and files cannot have children, the ACE effectively applies to nothing -- so it can just as well be omitted.

Now, from this state, what happens if we create `folder/subfolder/file2.txt`? Well, `file2.txt` should inherit permissions from the parent `folder/subfolder` on creation. We get this:

```
folder             O:SYG:SYD:(A;OICIIO;FA;;;AU)
├── subfolder      O:SYG:SYD:(A;OICIIO;FA;;;AU)
|   └── file2.txt  O:SYG:SYD:(A;;FA;;;AU)
└── file1.txt      O:SYG:SYD:
```

In other words, we landed in a state where file permissions are inconsistent: `file1.txt` is accessible by nobody, and `file2.txt` is accessible by all Authenticated Users, which is everybody (see [Azure Files file-level permissions documentation](https://learn.microsoft.com/en-us/azure/storage/files/storage-files-identity-configure-file-level-permissions)).

### Why is No Propagate Inherit (NP) not recommended?

Let's take the same example again. Consider the following file structure:

```
folder
├── subfolder
└── file1.txt
```

Let's suppose you set this SDDL recursively on all items under the top-level folder: `O:SYG:SYD:(A;OICINP;FA;;;AU)`. Let's again take a moment to understand this permission:


- Owner is `SY` (`NT AUTHORITY\SYSTEM`)
- Group is `SY` (`NT AUTHORITY\SYSTEM`)
- The permissions has a single ACE:
    - It Allows access (`A`)
    - It has inheritance flags `OI` (Object Inherit), `CI` (Container Inherit), and `NP` (No Propagate Inherit)
    - It grants the permission `FA` (File All, also called "Modify")
    - It applies to `AU` (`NT AUTHORITY\Authenticated Users`)

The NP (No Propagate Inheritance) flag means the ACE is inherited by children but not by grandchildren.

The result of applying this permission recursively across the above folder structure would be:

```
folder         O:SYG:SYD:(A;OICINP;FA;;;AU)
├── subfolder  O:SYG:SYD:(A;OICINP;FA;;;AU)
└── file1.txt  O:SYG:SYD:(A;;FA;;;AU)
```

Here, `file1.txt` gets `(A;;FA;;;AU)` since OI, CI, and NP don't apply to files. Let's now create `folder/subfolder2`. It gets `(A;;FA;;;AU)`, since the permission is supposed to apply to children, but not to propagate to grandchildren.

```
folder                  O:SYG:SYD:(A;OICINP;FA;;;AU)
├── subfolder           O:SYG:SYD:(A;OICINP;FA;;;AU)
├── subfolder2          O:SYG:SYD:(A;;FA;;;AU)
└── file1.txt           O:SYG:SYD:(A;;FA;;;AU)
```

And if you create a file in `parent/child1/child2`:

```
folder                  O:SYG:SYD:(A;OICINP;FA;;;AU)
├── subfolder           O:SYG:SYD:(A;OICINP;FA;;;AU)
├── subfolder2          O:SYG:SYD:(A;;FA;;;AU)
|   └── file2.txt       O:SYG:SYD:
└── file.txt            O:SYG:SYD:(A;;FA;;;AU)
```

In this case, only SY can access `file.txt`, but no one can access `file2.txt`. So we end up with inconsistent permissions again.

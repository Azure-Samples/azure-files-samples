# Frequently Asked Questions

## Why does Set-AzFileAclRecursive display a warning about using only ObjectInherit (OI) and ContainerInherit (CI) flags?

Setting ObjectInherit (OI) and ContainerInherit (CI) flags on all permissions leads to a consistent state. But using other flags, like InheritOnly (IO) or NoPropagate (NP), can cause issues. To understand why it's not recommended to use IO and NP, let's look at some examples.

### Why is InheritOnly (IO) not recommended?

To answer this, let's consider the following folder structure:

```
folder
├── subfolder
└── file1.txt
```

Let's suppose you set this SDDL recursively on all items under the top-level folder: `O:SYG:SYD:(A;OICIIO;0x1200a9;;;AU)`. The result would be:

```
folder          O:SYG:SYD:(A;OICIIO;0x1200a9;;;AU)
├── subfolder   O:SYG:SYD:(A;OICIIO;0x1200a9;;;AU)
└── file1.txt   O:SYG:SYD:
```

In other words, `folder` and `folder/subfolder` get the SDDL you set (as expected), but `folder/file1.txt` gets `O:SYG:SYD:`, i.e. it has an empty DACL, meaning that no one can access the file. This is because IO means that the permission (aka ACE) does not apply to the item itself, but should only apply to its children. But files can't have children, so effectively, the permission applies to nothing -- so it can just as well be omitted.

Now, from this state, what happens if we create `folder/subfolder/file2.txt`? Well, `file2.txt` should inherit permissions from the parent `folder/subfolder`. We get this:

```
folder             O:SYG:SYD:(A;OICIIO;0x1200a9;;;AU)
├── subfolder      O:SYG:SYD:(A;OICIIO;0x1200a9;;;AU)
|   └── file2.txt  O:SYG:SYD:(A;;0x1200a9;;;AU)
└── file1.txt      O:SYG:SYD:
```

In other words, we landed in a state where file permissions are inconsistent: `file1.txt` is accessible by nobody, and `file2.txt` is accessible by everybody (AU means all Authenticated Users, see [Azure Files file-level permissions documentation](https://learn.microsoft.com/en-us/azure/storage/files/storage-files-identity-configure-file-level-permissions)).


### Why is NoPropagate (NP) not recommended?

Let's take the same example again. Consider the following file structure:

```
folder
├── subfolder
└── file1.txt
```

Let's suppose you set this SDDL recursively on all items under the top-level folder: `O:SYG:SYD:(A;OICINP;0x1200a9;;;AU)`. The NP (No Propagate) flag means the ACE is inherited by children but not by grandchildren. The result would be:

```
folder         O:SYG:SYD:(A;OICINP;0x1200a9;;;AU)
├── subfolder  O:SYG:SYD:(A;OICINP;0x1200a9;;;AU)
└── file1.txt  O:SYG:SYD:(A;;0x1200a9;;;AU)
```

Here, `file1.txt` gets `(A;;0x1200a9;;;AU)` since OI, CI, and NP don't apply to files. Let's now create `folder/subfolder2`. It gets `(A;ID;0x1200a9;;;AU)`, since the permission is supposed to apply to children, but not to propagate to grandchildren.

```
folder                  O:SYG:SYD:(A;OICINP;0x1200a9;;;AU)
├── subfolder           O:SYG:SYD:(A;OICINP;0x1200a9;;;AU)
├── subfolder2          O:SYG:SYD:(A;;0x1200a9;;;AU)
└── file1.txt           O:SYG:SYD:(A;;0x1200a9;;;AU)
```

And if you create a file in `parent/child1/child2`:

```
folder                  O:SYG:SYD:(A;OICINP;0x1200a9;;;AU)
├── subfolder           O:SYG:SYD:(A;OICINP;0x1200a9;;;AU)
├── subfolder2          O:SYG:SYD:(A;;0x1200a9;;;AU)
|   └── file2.txt       O:SYG:SYD:
└── file.txt            O:SYG:SYD:(A;;0x1200a9;;;AU)
```

In this case, only SY can access `file.txt`, but no one can access `file2.txt`. This inconsistency can also lead to confusion.

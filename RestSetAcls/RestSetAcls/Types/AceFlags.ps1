[Flags()]
enum AutoInheritFlags {
    # The new discretionary access control list (DACL) contains ACEs inherited from the DACL of ParentDescriptor, as
    # well as any explicit ACEs specified in the DACL of CreatorDescriptor. If this flag is not set, the new DACL does
    # not inherit ACEs.
    SEF_DACL_AUTO_INHERIT = 0x01

    # The new system access control list (SACL) contains ACEs inherited from the SACL of ParentDescriptor, as well as
    # any explicit ACEs specified in the SACL of CreatorDescriptor. If this flag is not set, the new SACL does not
    # inherit ACEs.
    SEF_SACL_AUTO_INHERIT = 0x02

    # CreatorDescriptor is the default descriptor for the type of object specified by ObjectType. As such,
    # CreatorDescriptor is ignored if ParentDescriptor has any object-specific ACEs for the type of object specified by
    # the ObjectType parameter. If no such ACEs are inherited, CreatorDescriptor is handled as though this flag were not
    # specified.
    SEF_DEFAULT_DESCRIPTOR_FOR_OBJECT = 0x04

    # The function does not perform privilege checking. If the SEF_AVOID_OWNER_CHECK flag is also set, the Token
    # parameter can be NULL. This flag is useful while implementing automatic inheritance to avoid checking privileges
    # on each child updated.
    SEF_AVOID_PRIVILEGE_CHECK = 0x08

    # The function does not check the validity of the owner in the resultant NewDescriptor as described in Remarks
    # below. If the SEF_AVOID_PRIVILEGE_CHECK flag is also set, the Token parameter can be NULL.
    SEF_AVOID_OWNER_CHECK = 0x10

    # The owner of NewDescriptor defaults to the owner from ParentDescriptor. If not set, the owner of NewDescriptor
    # defaults to the owner of the token specified by the Token parameter. The owner of the token is specified in the
    # token itself. In either case, if the CreatorDescriptor parameter is not NULL, the NewDescriptor owner is set to
    # the owner from CreatorDescriptor.
    SEF_DEFAULT_OWNER_FROM_PARENT = 0x20 

    # The group of NewDescriptor defaults to the group from ParentDescriptor. If not set, the group of NewDescriptor
    # defaults to the group of the token specified by the Token parameter. The group of the token is specified in the
    # token itself. In either case, if the CreatorDescriptor parameter is not NULL, the NewDescriptor group is set to
    # the group from CreatorDescriptor.
    SEF_DEFAULT_GROUP_FROM_PARENT = 0x40

    # When this flag is set, the mandatory label ACE in CreatorDescriptor is not used to create a mandatory label ACE
    # in NewDescriptor. Instead, a new SYSTEM_MANDATORY_LABEL_ACE with an access mask of 
    # SYSTEM_MANDATORY_LABEL_NO_WRITE_UP and the SID from the token's integrity SID is added to NewDescriptor.
    SEF_MACL_NO_WRITE_UP = 0x100

    # When this flag is set, the mandatory label ACE in CreatorDescriptor is not used to create a mandatory label ACE
    # in NewDescriptor. Instead, a new SYSTEM_MANDATORY_LABEL_ACE with an access mask of
    # SYSTEM_MANDATORY_LABEL_NO_READ_UP and the SID from the token's integrity SID is added to NewDescriptor.
    SEF_MACL_NO_READ_UP = 0x200

    # When this flag is set, the mandatory label ACE in CreatorDescriptor is not used to create a mandatory label ACE
    # in NewDescriptor. Instead, a new SYSTEM_MANDATORY_LABEL_ACE with an access mask of
    # SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP and the SID from the token's integrity SID is added to NewDescriptor.
    SEF_MACL_NO_EXECUTE_UP = 0x400

    # Any restrictions specified by the ParentDescriptor that would limit the caller's ability to specify a DACL in the
    # CreatorDescriptor are ignored.
    SEF_AVOID_OWNER_RESTRICTION = 0x1000
}
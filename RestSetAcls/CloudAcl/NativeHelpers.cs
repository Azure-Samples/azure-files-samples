using System;
using System.Runtime.InteropServices;
using System.Security.AccessControl;

namespace CloudAcl
{
    public static class NativeMethods
    {
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CreatePrivateObjectSecurityEx(
            IntPtr ParentDescriptor,
            IntPtr CreatorDescriptor,
            out IntPtr NewDescriptor,
            IntPtr ObjectType,
            [MarshalAs(UnmanagedType.Bool)] bool IsContainerObject,
            uint AutoInheritFlags,
            IntPtr Token,
            ref GenericMapping GenericMapping);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DestroyPrivateObjectSecurity(ref IntPtr ObjectDescriptor);

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern int GetSecurityDescriptorLength(IntPtr pSecurityDescriptor);
    }

    [Flags]
    enum AutoInheritFlags
    {
        /// <summary>
        /// The new discretionary access control list (DACL) contains ACEs inherited from the DACL of ParentDescriptor, as
        /// well as any explicit ACEs specified in the DACL of CreatorDescriptor. If this flag is not set, the new DACL does
        /// not inherit ACEs.
        /// </summary>
        SEF_DACL_AUTO_INHERIT = 0x01,

        /// <summary>
        /// The new system access control list (SACL) contains ACEs inherited from the SACL of ParentDescriptor, as well as
        /// any explicit ACEs specified in the SACL of CreatorDescriptor. If this flag is not set, the new SACL does not
        /// inherit ACEs.
        /// </summary>
        SEF_SACL_AUTO_INHERIT = 0x02,

        /// <summary>
        /// CreatorDescriptor is the default descriptor for the type of object specified by ObjectType. As such,
        /// CreatorDescriptor is ignored if ParentDescriptor has any object-specific ACEs for the type of object specified by
        /// the ObjectType parameter. If no such ACEs are inherited, CreatorDescriptor is handled as though this flag were not
        /// specified.
        /// </summary>
        SEF_DEFAULT_DESCRIPTOR_FOR_OBJECT = 0x04,

        /// <summary>
        /// The function does not perform privilege checking. If the SEF_AVOID_OWNER_CHECK flag is also set, the Token
        /// parameter can be NULL. This flag is useful while implementing automatic inheritance to avoid checking privileges
        /// on each child updated.
        /// </summary>
        SEF_AVOID_PRIVILEGE_CHECK = 0x08,

        /// <summary>
        /// The function does not check the validity of the owner in the resultant NewDescriptor as described in Remarks
        /// below. If the SEF_AVOID_PRIVILEGE_CHECK flag is also set, the Token parameter can be NULL.
        /// </summary>
        SEF_AVOID_OWNER_CHECK = 0x10,

        /// <summary>
        /// The owner of NewDescriptor defaults to the owner from ParentDescriptor. If not set, the owner of NewDescriptor
        /// defaults to the owner of the token specified by the Token parameter. The owner of the token is specified in the
        /// token itself. In either case, if the CreatorDescriptor parameter is not NULL, the NewDescriptor owner is set to
        /// the owner from CreatorDescriptor.
        /// </summary>
        SEF_DEFAULT_OWNER_FROM_PARENT = 0x20,

        /// <summary>
        /// The group of NewDescriptor defaults to the group from ParentDescriptor. If not set, the group of NewDescriptor
        /// defaults to the group of the token specified by the Token parameter. The group of the token is specified in the
        /// token itself. In either case, if the CreatorDescriptor parameter is not NULL, the NewDescriptor group is set to
        /// the group from CreatorDescriptor.
        /// </summary>
        SEF_DEFAULT_GROUP_FROM_PARENT = 0x40,

        /// <summary>
        /// When this flag is set, the mandatory label ACE in CreatorDescriptor is not used to create a mandatory label ACE
        /// in NewDescriptor. Instead, a new SYSTEM_MANDATORY_LABEL_ACE with an access mask of 
        /// SYSTEM_MANDATORY_LABEL_NO_WRITE_UP and the SID from the token's integrity SID is added to NewDescriptor.
        /// </summary>
        SEF_MACL_NO_WRITE_UP = 0x100,

        /// <summary>
        /// When this flag is set, the mandatory label ACE in CreatorDescriptor is not used to create a mandatory label ACE
        /// in NewDescriptor. Instead, a new SYSTEM_MANDATORY_LABEL_ACE with an access mask of
        /// SYSTEM_MANDATORY_LABEL_NO_READ_UP and the SID from the token's integrity SID is added to NewDescriptor.
        /// </summary>
        SEF_MACL_NO_READ_UP = 0x200,

        /// <summary>
        /// When this flag is set, the mandatory label ACE in CreatorDescriptor is not used to create a mandatory label ACE
        /// in NewDescriptor. Instead, a new SYSTEM_MANDATORY_LABEL_ACE with an access mask of
        /// SYSTEM_MANDATORY_LABEL_NO_EXECUTE_UP and the SID from the token's integrity SID is added to NewDescriptor.
        /// </summary>
        SEF_MACL_NO_EXECUTE_UP = 0x400,

        /// <summary>
        /// Any restrictions specified by the ParentDescriptor that would limit the caller's ability to specify a DACL in the
        /// CreatorDescriptor are ignored.
        /// </summary>
        SEF_AVOID_OWNER_RESTRICTION = 0x1000
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct GenericMapping
    {
        public uint GenericRead;
        public uint GenericWrite;
        public uint GenericExecute;
        public uint GenericAll;
    }

    public static class NativeHelpers
    {
        // TODO: compute these from FileSystemRights instead of hardcoding...
        public static readonly GenericMapping FileGenericMapping = new GenericMapping
        {
            GenericRead = 1179785,
            GenericWrite = 1179926,
            GenericExecute = 1179808,
            GenericAll = 2032127
        };

        public static IntPtr MarshalSecurityDescriptor(CommonSecurityDescriptor sd)
        {
            if (sd == null)
            {
                return IntPtr.Zero;
            }

            int length = sd.BinaryLength;
            byte[] bytes = new byte[length];
            sd.GetBinaryForm(bytes, 0);
            IntPtr intPtr = Marshal.AllocHGlobal(length);
            Marshal.Copy(bytes, 0, intPtr, length);
            return intPtr;
        }

        public static CommonSecurityDescriptor UnmarshalSecurityDescriptor(IntPtr sdPtr, bool isDirectory)
        {
            if (sdPtr == IntPtr.Zero)
            {
                return null;
            }

            int length = NativeMethods.GetSecurityDescriptorLength(sdPtr);
            byte[] bytes = new byte[length];
            Marshal.Copy(sdPtr, bytes, 0, length);
            return new CommonSecurityDescriptor(isDirectory, isDS: false, bytes, 0);
        }
    }
}

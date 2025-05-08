using System;
using System.Runtime.InteropServices;
using System.Security.AccessControl;

namespace CloudAcl
{
    internal static class InheritanceHelpers
    {

        public static CommonSecurityDescriptor ComputeInheritance(CommonSecurityDescriptor parentSd, CommonSecurityDescriptor childSd)
        {
            // Child SD is not allowed to be null by this implementation.
            // This simplifying assumption is made to avoid having to deal with the token,
            // and is good enough for our use-case of computing inheritance on existing ACLs.
            if (childSd == null)
            {
                throw new NotImplementedException("Support for null child SD is not implemented yet.");
            }

            bool isDirectory = childSd.IsContainer;

            IntPtr parentSdIntPtr = IntPtr.Zero;
            IntPtr childSdIntPtr = IntPtr.Zero;
            IntPtr newDescriptorIntPtr = IntPtr.Zero;

            try
            {
                parentSdIntPtr = NativeHelpers.MarshalSecurityDescriptor(parentSd);
                childSdIntPtr = NativeHelpers.MarshalSecurityDescriptor(childSd);

                // Since we only deal with file system objects, we will never have object GUIDs.
                // We can safely set the object type to null.
                IntPtr objectTypeIntPtr = IntPtr.Zero;

                // We don't want to run this with a token, so set AVOID_PRIVILEGE_CHECK and AVOID_OWNER_CHECK.
                AutoInheritFlags autoInheritFlags = AutoInheritFlags.SEF_AVOID_OWNER_CHECK | AutoInheritFlags.SEF_AVOID_OWNER_CHECK;

                // We want to opt in to ACL inheritance, so set the SEF_DACL_AUTO_INHERIT and SEF_SACL_AUTO_INHERIT flags if the DACL/SACL are not protected.
                if ((childSd.ControlFlags & ControlFlags.DiscretionaryAclProtected) != 0)
                {
                    autoInheritFlags |= AutoInheritFlags.SEF_DACL_AUTO_INHERIT;
                }

                if ((childSd.ControlFlags & ControlFlags.SystemAclProtected) != 0)
                {
                    autoInheritFlags |= AutoInheritFlags.SEF_SACL_AUTO_INHERIT;
                }

                // We do not allow CreatorDescriptor to be null in this implementation, so according to
                // MS-DTYP 2.5.3.4, the token will never be used. Hence we can safely set it to null.
                // This also makes things easier for us -- one less thing to marshal.
                // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/0f0c6ffc-f57d-47f8-a6c8-63889e874e24
                IntPtr token = IntPtr.Zero;

                // Build generic mapping object. Since this module only deals with file system objects,
                // we can hard-code the file generic rights mapping.
                // https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-generic_mapping  
                GenericMapping genericMapping = NativeHelpers.FileGenericMapping;

                bool success = NativeMethods.CreatePrivateObjectSecurityEx(
                    parentSdIntPtr,
                    childSdIntPtr,
                    out newDescriptorIntPtr,
                    objectTypeIntPtr,
                    IsContainerObject: isDirectory,
                    (uint)autoInheritFlags,
                    token,
                    ref genericMapping);

                return NativeHelpers.UnmarshalSecurityDescriptor(newDescriptorIntPtr, isDirectory);
            }
            finally
            {
                if (parentSdIntPtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(parentSdIntPtr);
                }
                if (childSdIntPtr != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(childSdIntPtr);
                }
                if (newDescriptorIntPtr != IntPtr.Zero)
                {
                    bool success = NativeMethods.DestroyPrivateObjectSecurity(ref newDescriptorIntPtr);
                    if (!success)
                    {
                        throw new Exception("Destroying new descriptor failed");
                    }
                }
            }
        }
    }
}

using System;
using System.Security.AccessControl;

using Azure;
using Azure.Storage.Files.Shares;
using Azure.Storage.Files.Shares.Models;
using Azure.Storage.Files.Shares.Specialized;

namespace CloudAcl
{
    internal class RestHelpers
    {
        public static Pageable<ShareFileItem> GetFilesAndDirectories(ShareDirectoryClient client)
        {
            var options = new ShareDirectoryGetFilesAndDirectoriesOptions
            {
                IncludeExtendedInfo = true,
                Traits = ShareFileTraits.All
            };

            return client.GetFilesAndDirectories(options);
        }

        public static string GetDirectoryPermissionKey(ShareDirectoryClient client)
        {
            return client.GetProperties().Value.SmbProperties.FilePermissionKey;
        }

        public static CommonSecurityDescriptor GetDirectoryPermission(ShareDirectoryClient client)
        {
            var key = GetDirectoryPermissionKey(client);
            return GetPermission(client.GetParentShareClient(), key, isDirectory: true);
        }

        public static CommonSecurityDescriptor GetFilePermission(ShareFileClient client)
        {
            var key = client.GetProperties().Value.SmbProperties.FilePermissionKey;
            return GetPermission(client.GetParentShareClient(), key, isDirectory: false);
        }

        public static CommonSecurityDescriptor GetPermission(ShareClient client, string key, bool isDirectory)
        {
            var base64 = client.GetPermission(key, FilePermissionFormat.Binary).Value.Permission;
            var bytes = Convert.FromBase64String(base64);
            return new CommonSecurityDescriptor(isDirectory, isDS: false, bytes, 0);
        }

        public static string SetDirectoryPermission(ShareDirectoryClient client, CommonSecurityDescriptor permission)
        {
            if (!permission.IsContainer)
            {
                throw new ArgumentException("Expected the permission on a folder to have IsContainer set to true");
            }

            var base64 = GetBase64(permission);
            if (base64.Length < 8192)
            {
                var options = new ShareDirectorySetHttpHeadersOptions
                {
                    FilePermission = new ShareFilePermission
                    {
                        Permission = base64,
                        PermissionFormat = FilePermissionFormat.Binary
                    }
                };

                return client.SetHttpHeaders(options).Value.SmbProperties.FilePermissionKey;
            }
            else
            {
                var key = CreatePermission(client.GetParentShareClient(), base64);
                return SetDirectoryPermissionKey(client, key);
            }
        }

        public static string SetDirectoryPermissionKey(ShareDirectoryClient client, string key)
        {
            var options = new ShareDirectorySetHttpHeadersOptions
            {
                SmbProperties = new FileSmbProperties
                {
                    FilePermissionKey = key,
                }
            };

            return client.SetHttpHeaders(options).Value.SmbProperties.FilePermissionKey;
        }

        public static string SetFilePermission(ShareFileClient client, CommonSecurityDescriptor permission)
        {
            if (permission.IsContainer)
            {
                throw new ArgumentException("Expected the permission on a file to have IsContainer set to false");
            }

            var base64 = GetBase64(permission);
            if (base64.Length < 8192)
            {
                var options = new ShareFileSetHttpHeadersOptions
                {
                    FilePermission = new ShareFilePermission
                    {
                        Permission = base64,
                        PermissionFormat = FilePermissionFormat.Binary
                    }
                };

                return client.SetHttpHeaders(options).Value.SmbProperties.FilePermissionKey;
            }
            else
            {
                var key = CreatePermission(client.GetParentShareClient(), base64);
                return SetFilePermissionKey(client, key);
            }
        }

        public static string SetFilePermissionKey(ShareFileClient client, string key)
        {
            var options = new ShareFileSetHttpHeadersOptions
            {
                SmbProperties = new FileSmbProperties
                {
                    FilePermissionKey = key,
                }
            };

            return client.SetHttpHeaders(options).Value.SmbProperties.FilePermissionKey;
        }

        public static string CreatePermission(ShareClient client, CommonSecurityDescriptor permission)
        {
            return CreatePermission(client, GetBase64(permission));
        }

        public static string CreatePermission(ShareClient client, string base64)
        {
            var options = new ShareFilePermission
            {
                Permission = base64,
                PermissionFormat = FilePermissionFormat.Binary
            };

            return client.CreatePermission(options).Value.FilePermissionKey;
        }

        private static string GetBase64(CommonSecurityDescriptor permission)
        {
            var length = permission.BinaryLength;
            var bytes = new byte[length];
            permission.GetBinaryForm(bytes, 0);
            return Convert.ToBase64String(bytes);
        }
    }
}

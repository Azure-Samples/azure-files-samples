using System.Collections.Generic;
using System.Management.Automation;
using System.Security.AccessControl;
using Azure.Storage.Files.Shares;
using Azure.Storage.Files.Shares.Models;
using Azure.Storage.Files.Shares.Specialized;

namespace CloudAcl
{
    [Cmdlet(VerbsData.Restore, "AzFileAclInheritanceRecursive")]
    [OutputType(typeof(FavoriteStuff))]
    public class RestoreAzFileAclInheritanceRecursive : PSCmdlet
    {
        [Parameter(Mandatory = true)]
        public ShareDirectoryClient DirectoryClient { get; set; }

        [Parameter(Mandatory = true)]
        public bool PassThru { get; set; }

        protected class WorkItem
        {
            public bool IsDirectory;
            public ShareDirectoryClient DirectoryClient { get; set; }
            public ShareFileClient FileClient { get; set; }
            public CommonSecurityDescriptor DirectoryPermission { get; set; }
        }

        // This method gets called once for each cmdlet in the pipeline when the pipeline starts executing
        protected override void BeginProcessing()
        {
            WriteVerbose("Started");
        }

        // This method will be called for each input received from the pipeline to this cmdlet; if no input is received, this method is not called
        protected override void ProcessRecord()
        {
            var initialWorkItem = new WorkItem
            {
                IsDirectory = true,
                DirectoryClient = this.DirectoryClient,
                FileClient = null,
                DirectoryPermission = RestHelpers.GetDirectoryPermission(this.DirectoryClient),
            };

            var threadPool = new WorkStackThreadPool<WorkItem>(workerCount: 5, initialWorkItem, ProcessWorkItem);
            threadPool.Start();
            threadPool.AwaitCompletion();
        }

        protected IEnumerable<WorkItem> ProcessWorkItem(WorkItem workItem)
        {
            List<WorkItem> foldersToExploreLater = new List<WorkItem>();

            var parentClient = workItem.DirectoryClient;
            var shareClient = parentClient.GetParentShareClient();

            var options = new ShareDirectoryGetFilesAndDirectoriesOptions
            {
                IncludeExtendedInfo = true,
                Traits = ShareFileTraits.All
            };

            foreach (var child in parentClient.GetFilesAndDirectories(options))
            {
                // Gather parent and child permissions
                var parentPermission = workItem.DirectoryPermission;
                var permissionKey = child.PermissionKey;
                var childPermission = RestHelpers.GetPermission(shareClient, child.PermissionKey, child.IsDirectory);

                // Compute inheritance
                CommonSecurityDescriptor newPermission = InheritanceHelpers.ComputeInheritance(parentPermission, childPermission);

                // Set new permission on child
                // TODO: double check the permission key we get back matches what we set.
                if (!child.IsDirectory)
                {
                    var fileClient = parentClient.GetFileClient(child.Name);
                    RestHelpers.SetFilePermission(fileClient, newPermission);
                }
                else
                {
                    var folderClient = parentClient.GetSubdirectoryClient(child.Name);
                    RestHelpers.SetDirectoryPermission(folderClient, newPermission);

                    foldersToExploreLater.Add(new WorkItem
                    {
                        DirectoryClient = parentClient.GetSubdirectoryClient(child.Name),
                        DirectoryPermission = newPermission
                    });
                }
            }

            return foldersToExploreLater;
        }

        

        // This method will be called once at the end of pipeline execution; if no input is received, this method is not called
        protected override void EndProcessing()
        {
            WriteVerbose("End!");
        }
    }

    public class FavoriteStuff
    {
        public int FavoriteNumber { get; set; }
        public string FavoritePet { get; set; }
    }
}

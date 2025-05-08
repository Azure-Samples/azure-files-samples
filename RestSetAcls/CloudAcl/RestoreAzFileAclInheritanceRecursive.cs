using System;
using System.Collections.Generic;
using System.Management.Automation;
using System.Security.AccessControl;
using Azure.Storage.Files.Shares;
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



        protected abstract class WorkItem { }

        // A DirectoryOpenWorkItem says that we should list the contents of a directory, and add each child to the
        // stack as FileInherit or DirectoryInheritAndOpen work
        protected class DirectoryOpenWorkItem : WorkItem
        {
            public ShareDirectoryClient DirectoryClient { get; set; }
        }

        // An ApplyInheritanceToFolderAndRecurseWorkItem says to compute inheritance from the parent permission onto
        // the folder's permission, and then recurse on the folder contents, and add each child as an
        // ApplyInheritanceToFileWorkItem or ApplyInheritanceToFolderAndRecurseWorkItem to the stack
        protected class DirectoryInheritAndOpenWorkItem : WorkItem
        {
            public ShareDirectoryClient DirectoryClient { get; set; }

            public string DirectoryPermissionKey { get; set; }

            public CommonSecurityDescriptor ParentPermission { get; set; }
        }

        // An ApplyInheritanceToFileWorkItem says to compute inheritance from the parent permission onto the file's permission
        protected class FileInheritWorkItem : WorkItem
        {
            public ShareFileClient FileClient { get; set; }

            public string FilePermissionKey { get; set; }

            public CommonSecurityDescriptor ParentPermission { get; set; }
        }

        // This method gets called once for each cmdlet in the pipeline when the pipeline starts executing
        protected override void BeginProcessing()
        {
            WriteVerbose("Started");
        }

        // This method will be called for each input received from the pipeline to this cmdlet; if no input is received, this method is not called
        protected override void ProcessRecord()
        {
            var initialWorkItem = new DirectoryOpenWorkItem
            {
                DirectoryClient = this.DirectoryClient,
            };

            var threadPool = new WorkStackThreadPool<WorkItem>(workerCount: 5, initialWorkItem, ProcessWorkItem);
            threadPool.Start();
            threadPool.AwaitCompletion();
        }

        protected IEnumerable<WorkItem> ProcessWorkItem(WorkItem workItem)
        {
            List<WorkItem> foldersToExploreLater = new List<WorkItem>();

            if (workItem is DirectoryOpenWorkItem dowi)
            {
                CommonSecurityDescriptor directoryPermission = RestHelpers.GetDirectoryPermission(dowi.DirectoryClient);
                return GetChildWorkItems(dowi.DirectoryClient, directoryPermission);
            }
            else if (workItem is DirectoryInheritAndOpenWorkItem diaowi)
            {
                // Step 1: inherit
                CommonSecurityDescriptor oldPermission = RestHelpers.GetPermission(
                    diaowi.DirectoryClient.GetParentShareClient(),
                    diaowi.DirectoryPermissionKey,
                    isDirectory: true);

                CommonSecurityDescriptor newPermission = InheritanceHelpers.ComputeInheritance(diaowi.ParentPermission, oldPermission);

                RestHelpers.SetDirectoryPermission(diaowi.DirectoryClient, newPermission);

                WriteObject(diaowi.DirectoryClient.Path); // log that it's done

                // Step 2: open 
                return GetChildWorkItems(diaowi.DirectoryClient, newPermission);
            }
            else if (workItem is FileInheritWorkItem fiwi)
            {
                CommonSecurityDescriptor filePermission = RestHelpers.GetPermission(
                    fiwi.FileClient.GetParentShareClient(),
                    fiwi.FilePermissionKey,
                    isDirectory: false);

                CommonSecurityDescriptor newPermission = InheritanceHelpers.ComputeInheritance(fiwi.ParentPermission, filePermission);

                RestHelpers.SetFilePermission(fiwi.FileClient, newPermission);

                WriteObject(fiwi.FileClient.Path); // log that it's done

                return new List<WorkItem>();
            }
            else
            {
                throw new ArgumentException("WorkItem is not of a known type");
            }
        }

        private IEnumerable<WorkItem> GetChildWorkItems(ShareDirectoryClient directoryClient, CommonSecurityDescriptor directoryPermission)
        {
            foreach (var item in RestHelpers.GetFilesAndDirectories(directoryClient))
            {
                if (item.IsDirectory)
                {
                    yield return new DirectoryInheritAndOpenWorkItem
                    {
                        DirectoryClient = directoryClient.GetSubdirectoryClient(item.Name),
                        DirectoryPermissionKey = item.PermissionKey,
                        ParentPermission = directoryPermission
                    };
                }
                else
                {
                    yield return new FileInheritWorkItem
                    {
                        FileClient = directoryClient.GetFileClient(item.Name),
                        FilePermissionKey = item.PermissionKey,
                        ParentPermission = directoryPermission
                    };
                }
            }
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

// See https://aka.ms/new-console-template for more information
using Azure;
using Azure.Storage.Files.Shares;
using Azure.Storage.Files.Shares.Models;
using System.Collections.Concurrent;
using System.IO;

internal class Downloader
{
    string shareNameOrUri;
    string sourcePath;
    bool isSourceADirectory;
    string connectionString;
    string sas;
    bool isSASMode = true;
    string downloadPath;
    ConcurrentQueue<string> fileQueue = new ConcurrentQueue<string>();
    ShareClient share;
    long isListFilesComplete = 0;
    SemaphoreSlim semaphore;

    public Downloader(
        string ShareNameOrUri,
        string SourcePath,
        bool IsSourceADirectory,
        string ConnectionString,
        string SAS,
        string DownloadPath,
        int ThreadCount
        )
    {
        this.shareNameOrUri = ShareNameOrUri;
        this.sourcePath = SourcePath;
        this.isSourceADirectory = IsSourceADirectory;
        this.connectionString = ConnectionString;
        this.sas = SAS;
        this.downloadPath = DownloadPath;
        this.semaphore = new SemaphoreSlim(ThreadCount);

        if (String.IsNullOrWhiteSpace(ConnectionString) && String.IsNullOrWhiteSpace(SAS))
        {
            throw new ArgumentNullException("Both connection string and sas cannot be empty");
        }

        if (String.IsNullOrWhiteSpace(SAS))
        {
            this.isSASMode = false;
            share = new ShareClient(connectionString, shareNameOrUri);
        }
        else
        {
            this.isSASMode = true;
            shareNameOrUri = shareNameOrUri.TrimEnd('/') + "/";
            share = new ShareClient(new Uri(shareNameOrUri), new AzureSasCredential(SAS));
        }

    }

    public async Task ListFiles()
    {
        Console.WriteLine("Starting ListFiles");

        char[] pathSeparators = { '\\', '/' };
        string[] parentDirectories = sourcePath.Split(pathSeparators, StringSplitOptions.RemoveEmptyEntries);
        string currentPath = downloadPath;

        // Loop through each parent directory and create it if it doesn't exist
        int parentDirIndex = 0;
        foreach (var directory in parentDirectories)
        {
            parentDirIndex++;
            if (!isSourceADirectory && parentDirIndex == parentDirectories.Length)
            {
                break;
            }

            currentPath = Path.Combine(currentPath, directory);

            // If the directory does not exist, create it
            if (!Directory.Exists(currentPath))
            {
                Directory.CreateDirectory(currentPath);
                Console.WriteLine("Created directory: " + currentPath);
            }
        }

        if (isSourceADirectory)
        {
            Queue<ShareDirectoryClient> directoryQueue = new Queue<ShareDirectoryClient>();
            if (string.IsNullOrWhiteSpace(sourcePath))
            {
                directoryQueue.Enqueue(share.GetRootDirectoryClient());
            }
            else
            {
                if (isSASMode)
                {
                    Uri directoryUri = new Uri(shareNameOrUri + sourcePath);
                    Console.WriteLine($"Directory Uri: {directoryUri.AbsoluteUri}");
                    directoryQueue.Enqueue(new ShareDirectoryClient(directoryUri, new AzureSasCredential(sas)));
                }
                else
                {
                    directoryQueue.Enqueue(new ShareDirectoryClient(connectionString, shareNameOrUri, sourcePath));
                }
            }

            do
            {
                ShareDirectoryClient directoryClient = directoryQueue.Dequeue();
                Console.WriteLine("Listing files from: " + directoryClient.Name);
                await foreach (ShareFileItem item in directoryClient.GetFilesAndDirectoriesAsync())
                {
                    if (item.IsDirectory)
                    {
                        ShareDirectoryClient subdirItem = directoryClient.GetSubdirectoryClient(item.Name);
                        //create directory locally
                        Directory.CreateDirectory(Path.Combine(downloadPath, subdirItem.Path));
                        directoryQueue.Enqueue(subdirItem);
                    }
                    else
                    {
                        fileQueue.Enqueue(directoryClient.Path + "/" + item.Name);
                    }
                }
            } while (directoryQueue.Count > 0);
        }
        else
        {
            fileQueue.Enqueue(sourcePath);
        }
        Interlocked.Increment(ref isListFilesComplete);
    }

    async Task DownloadFile(string path)
    {
        Console.WriteLine("Starting Download File for " + path);
        try
        {
            ShareFileClient file = null;
            if (isSASMode)
            {
                Uri fileUri = new Uri(shareNameOrUri + path);
                Console.WriteLine($"File Uri: {fileUri.AbsoluteUri}");
                file = new ShareFileClient(fileUri, new AzureSasCredential(sas));
            }
            else
            {
                file = new ShareFileClient(connectionString, shareNameOrUri, path);
            }
            ShareFileProperties properties = await file.GetPropertiesAsync();
            ShareFileGetRangeListOptions listOptions = new ShareFileGetRangeListOptions();
            ShareFileDownloadOptions downloadOptions = new ShareFileDownloadOptions();
            ShareFileDownloadInfo downloadInfo = await file.DownloadAsync();
            using (FileStream stream = File.Open(Path.Combine(downloadPath, path), FileMode.OpenOrCreate))
            {
                await downloadInfo.Content.CopyToAsync(stream);
                await stream.FlushAsync();
                stream.Close();
            }

            Console.WriteLine($"Download succeeded for file: {path}");

            //long startOffset = 0;
            //long endOffset = 0;
            //long listRangeSize = 1024l * 1024l * 1024l * 1024l;
            //using (FileStream writeStream = File.OpenWrite(Path.Combine(downloadPath, path)))
            //{
            //    while (startOffset < properties.ContentLength)
            //    {
            //        startOffset = endOffset;
            //        endOffset = Math.Min(endOffset + listRangeSize, properties.ContentLength);
            //        if (startOffset < endOffset)
            //        {
            //            Console.WriteLine($"Calling ListRanges for {path} for range: {startOffset}-{endOffset}");
            //            listOptions.Range = new Azure.HttpRange(startOffset, endOffset - startOffset);
            //            await file.GetRangeListAsync(listOptions);

            //            listOptions.Range = new Azure.HttpRange(0, 1024);
            //            ShareFileRangeInfo ranges = await file.GetRangeListAsync(listOptions);
            //            if (ranges != null)
            //            {
            //                int count = ranges.Ranges.Count();
            //                Console.WriteLine($"Got {count} ranges for {path}");
            //                foreach (Azure.HttpRange range in ranges.Ranges)
            //                {
            //                    Console.WriteLine($"Downloading {range.Offset} offset and {range.Length} bytes for {path}");
            //                    writeStream.Position = range.Offset;
            //                    downloadOptions.Range = range;
            //                    ShareFileDownloadInfo data = await file.DownloadAsync(downloadOptions);
            //                    data.Content.CopyTo(writeStream);
            //                    writeStream.Flush();
            //                }
            //            }
            //        }
            //        else
            //        {
            //            break;
            //        }
            //    }
            //}
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Download file failed for {path}. " + ex);
        }
        finally
        {
            semaphore.Release();
        }
    }

    public async Task CreateFiles()
    {
        Console.WriteLine("Starting CreateFiles");
        List<Task> fileDownloadTasks = new List<Task>();
        TimeSpan semaphoreMaxWaitTime = TimeSpan.FromSeconds(5);
        while (!fileQueue.IsEmpty || Interlocked.Read(ref isListFilesComplete) == 0)
        {
            while (!fileQueue.IsEmpty)
            {
                string filePath = "";
                semaphore.Wait(semaphoreMaxWaitTime);
                try
                {
                    if (fileQueue.TryDequeue(out filePath))
                    {
                        fileDownloadTasks.Add(DownloadFile(filePath));
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Download file failed for {filePath}. " + ex);
                }
            }

            Console.WriteLine("Will sleep for 5 seconds waiting for next available thread or next file");
            Thread.Sleep(5000);
        }

        Console.WriteLine("Waiting for all downloads to finish");
        await Task.WhenAll(fileDownloadTasks.ToArray());
        Console.WriteLine("All downloads complete");
    }
}

internal class Program
{
    private static void Main(string[] args)
    {
        string ShareName = "";
        string ShareUri = "";
        string SourcePath = "";
        bool IsSourceADirectory = true;
        string ConnectionString = "";
        string SAS = "";
        string DownloadPath = "";
        int ThreadCount = 64;

        foreach (string arg in args)
        {
            string param = arg.Split(":", 2)[0];
            string value = arg.Split(":", 2)[1];

            if (param.ToLower() == "sharename")
            {
                ShareName = value;
            }
            if (param.ToLower() == "shareuri")
            {
                ShareUri = value;
            }
            if (param.ToLower() == "sourcepath")
            {
                SourcePath = value;
            }
            if (param.ToLower() == "issourceadirectory")
            {
                IsSourceADirectory = bool.Parse(value);
            }
            if (param.ToLower() == "connectionstring")
            {
                ConnectionString = value;
            }
            if (param.ToLower() == "downloadpath")
            {
                DownloadPath = value;
            }
            if (param.ToLower() == "threadcount")
            {
                ThreadCount = int.Parse(value);
            }
            if (param.ToLower() == "sas")
            {
                SAS = value;
            }
        }

        if ((String.IsNullOrWhiteSpace(ShareName) && String.IsNullOrWhiteSpace(ShareUri))
            || (String.IsNullOrWhiteSpace(ConnectionString) && String.IsNullOrWhiteSpace(SAS))
            || (!String.IsNullOrWhiteSpace(ConnectionString) && String.IsNullOrWhiteSpace(ShareName))
            || (!String.IsNullOrWhiteSpace(SAS) && String.IsNullOrWhiteSpace(ShareUri))
            || ThreadCount <= 0)
        {
            Console.WriteLine(@"Insufficient parameters::

CustomFileDownloader: This tool will help you download files from a file share where some files may have invalid content and request may fail.

Params:
shareName (required with connection string): string
shareUri (required with SAS): string
isSourceADirectory (optional: default = true): boolean (true/false)
sourcePath (optional: default = ""): string
connectionString or SAS (required): string
downloadPath (optional: default = ""): string
threadCount (optional: default = 64): int

Here is a sample command for Windows:
CustomFileDownloader.exe shareName:yourshare sourcePath:DirInFileShare1/DirInFileShare2 isSourceADirectory:true connectionString:AccountName=sourceaccountname;AccountKey=XXXXXXXXXXXX;EndpointSuffix=core.windows.net;DefaultEndpointsProtocol=https; threadCount:64

CustomFileDownloader.exe shareUri:https://sourceaccountname.file.core.windows.net/yourshare sourcePath:DirInFileShare1/DirInFileShare2 isSourceADirectory:true SAS:XXXXXXXXXXXXXXXXXXX threadCount:64

Here is a sample command for Linux:
dotnet CustomFileDownloader shareName:yourshare sourcePath:DirInFileShare1/DirInFileShare2 isSourceADirectory:true connectionString:AccountName=sourceaccountname;AccountKey=XXXXXXXXXXXX;EndpointSuffix=core.windows.net;DefaultEndpointsProtocol=https; downloadPath:/home/yourpath threadCount:64

dotnet CustomFileDownloader shareUri:https://sourceaccountname.file.core.windows.net/yourshare sourcePath:DirInFileShare1/DirInFileShare2 isSourceADirectory:true SAS:XXXXXXXXXXXXXXXXXXX threadCount:64
");
            return;
        }

        Downloader downloader = new Downloader(String.IsNullOrWhiteSpace(ShareName) ? ShareUri : ShareName, 
            SourcePath, IsSourceADirectory, ConnectionString, SAS, DownloadPath, ThreadCount);
        Task listFilesTask = downloader.ListFiles();
        Task createFilesTask = downloader.CreateFiles();

        Task.WaitAll(listFilesTask, createFilesTask);

        Console.WriteLine("Done");
    }
}
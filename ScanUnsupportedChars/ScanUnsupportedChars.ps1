<#
 .SYNOPSIS
    Copyright (c) Microsoft Corporation.  All rights reserved.

    This is a Powershell script to scan / scan plus rename the files/directories that are not supported by Azure File Sync.

 .DESCRIPTION

    Scan provided share to get the file names not suported by AFS. The script can be used to:
       a. Scan file/directories name that have unsupported chars.
       b. Rename (remove or replace) such unsupported chars from names.
       c. Move such file/directories out of the share to a desired location.

   Note - this script might report false positive i.e. a file name is supported but this script might say its not supported.
          This is by design to keep the script simple and allow customer to rename such files proactively.

   Version 5.2
   Last Modified Date: November 3, 2021

   Note: Please open powershell in full screen mode to avoid output truncation.

   How to execute this script:

   Open PS in admin and full screen mode and run following command:

   Set-ExecutionPolicy Unrestricted
   #Run of your command as per the examples shared below.
   Set-ExecutionPolicy AllSigned

 .PARAMETER SharePath
     Path of the share to scan, it could be local folder like D:\share, D:\ or a remote share like \\server\share
 .PARAMETER RenameItems
     Switch if you want to rename the item as it scan. If you wont want to rename, do not provide this switch.
 .PARAMETER ReplacementString
     The 'character' that would replace the unsupported char in the file names. Default is '' (empty string)
 .PARAMETER CsvPath
     Directory path for output CSV formatted files. If not specified, the output would be printed on the PS console.
     The output would be in UnsupportedCharsDetails.csv, LongPathFileNames.csv and FixedFileNames.csv
 .PARAMETER DestinationPath
     Switch if you want to Copy invalid Files to a seperate location. This location can be a local folder C:\share or remote share like \\server\share
     This does not work in combination with RenameItems
 .PARAMETER RoboCopyOptions
     Arguments which should be passed directly to the Robocopy Process /SEC for setting ACL's in remote Share for example.
     Through this Arguments it can be controlled if Files should be moved / copied and/or overriden

 .EXAMPLE
     .\ScanUnsupportedChars.ps1  -SharePath  <LocalShareRootPath>
     Just to see all files with unsupported chars on console window with unsupported char replaced by 'empty string'

 .EXAMPLE
     .\ScanUnsupportedChars.ps1  -SharePath  <LocalShareRootPath> -ReplacementString "YourOwnString"
     Just to see all files with unsupported chars on console window with unsupported char replaced by 'YourOwnString'

 .EXAMPLE
     .\ScanUnsupportedChars.ps1  -SharePath  <LocalShareRootPath> -RenameItems -ReplacementString "YourOwnString"
     To replace the unsupported char with your own string.

 .EXAMPLE
     .\ScanUnsupportedChars.ps1  -SharePath  <LocalShareRootPath> -RenameItems
     To remove the unsupported char from file paths

 .EXAMPLE
     .\ScanUnsupportedChars.ps1  -SharePath  <LocalShareRootPath> -CsvPath <DirectoryPathForCSVFiles>
     To dump the script output to CSV files

 .EXAMPLE
     .\ScanUnsupportedChars.ps1  -SharePath  E:\SyncShare
      This would scan the provided SyncShare for the unsupported file names.

 .EXAMPLE
     .\ScanUnsupportedChars.ps1  -SharePath  E:\SyncShare -RenameItems
      This would scan and rename the unsupported file names in the provided sync share.
      This would replace the unsupported char with empty string.

 .EXAMPLE
      .\ScanUnsupportedChars.ps1  -SharePath  E:\SyncShare -RenameItems -ReplacementString "-"
      This would scan and rename the unsupported file names in the provided sync share.
      This would replace the unsupported char with "-".

 .EXAMPLE
      .\ScanUnsupportedChars.ps1  -SharePath  \\server\SyncShare 
        This would scan the provided remote SyncShare for the unsupported file names.

 .EXAMPLE
      .\ScanUnsupportedChars.ps1  -SharePath  \\server\SyncShare  -RenameItems
      This would scan and rename the unsupported file names for the provided remote SyncShare.
      This would replace the unsupported char with empty string.

 .EXAMPLE
      .\ScanUnsupportedChars.ps1  -SharePath  \\server\SyncShare  -RenameItems -ReplacementString "-"
      This would scan and rename the unsupported file names for the provided remote SyncShare.
      This would replace the unsupported char with "-".

 .EXAMPLE
      .\ScanUnsupportedChars.ps1  -SharePath  \\server\SyncShare  -CsvPath "C:\temp"
      This would scan unsupported file names for the provided remote SyncShare and puts the output in the
      CSV formatted files in the output directory.

 .EXAMPLE
      .\ScanUnsupportedChars.ps1  -SharePath  \\server\SyncShare  -DestinationPath "\\some\server" -RoboCopyOptions '/SEC'
      This would scan unsupported file names for the provided remote SyncShare and puts the output in the Destination Path

.NOTES
     Script Limitations:
     1. If file name have only the unsupported chars in the name and provided ReplacementString is empty string,
        the fixed file name would be empty string, hence cannot be renamed into.
     2. If after replacing the unsupported chars, two or more files gets the same fixed name, the script would not
        be able to rename them due to name collision.
#>

[CmdletBinding()]
Param(
   [Parameter(Mandatory=$True,Position=1, HelpMessage = "Share path")]
   [string]$SharePath,
   [Parameter(Mandatory=$False,Position=2, HelpMessage = "Rename Items as it scan")]
   [switch]$RenameItems,
   [Parameter(Mandatory=$False,Position=3, HelpMessage = "Replacement string for the unsupported char")]
   [string]$ReplacementString,
   [Parameter(Mandatory=$False,Position=4, HelpMessage = "Directory for CSV formatted file output")]
   [string]$CsvPath,
   [Parameter(Mandatory=$False,Position=5, HelpMessage = "Destination path to Copy/Move Items to (acts as switch)")]
   [string]$DestinationPath,
   [Parameter(Mandatory=$False,Position=6, HelpMessage = "Arguments which should be passed to RoboCopy")]
   [string]$RoboCopyOptions
)

$ErrorActionPreference="Stop"

$assemblies = ("System.Net.Http")
Add-Type -ReferencedAssemblies $assemblies -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using ft = System.Runtime.InteropServices.ComTypes;
using System.ComponentModel;
using System.Text;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;

public class InvalidCharInfo
{
    public int Code { get; set; }
    public int Position { get; set; }
    public string Message { get; set; }
    public InvalidCharInfo()
    {
        Code = 0;
        Position = 0;
        Message = string.Empty;
    }
}

public enum FixedEntryType
{
    FOLDER,
    FILE
}

public class FixedFileNameEntry
{
    public string OriginalFilePath { get; set; }
    public string FixedFileName { get; set; }
    public FixedEntryType Type { get; set; }

    public FixedFileNameEntry()
    {
        OriginalFilePath = string.Empty;
        FixedFileName = string.Empty;
        Type = FixedEntryType.FILE;
    }
}

public class ListFiles
{
    static IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
    static int FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
    private const int FILE_ATTRIBUTE_NORMAL = 0x80;
    const int MAX_PATH = 260;
    public int ItemCount = 0;
    private const int AzureMaxFilePathLengthLimit = 2048;

    public string ReplacementString;
    public int SharePathLength;

    public List<string> FilePathTooLongList = new List<string>();
    public List<FixedFileNameEntry> FilesWithInvalidCharsFixedName = new List<FixedFileNameEntry>();
    public List<FixedFileNameEntry> FilesFailedToRename = new List<FixedFileNameEntry>();

    // Unsupported chars blocked list
    private static List<int> disallowedChars = new List<int>();

    // Chars may not work in combination with others
    private static List<int> combinationFailureChars = new List<int>();

    public Dictionary<string, InvalidCharInfo> InvalidCharFileInformation = new Dictionary<string, InvalidCharInfo>();

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct WIN32_FIND_DATA
    {
        internal FileAttributes dwFileAttributes;
        internal ft.FILETIME ftCreationTime;
        internal ft.FILETIME ftLastAccessTime;
        internal ft.FILETIME ftLastWriteTime;
        internal int nFileSizeHigh;
        internal int nFileSizeLow;
        internal int dwReserved0;
        internal int dwReserved1;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MAX_PATH)]
        internal string cFileName;
        // not using this
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 14)]
        internal string cAlternate;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern IntPtr FindFirstFile(string lpFileName, out WIN32_FIND_DATA lpFindFileData);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    internal static extern bool FindNextFile(IntPtr hFindFile, out WIN32_FIND_DATA lpFindFileData);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool FindClose(IntPtr hFindFile);

    public ListFiles()
    {
        disallowedChars.Add(0x0000002A); // 0x0000002A  = '*'
        disallowedChars.Add(0x00000022); // 0x00000022  = quotation mark
        disallowedChars.Add(0x0000003F); // 0x0000003F  = '?'
        disallowedChars.Add(0x0000003E); // 0x0000003E  = '>'
        disallowedChars.Add(0x0000003C); // 0x0000003C  = '<'
        disallowedChars.Add(0x0000003A); // 0x0000003A  = ':'
        disallowedChars.Add(0x0000007C); // 0x0000007C  = '|'
        disallowedChars.Add(0x0000002F); // 0x0000002F  = '/'
        disallowedChars.Add(0x0000005C); // 0x0000005C  = '\'
        disallowedChars.Add(0x0000007F); // 0x0000007F  = del delete

        // Unsupported control chars
        disallowedChars.Add(0x00000081); // high octet preset)
        disallowedChars.Add(0x0000008D); // ri reverse line feed
        disallowedChars.Add(0x0000008F); // ss3 single shift three
        disallowedChars.Add(0x00000090); // dcs device control string
        disallowedChars.Add(0x0000009D); // osc operating system command

        // Following chars may not work with combination of other chars
        combinationFailureChars.Add(0x1FFFE);
        combinationFailureChars.Add(0x1FFFF);
        combinationFailureChars.Add(0x2FFFE);
        combinationFailureChars.Add(0x2FFFF);
        combinationFailureChars.Add(0x3FFFE);
        combinationFailureChars.Add(0x3FFFF);
        combinationFailureChars.Add(0x4FFFE);
        combinationFailureChars.Add(0x4FFFF);
        combinationFailureChars.Add(0x5FFFE);
        combinationFailureChars.Add(0x5FFFF);
        combinationFailureChars.Add(0x6FFFE);
        combinationFailureChars.Add(0x6FFFF);
        combinationFailureChars.Add(0x7FFFE);
        combinationFailureChars.Add(0x7FFFF);
        combinationFailureChars.Add(0x8FFFE);
        combinationFailureChars.Add(0x8FFFF);
        combinationFailureChars.Add(0x9FFFE);
        combinationFailureChars.Add(0x9FFFF);
        combinationFailureChars.Add(0xAFFFE);
        combinationFailureChars.Add(0xAFFFF);
        combinationFailureChars.Add(0xBFFFE);
        combinationFailureChars.Add(0xBFFFF);
        combinationFailureChars.Add(0xCFFFE);
        combinationFailureChars.Add(0xCFFFF);
        combinationFailureChars.Add(0xDFFFE);
        combinationFailureChars.Add(0xDFFFF);
        combinationFailureChars.Add(0xEFFFE);
        combinationFailureChars.Add(0xEFFFF);
        combinationFailureChars.Add(0xFFFFE);
        combinationFailureChars.Add(0xFFFFF);
        combinationFailureChars.Add(0x10FFFE);
        combinationFailureChars.Add(0x10FFFF);
    }

    public static bool IsExcluded(string itemName)
    {
        bool excluded = itemName.ToLower().Contains(@"recycle.bin") ||
                        itemName.ToLower().Contains(@":\system volume information");

        if (excluded)
        {
            Console.WriteLine("Excluded from checks directory path : " + itemName);
            return excluded;
        }

        return excluded;
    }

    // Function validates the validity for the char supported by azure files
    // Chars outside the range as validated by this function are invalid/control chars
    public static int IsSupported(string charString)
    {
        int CodePoint = Char.ConvertToUtf32(charString, 0);
        if ((0x1F <= CodePoint && CodePoint <= 0xD7FF) ||
            (0xE000 <= CodePoint && CodePoint <= 0xF8FF) ||
            (0xF900 <= CodePoint && CodePoint <= 0xFDCF) ||  // FDD0 not supported
            (0xFDD1 <= CodePoint && CodePoint <= 0xFDDC) ||  // FDDD not supported
            (0xFDDE <= CodePoint && CodePoint <= 0xFFFD) ||
            (0x10000 <= CodePoint && CodePoint <= 0x4FFFD) ||
            (0x50000 <= CodePoint && CodePoint <= 0x8FFFD) ||
            (0x90000 <= CodePoint && CodePoint <= 0xCFFFD) ||
            (0xD0000 <= CodePoint && CodePoint <= 0x10FFFD))
        {
            // The character is withing the range of valid characters supported by XStore,
            // hence it is supported, unless it is part of the exception list
            if (disallowedChars.Contains(CodePoint))
            {
                Console.WriteLine("Unsupported char code point: " + CodePoint);
                return CodePoint;
            }
            else if ((0x80 <= CodePoint && CodePoint <= 0x9F) ||
                     (0xFDD0 <= CodePoint && CodePoint <= 0xFFFF) ||
                     combinationFailureChars.Contains(CodePoint))
            {
                // These are supported codepoints, but they might not work in combination of other chars
                // The char combination that fails the REST call for the item could be anywhere in the path
                // so instead of making this scanner more complicated to identify which combination might work
                // we are over cautious and remove these from file/directory names
                Console.WriteLine("Code point might not work in combination of other chars: " + CodePoint);
                return CodePoint;
            }
            else
            {
                return 0;
            }
        }
        else
        {
            // The character is outside the range of valid characters supported by XStore
            Console.WriteLine("Not in range - Unsupported char code point: " + CodePoint);
            return CodePoint;
        }
    }

    public string ValidateAndReturnFixedPath(string filePath)
    {
        ItemCount++;

        int filePathLength = filePath.Length - SharePathLength;
        int fileNameIndex = filePath.LastIndexOf(@"\");

        if (filePathLength > AzureMaxFilePathLengthLimit)
        {
            FilePathTooLongList.Add(filePath);
            return string.Empty;
        }

        string fileName = filePath.Substring(4);  // remove first four char of '\\?\'

        if (fileName.Contains(@"\"))
        {
            fileName = fileName.Substring(fileName.LastIndexOf(@"\") + 1);
        }

        if (string.IsNullOrEmpty(fileName))
        {
            Console.WriteLine("**** Empty File name ****");
            return string.Empty;
        }

        var fileNameArray = fileName.ToCharArray();
        char prevChar = 'a';

        StringBuilder newFileName = new StringBuilder();
        int charPosition = fileNameIndex;
        bool foundUnsupportedChar = false;

        foreach (var Character in fileNameArray)
        {
            charPosition++;

            int Code = 0;
            InvalidCharInfo info = new InvalidCharInfo();
            info.Position = charPosition;
            info.Message = "Contains unsupported character";

            if (Char.IsHighSurrogate(Character) && fileName.Length == 1)
            {
                Code = -1;
                info.Message = "Invalid surrogate char found in the file name";
            }
            else if (!Char.IsHighSurrogate(prevChar) && Char.IsHighSurrogate(Character))
            {
                // Valid case
            }
            else if (!Char.IsHighSurrogate(prevChar) && Char.IsLowSurrogate(Character))
            {
                Code = -1;
                info.Message = "Found a low surrogate character without a preceding high surrogate character";
            }
            else if (Char.IsHighSurrogate(prevChar) && !Char.IsLowSurrogate(Character))
            {
                Code = -1;
                info.Message = "Invalid surrogate pair found in the file name";
            }
            else if (Char.IsHighSurrogate(prevChar) && Char.IsLowSurrogate(Character))
            {
                char[] charArray = { prevChar, Character };
                Code = IsSupported(new string(charArray));
            }
            else
            {
                char[] charArray = { Character };
                Code = IsSupported(new string(charArray));
            }

            if (Code != 0)
            {
                foundUnsupportedChar = true;
                info.Code = Code;

                // Remove the previous high surrogate char
                if (Char.IsHighSurrogate(prevChar) && newFileName.Length > 1)
                {
                    newFileName.Remove(newFileName.Length - 1, 1);
                }

                // Keeps information about only one unsupported char
                InvalidCharFileInformation[filePath] = info;
                newFileName.Append(ReplacementString);
            }
            else
            {
                newFileName.Append(Character);
            }

            prevChar = Character;
        }

        if (foundUnsupportedChar)
        {
            // Convert from string builder to string
            string updatedFileName = newFileName.ToString();

            if (updatedFileName.EndsWith(@".")) // Filenames with trailing dots are not supported
            {
                updatedFileName = updatedFileName.TrimEnd(new char [] {'.'}) + ReplacementString;
            }

            return filePath.Substring(0, fileNameIndex + 1) + updatedFileName.ToString();
        }
        else if (fileName.EndsWith(@".")) // Filenames with trailing dots are not supported
        {
            InvalidCharInfo info = new InvalidCharInfo();

            info.Code = 0x0000002E;
            info.Position = filePath.Length;
            info.Message = "File name ends with '.'";

            InvalidCharFileInformation.Add(filePath, info);
            fileName = fileName.TrimEnd(new char [] {'.'});
            return filePath.Substring(0, fileNameIndex + 1) + fileName + ReplacementString;
        }
        else
        {
            return string.Empty;
        }
    }

    // Assume directoryPath passed in is already prefixed with \\?\
    public void FindFilesAndDirs(string directoryPath)
    {
        SharePathLength = directoryPath.Length;
        WIN32_FIND_DATA findData;

        if (directoryPath.EndsWith(@"\"))
        {
            directoryPath += @"*";
        }
        else
        {
            directoryPath += @"\*";
        }

        IntPtr findHandle = FindFirstFile(directoryPath, out findData);

        // Remove the '*' from the path
        directoryPath = directoryPath.Substring(0, directoryPath.Length - 1);

        if (findHandle != INVALID_HANDLE_VALUE)
        {
            bool found = false;

            do
            {
                string currentFileName = findData.cFileName;

                // if this is a directory, find its contents
                if (((int)findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
                {
                    string volumeRootExclusionName = @":\" + currentFileName;

                    if (currentFileName != "." && currentFileName != ".." && !IsExcluded(volumeRootExclusionName))
                    {
                        string dirPath = Path.Combine(directoryPath, currentFileName);

                        try
                        {
                            FindFilesAndDirs(dirPath);
                            string fixedDirName = ValidateAndReturnFixedPath(dirPath);

                            if (!string.IsNullOrEmpty(fixedDirName))
                            {
                                FixedFileNameEntry entry = new FixedFileNameEntry();
                                entry.OriginalFilePath = dirPath;
                                entry.FixedFileName = fixedDirName;
                                entry.Type = FixedEntryType.FOLDER;
                                FilesWithInvalidCharsFixedName.Add(entry);
                            }
                        }
                        catch(Exception ex)
                        {
                            Console.WriteLine("Failed to process directory :" + dirPath + " Exception: " + ex);
                        }
                    }
                }
                else // it's a file, add it to the results
                {
                    string filePath = Path.Combine(directoryPath, currentFileName);
                    string fixedFileName = ValidateAndReturnFixedPath(filePath);

                    if (!string.IsNullOrEmpty(fixedFileName))
                    {
                        FixedFileNameEntry entry = new FixedFileNameEntry();;
                        entry.OriginalFilePath = filePath;
                        entry.FixedFileName = fixedFileName;
                        FilesWithInvalidCharsFixedName.Add(entry);
                    }
                }

                // find next
                found = FindNextFile(findHandle, out findData);
            }
            while (found);

            // close the find handle
            FindClose(findHandle);
        }
        else
        {
            string errorMessage = string.Empty;
            int gle = Marshal.GetLastWin32Error();

            if (gle != 0)
            {
                try
                {
                    errorMessage = new Win32Exception(gle).Message;
                }
                catch
                {
                }
            }

            if (string.IsNullOrEmpty(errorMessage))
            {
                if (gle == 0)
                {
                    gle = -1;
                }

                errorMessage = "Unknown error: " + gle;
            }

            Console.WriteLine(" Could not open directory :" + directoryPath + " Error Message " + errorMessage);
        }

        if (ItemCount % 1000 == 1)
        {
            Console.WriteLine("Processed Item count: " + ItemCount);
        }
    }

    public bool IsHandledThroughFolder(string path)
    {
        return FilesWithInvalidCharsFixedName.Any(
            item => Path.GetDirectoryName(path)
                    .StartsWith(item.OriginalFilePath)
                && item.Type == FixedEntryType.FOLDER);
    }

    public void RenameItems()
    {
        foreach(var item in FilesWithInvalidCharsFixedName)
        {
            try
            {
                FileAttributes attr = File.GetAttributes(item.OriginalFilePath);

                if ((attr & FileAttributes.Directory) == FileAttributes.Directory)
                {
                    System.IO.Directory.Move(item.OriginalFilePath, item.FixedFileName);
                }
                else
                {
                    System.IO.File.Move(item.OriginalFilePath, item.FixedFileName);
                }
            }
            catch(Exception ex)
            {
                FilesFailedToRename.Add(item);

                Console.WriteLine("Exception " + ex.Message);
                Console.WriteLine("Failed to rename {0} to {1}", item.OriginalFilePath, item.FixedFileName);
            }
        }
    }
}
"@
# Main

if ($SharePath.EndsWith("\"))
{
    $SharePath = $SharePath.Substring(0, $SharePath.Length - 1);
}

if ($SharePath.EndsWith(":"))
{
    $SharePath += "\";
}

if($SharePath.StartsWith("\\?\") -or $SharePath.StartsWith("\\?\unc\"))
{
    # We are good
}
elseif($SharePath.StartsWith("\\"))
{
    # Its smb server path, make sure it start with \\?\unc\
    $SharePath = "\\?\unc\" + $SharePath.Substring(2);
}
else
{
    $SharePath = "\\?\" + $SharePath;
}

Write-Host "Normalized Share path: " $SharePath -ForegroundColor Green

if ([string]::IsNullOrEmpty($ReplacementString) -or $ReplacementString.Contains(' ') -or $ReplacementString.Contains('.'))
{
    Write-Host "ReplacementString not provided, using default as ''" -ForegroundColor Yellow
    $ReplacementString = ""
}
else
{
    Write-Host "Provided ReplacementString: " $ReplacementString
}

if (-not ([string]::IsNullOrEmpty($CsvPath)))
{
    if (-not (Test-Path -Path $CsvPath -PathType Container))
    {
        Write-Error "Specified output directory does not exist or its not a directory: $CsvPath" -ErrorAction Stop
    }
}

$UnsupportedCharsDetailsFileName = $CsvPath + "\\UnsupportedCharsDetails.csv"
$LongPathFileNamesFileName = $CsvPath + "\\LongPathFileNames.csv"
$FixedFileNamesFileName = $CsvPath + "\\FixedFileNames.csv"

$listFile = New-Object ListFiles

$listFile.ReplacementString = $ReplacementString
$listFile.SharePathLength = $SharePath.Length

$listFile.FindFilesAndDirs($SharePath)

$UnSupportedList = $listFile.InvalidCharFileInformation;

Write-Host "==================== Scan Results Started ========================="

Write-Host "Files/Directories with unsupported characters, total count: " $UnSupportedList.Count -ForegroundColor Yellow

if($UnSupportedList.Count -eq 0)
{
    Write-Host "No unsupported char detected" -ForegroundColor Green
}
else
{
    if ([string]::IsNullOrEmpty($CsvPath))
    {
        [bool] $setTableWidth = $true
        [int] $hostWindowWidth = $host.UI.RawUI.WindowSize.Width
        [int] $codewidth = 12;

        if($hostWindowWidth -lt $codewidth)
        {
            $setTableWidth = $false;
        }

        $hostWindowWidth = $hostWindowWidth - $codewidth;

        [int] $messageWidth = [int] $hostWindowWidth/3;

        if($messageWidth -le 0)
        {
            $setTableWidth = $false;
        }

        [int] $fileNameWidth = $hostWindowWidth - $messageWidth;

        if($fileNameWidth -le 0)
        {
            $setTableWidth = $false;
        }

        if($setTableWidth)
        {
            $UnSupportedList | Format-Table @{Label= "FileName";    Expression={ $_.Key}; Width=$fileNameWidth },`
                                            @{Label= "Message";     Expression={ $_.Value.Message}; Width=$messageWidth},`
                                            @{Label= "Code";        Expression={ $_.Value.Code}; Width=$codewidth},`
                                            @{Label= "Position";    Expression={ $_.Value.Position}; Width=$codewidth} -Wrap -AutoSize
        }
        else
        {
            $UnSupportedList | Format-Table @{Label= "FileName";    Expression={ $_.Key}; },`
                                            @{Label= "Message";     Expression={ $_.Value.Message}; },`
                                            @{Label= "Code";        Expression={ $_.Value.Code}; },`
                                            @{Label= "Position";    Expression={ $_.Value.Position}; } -Wrap -AutoSize
        }
    }
    else
    {
        foreach ($item in $UnSupportedList.GetEnumerator())
        {
            $fileObject = [PSCustomObject]@{
                                FileName = $item.Key
                                Message = $item.Value.Message
                                Code = $item.Value.Code
                                Position = $item.Value.Position
                                }

            Export-Csv -InputObject $fileObject -Path $UnsupportedCharsDetailsFileName -Append -NoTypeInformation -Force
        }

        Write-Host "CSV file generated at: $UnsupportedCharsDetailsFileName"  -ForegroundColor Green
    }
}

Write-Host "========================== File Path too long start==========================================" -ForegroundColor Yellow

$FilePathTooLongList = $listFile.FilePathTooLongList;

Write-Host "Files/Directories having path length > 2048 chars (current limit for azure files), total count: " $FilePathTooLongList.Count -ForegroundColor Yellow

if($FilePathTooLongList.Count -gt 0)
{
    if ([string]::IsNullOrEmpty($CsvPath))
    {
        ForEach ($File in $FilePathTooLongList)
        {
            Write-Host $File -ForegroundColor Red
        }
    }
    else
    {
        $FilePathTooLongList | Export-Csv -Path $LongPathFileNamesFileName -Append -NoTypeInformation -Force

        Write-Host "CSV file generated at: $LongPathFileNamesFileName" -ForegroundColor Green
    }
}

Write-Host "========================== File Path too long end ==========================================" -ForegroundColor Yellow

$FilesWithInvalidCharsFixedName = $listFile.FilesWithInvalidCharsFixedName;

Write-Host "Files/Directories with unsupported characters, total count: " $UnSupportedList.Count 
Write-Host "Number of Files/Directories which can be fixed using this script: " $FilesWithInvalidCharsFixedName.Count

if ($FilesWithInvalidCharsFixedName.Count -gt 0)
{
    if ($RenameItems)
    {
        $listFile.RenameItems()

        Write-Host "***************************Items rename table start***************************" -ForegroundColor Yellow

        if($setTableWidth)
        {
            $FilesWithInvalidCharsFixedName | Format-Table @{Label= "OriginalFilePath";    Expression={ $_.OriginalFilePath}; Width=$fileNameWidth },`
                                                           @{Label= "FixedFileName";       Expression={ $_.FixedFileName}; Width=$fileNameWidth} -Wrap
        }
        else
        {
            $FilesWithInvalidCharsFixedName | Format-Table @{Label= "OriginalFilePath";    Expression={ $_.OriginalFilePath};},`
                                                           @{Label= "FixedFileName";       Expression={ $_.FixedFileName};} -Wrap -AutoSize
        }

        Write-Host "***************************Items rename table end*****************************" -ForegroundColor Yellow

        Write-Host "***************************Items failed to rename table start*****************************" -ForegroundColor Yellow

        $filesFailedToRename = $listFile.FilesFailedToRename;

        Write-Host "Number of Files/Directories failed to rename: " $filesFailedToRename.Count -ForegroundColor Yellow

        if ($filesFailedToRename.Count -gt 0)
        {
            if($setTableWidth)
            {
                $filesFailedToRename | Format-Table @{Label= "OriginalFilePath"; Expression={ $_.OriginalFilePath}; Width=$fileNameWidth },`
                                                    @{Label= "FixedFileName";    Expression={ $_.FixedFileName}; Width=$fileNameWidth} -Wrap
            }
            else
            {
                $filesFailedToRename | Format-Table @{Label= "OriginalFilePath"; Expression={ $_.OriginalFilePath};},`
                                                    @{Label= "FixedFileName";    Expression={ $_.FixedFileName};} -Wrap -AutoSize
            }
        }

        Write-Host "***************************Items failed to rename table end*****************************" -ForegroundColor Yellow
    }
    elseif($PSBoundParameters.ContainsKey('DestinationPath') -and !($PSBoundParameters.ContainsKey('RenameItems')))
    {
        Write-Host "========================== File COPY/MOVE start ==========================================" -ForegroundColor Yellow
        $PSDefaultParameterValues['*:Encoding'] = 'utf8'
        CHCP 65001

        # To prevent previous code from breaking, revert for copy to previous sharepath
        foreach ($file in $FilesWithInvalidCharsFixedName) {
            $path = $file.OriginalFilePath
            if($path.StartsWith("\\?\"))
            {
                $path = $path.Remove(0, 4)
            }
            if($path.StartsWith("\\?\unc\")){
                $path = $path.Remove(0, 8)
            }

            # is File or Folder already part of a synced directory, file can be skipped
            $isHandled = $listFile.IsHandledThroughFolder($file.OriginalFilePath)
            if(!$isHandled){
                $root = [System.IO.Path]::GetPathRoot($path);
                $relative_path = $path.Remove(0, $root.Length);
                $file_name = [System.IO.Path]::GetFileName($path)

                if($file.Type -eq 'FOLDER'){
                    $source = [System.IO.Path]::GetDirectoryName($path + '\')
                    $destination = [System.IO.Path]::Combine($DestinationPath, [System.IO.Path]::GetDirectoryName($relative_path + '\'));
                    
                    [System.IO.Directory]::CreateDirectory($destination)
                    $allArgs = @('"' + $source + '"', '"' + $destination + '"', '*.*', '/E ' + $RoboCopyOptions)

                    Start-Process Robocopy.exe -ArgumentList $allArgs -NoNewWindow -Wait -PassThru
                    Write-Host 'Folder'$file_name' and all contents were copied from '$SharePath' to '$destination -ForegroundColor Green
                } else {
                    $source = [System.IO.Path]::GetDirectoryName($path)
                    $destination = [System.IO.Path]::Combine($DestinationPath, [System.IO.Path]::GetDirectoryName($relative_path));
                
                    $allArgs = @('"' + $source + '"', '"' + $destination + '"', '"'+ $file_name +'"', $RoboCopyOptions)
                    Start-Process Robocopy.exe -ArgumentList $allArgs -NoNewWindow -Wait -PassThru
                    Write-Host 'File'$file_name' copied from '$SharePath' to '$destination -ForegroundColor Green
                }

            } else {
                Write-Host $file.OriginalFilePath' skipped because already synced through parent folder' -ForegroundColor Yellow
            }
        }
        Write-Host "========================== File COPY/MOVE end ==========================================" -ForegroundColor Yellow
    }
    else
    {
        if ([string]::IsNullOrEmpty($CsvPath))
        {
            Write-Host "***************************Items can be renamed table start***************************" -ForegroundColor Yellow

            if($setTableWidth)
            {
                    $FilesWithInvalidCharsFixedName | Format-Table @{Label= "OriginalFilePath";Expression={ $_.OriginalFilePath}; Width=$fileNameWidth },`
                                                                    @{Label= "FixedFileName";Expression={ $_.FixedFileName}; Width=$fileNameWidth},`
                                                                    @{Label= "Type";Expression={ $_.Type};}  -Wrap
            }
            else
            {
                    $FilesWithInvalidCharsFixedName | Format-Table @{Label= "OriginalFilePath";Expression={ $_.OriginalFilePath};},`
                                                                    @{Label= "FixedFileName";Expression={ $_.FixedFileName};},`
                                                                    @{Label= "Type";Expression={ $_.Type};} -Wrap -AutoSize
            }

            Write-Host "***************************Items can be renamed table end*****************************" -ForegroundColor Yellow
        }
        else
        {
            $FilesWithInvalidCharsFixedName |  ForEach-Object {
                $fileObject = [PSCustomObject]@{
                                OriginalFilePath = $_.OriginalFilePath
                                FixedFileName = $_.FixedFileName
                                }

                Export-Csv -InputObject $fileObject -Path $FixedFileNamesFileName -Append -NoTypeInformation -Force
            }

            Write-Host "CSV file generated at: $FixedFileNamesFileName"  -ForegroundColor Green
        }

        Write-Host "To rename the items, run the script as " -ForegroundColor Green

        if ([string]::IsNullOrEmpty($ReplacementString))
        {
            Write-Host ".\ScanUnsupportedChars.ps1 -SharePath $SharePath -RenameItems " -ForegroundColor Green
        }
        else
        {
            Write-Host ".\ScanUnsupportedChars.ps1 -SharePath $SharePath -RenameItems -ReplacementString '$ReplacementString' " -ForegroundColor Green
        }
    }
}
else
{
     Write-Host "ALL GOOD - Sync share does not have any file with unsupported chars" -ForegroundColor Green
}

Write-Host "==================== Scan Results Finished ========================="

Remove-Variable listFile

<#
 .SYNOPSIS

    Copyright (c) Microsoft Corporation.  All rights reserved.

    This is a Powershell script to scan / scan plus rename the files that are not supported by Azure File Sync.

 .DESCRIPTION

   Scan provided share to get the file names not suported by AFS.
   It can also fix those files by replacing the unsupported char with the provided string in the files names.

   Version 4.3
   Last Modified Date: Oct 4, 2019

    Example usage:
 
    Note: Please open powershell in full screen mode to avoid output truncation.

    Set-ExecutionPolicy Unrestricted
       1. Just to see all files with unsupported chars on console window with unsupported char replaced by 'empty string'
       .\ScanUnsupportedChars.ps1  -SharePath  <LocalShareRootPath>
       2. Just to see all files with unsupported chars on console window with unsupported char replaced by 'YourOwnString'
       .\ScanUnsupportedChars.ps1  -SharePath  <LocalShareRootPath> -ReplacementString "YourOwnString"
       3. If you want to replace the unsupported char with your own string do
       .\ScanUnsupportedChars.ps1  -SharePath  <LocalShareRootPath> -RenameItem -ReplacementString "YourOwnString"
       4. If you want to remove the unsupported char from file paths do
       .\ScanUnsupportedChars.ps1  -SharePath  <LocalShareRootPath> -RenameItem
     Set-ExecutionPolicy AllSigned

 .PARAMETER SharePath
     Path of the share to scan, it could be local folder like D:\share, D:\ or a remote share like \\server\share
 .PARAMETER $RenameItems
     Switch if you want to rename the item as it scan. If you wont want to rename, do not provide this switch.
 .PARAMETER ReplacementString
     The 'character' that would replace the unsupported char in the file names. Default is '' (empty string)

 .EXAMPLE
     .\ScanUnsupportedChars.ps1  -SharePath  E:\SyncShare
      This would scan the provided SyncShare for the unsupported file names.

 .EXAMPLE
     .\ScanUnsupportedChars.ps1  -SharePath  E:\SyncShare -RenameItem
      This would scan and rename the unsupported file names in the provided sync share.
      This would replace the unsupported char with empty string.

 .EXAMPLE
      .\ScanUnsupportedChars.ps1  -SharePath  E:\SyncShare -RenameItem -ReplacementString "-"
      This would scan and rename the unsupported file names in the provided sync share.
      This would replace the unsupported char with "-".

 .EXAMPLE
      .\ScanUnsupportedChars.ps1  -SharePath  \\server\SyncShare 
        This would scan the provided remote SyncShare for the unsupported file names.

 .EXAMPLE
      .\ScanUnsupportedChars.ps1  -SharePath  \\server\SyncShare  -RenameItem
      This would scan and rename the unsupported file names for the provided remote SyncShare.
      This would replace the unsupported char with empty string.

 .EXAMPLE
      .\ScanUnsupportedChars.ps1  -SharePath  \\server\SyncShare  -RenameItem -ReplacementString "-"
      This would scan and rename the unsupported file names for the provided remote SyncShare.
      This would replace the unsupported char with "-".

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
   [string]$ReplacementString
)

$ErrorActionPreference="Stop"

Add-Type -TypeDefinition @"

using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using ft = System.Runtime.InteropServices.ComTypes;
using System.ComponentModel;
using System.Text;

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

public class FixedFileNameEntry
{
    public string OriginalFilePath { get; set; }
    public string FixedFileName { get; set; }

    public FixedFileNameEntry()
    {
        OriginalFilePath = string.Empty;
        FixedFileName = string.Empty;
    }
}

public class ListFiles
{
    static IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
    static int FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
    const int MAX_PATH = 260;
    public int ItemCount = 0;
    private const int AzureMaxFilePathLengthLimit = 2048;

    public string ReplacementString;
    public int SharePathLength;

    public List<string> FilePathTooLongList = new List<string>();
    public List<FixedFileNameEntry> FilesWithInvalidCharsFixedName = new List<FixedFileNameEntry>();
    public List<FixedFileNameEntry> FilesFailedToRename = new List<FixedFileNameEntry>();

    // Unsupported chars black list
    private static List<int> disallowedChars = new List<int>();

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

        if ((0x00 <= CodePoint && CodePoint <= 0x007F) ||
            (0xA0 <= CodePoint && CodePoint <= 0xD7FF) ||
            (0xF900 <= CodePoint && CodePoint <= 0xFDCF) ||
            (0xFDF0 <= CodePoint && CodePoint <= 0xFFEF) ||
            (0x10000 <= CodePoint && CodePoint <= 0x1FFFD) ||
            (0x20000 <= CodePoint && CodePoint <= 0x2FFFD) ||
            (0x30000 <= CodePoint && CodePoint <= 0x3FFFD) ||
            (0x40000 <= CodePoint && CodePoint <= 0x4FFFD) ||
            (0x50000 <= CodePoint && CodePoint <= 0x5FFFD) ||
            (0x60000 <= CodePoint && CodePoint <= 0x6FFFD) ||
            (0x70000 <= CodePoint && CodePoint <= 0x7FFFD) ||
            (0x80000 <= CodePoint && CodePoint <= 0x8FFFD) ||
            (0x90000 <= CodePoint && CodePoint <= 0x9FFFD) ||
            (0xA0000 <= CodePoint && CodePoint <= 0xAFFFD) ||
            (0xB0000 <= CodePoint && CodePoint <= 0xBFFFD) ||
            (0xC0000 <= CodePoint && CodePoint <= 0xCFFFD) ||
            (0xD0000 <= CodePoint && CodePoint <= 0xDFFFD) ||
            (0xE1000 <= CodePoint && CodePoint <= 0xEFFFD) ||
            (0xE000 <= CodePoint && CodePoint <= 0xF8FF) ||
            (0xF0000 <= CodePoint && CodePoint <= 0xFFFFD) ||
            (0x100000 <= CodePoint && CodePoint <= 0x10FFFD) ||
            (0xE0000 <= CodePoint && CodePoint <= 0xE0FFF))
        {
            // The character is withing the range of valid characters supported by XStore,
            // hence it is supported, unless it is part of the exception list
            if (disallowedChars.Contains(CodePoint))
            {
                Console.WriteLine("Unsupported char code point: " + CodePoint);
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

        // Filenames with trailing dots are not supported
        // Filenames with trailing spaces are not supported
        if (fileName.EndsWith(@".") || fileName.EndsWith(@" "))
        {
            InvalidCharInfo info = new InvalidCharInfo();

            info.Code = fileName.EndsWith(@".") ? 0x0000002E : 0x00000020;
            info.Position = filePath.Length;
            info.Message = "File name ends with '.' or ' '";
            InvalidCharFileInformation.Add(filePath, info);

            fileName = fileName.TrimEnd(new char [] {' ','.'});

            return filePath.Substring(0, fileNameIndex + 1) + fileName + ReplacementString;
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
            return filePath.Substring(0, fileNameIndex + 1) + newFileName.ToString();
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

                        FindFilesAndDirs(dirPath);

                        string fixedDirName = ValidateAndReturnFixedPath(dirPath);

                        if (!string.IsNullOrEmpty(fixedDirName))
                        {
                            FixedFileNameEntry entry = new FixedFileNameEntry();
                            entry.OriginalFilePath = dirPath;
                            entry.FixedFileName = fixedDirName;

                            FilesWithInvalidCharsFixedName.Add(entry);
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
    [int] $hostWindowWidth = $host.UI.RawUI.WindowSize.Width
    [int] $codewidth = 12;

    if($hostWindowWidth -lt $codewidth)
    {
        $codewidth = 1;
    }

    $hostWindowWidth = $hostWindowWidth - $codewidth;

    [int] $messageWidth = [int] $hostWindowWidth/3;

    if($messageWidth -le 0)
    {
        $messageWidth = 1;
    }

    [int] $fileNameWidth = $hostWindowWidth - $messageWidth;

    if($fileNameWidth -le 0)
    {
        $fileNameWidth = 1;
    }

    $UnSupportedList | Format-Table @{Label= "FileName";    Expression={ $_.Key}; Width=$fileNameWidth },`
                                    @{Label= "Message";     Expression={ $_.Value.Message}; Width=$messageWidth},`
                                    @{Label= "Code";        Expression={ $_.Value.Code}; Width=$codewidth},`
                                    @{Label= "Position";    Expression={ $_.Value.Position}; Width=$codewidth} -Wrap 
}

Write-Host "========================== File Path too long start==========================================" -ForegroundColor Yellow

$FilePathTooLongList = $listFile.FilePathTooLongList;

Write-Host "Files/Directories having path length > 2048 chars (current limit for azure files), total count: " $FilePathTooLongList.Count -ForegroundColor Yellow

if($FilePathTooLongList.Count -gt 0)
{
    ForEach ($File in $FilePathTooLongList)
    {
        Write-Host $File -ForegroundColor Red
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

        $FilesWithInvalidCharsFixedName | Format-Table @{Label= "OriginalFilePath";    Expression={ $_.OriginalFilePath}; Width=$fileNameWidth },`
                                                    @{Label= "FixedFileName";         Expression={ $_.FixedFileName}; Width=$fileNameWidth} -Wrap

        Write-Host "***************************Items rename table end*****************************" -ForegroundColor Yellow

        Write-Host "***************************Items failed to rename table start*****************************" -ForegroundColor Yellow

        $filesFailedToRename = $listFile.FilesFailedToRename;

        Write-Host "Number of Files/Directories failed to rename: " $filesFailedToRename.Count -ForegroundColor Yellow

        if ($filesFailedToRename.Count -gt 0)
        {
            $filesFailedToRename | Format-Table @{Label= "OriginalFilePath";    Expression={ $_.OriginalFilePath}; Width=$fileNameWidth },`
                                                @{Label= "FixedFileName";         Expression={ $_.FixedFileName}; Width=$fileNameWidth} -Wrap
        }

        Write-Host "***************************Items failed to rename table end*****************************" -ForegroundColor Yellow
    }
    else
    {
        Write-Host "***************************Items can be renamed table start***************************" -ForegroundColor Yellow
        $FilesWithInvalidCharsFixedName | Format-Table @{Label= "OriginalFilePath";    Expression={ $_.OriginalFilePath}; Width=$fileNameWidth },`
                                                       @{Label= "FixedFileName";         Expression={ $_.FixedFileName}; Width=$fileNameWidth} -Wrap

        Write-Host "***************************Items can be renamed table end*****************************" -ForegroundColor Yellow

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
#=======================================================================================================================================================================
# Copyright (c) Microsoft Corporation.  All rights reserved.
#
# Description:
#
#   Azure File Sync: List per item sync errors
#
#   Version 1.4
#   Last Modified Date: 8/29/2018
#
#=======================================================================================================================================================================

<#
.SYNOPSIS
Individual namespace items (files and folders) can have characteristics that stop them from being successfully synced.
These characteristics  may include unsupported characters, individual item size or other aspects of sync and over-time changes in a namespace.
When the Azure File Sync engine detects such a problem, a per-item error log is produced that can be parsed to list the items currently not syncing properly.

The result of the script is a table that shows all per-item errors.
The table can be grouped by SyncGroup this server participates in.

.DESCRIPTION
Individual namespace items (files and folders) can have characteristics that stop them from being successfully synced.
These characteristics  may include unsupported characters, individual item size or other aspects of sync and over-time changes in a namespace.
When the Azure File Sync engine detects such a problem, a per-item error log is produced that can be parsed to list the items currently not syncing properly.

The result of the script is a table that shows all per-item errors.
The table can be grouped by SyncGroup this server participates in.

.PARAMETER ReportAllErrors
    Include in the report, all per-item error found in the event log.

.PARAMETER Width 
    Specifies the number of characters in each line of output. Any additional characters are truncated, not wrapped.
#>

[cmdletbinding()]
Param(
        [switch] $ReportAllErrors,

        [string] $CsvPath
)

# set PS execution mode
Set-StrictMode -Version 2.0

# Create a result table that the script can return and print.
$ResultTable = New-Object system.Data.DataTable "Per Item Errors"

# List of known errors that indicate that filename has an unsupported character:
# 1. ERROR_INVALID_NAME
# 2. ECS_E_XSMB_REST_INCOMPATIBILITY
$UnsupportedCharsErrorList = (-2147024773, -2134375851)

# Unsupported chars for file path
# 0x0000002A  = '*'
# 0x00000022  = quotation mark
# 0x0000003F  = '?'
# 0x0000003E  = '>'
# 0x0000003C  = '<'
# 0x0000003A  = ':'
# 0x0000007C  = '|'
# 0x00000085  =  nel next line
# 0x0000002F  = '/'
$DisallowedChars = (0x0000002A,0x00000022,0x0000003F,0x0000003E,0x0000003C,0x0000003A,0x0000007C,0x00000085,0x0000002F)

#Start PInvoke Code 
$sigFormatMessage = @' 
[DllImport("kernel32.dll")] 
public static extern uint FormatMessage(uint flags, IntPtr source, uint messageId, uint langId, StringBuilder buffer, uint size, string[] arguments); 
'@ 
 
$sigLoadLibrary = @' 
[DllImport("kernel32.dll")] 
public static extern IntPtr LoadLibrary(string lpFileName); 
'@ 

$sigGetLastError = @' 
[DllImport("kernel32.dll")] 
public static extern uint GetLastError(); 
'@ 

$Win32FormatMessage = Add-Type -MemberDefinition $sigFormatMessage -name "Win32FormatMessage" -namespace Win32Functions -PassThru -Using System.Text 
$Win32LoadLibrary = Add-Type -MemberDefinition $sigLoadLibrary -name "Win32LoadLibrary" -namespace Win32Functions -PassThru -Using System.Text 
$Win32GetLastError = Add-Type -MemberDefinition $sigGetLastError -name "Win32GetLastError" -namespace Win32Functions -PassThru -Using System.Text 

$global:SyncErrorModules = @(
    @{
        Path = Join-Path $env:ProgramFiles 'Azure\StorageSyncAgent\SyncShareRes.dll';
        MaskFlags    =  [uint32]::MaxValue;
        ModuleHandle = $null
    }

    @{
        Path = Join-Path $env:SystemRoot 'System32\winhttp.dll'
        MaskFlags    =  [uint32] 0x0000ffff; # the error messages in this dll are indexed (message id value) by error code instead of HResults
        ModuleHandle = $null
    }
)
#End PInvoke Code 

# Get the template for a specific Event type, and extract the Name of the user properties
function GetEventPropertyNames($eventId)
{
    $EventPropertiesNames = @()
    
    $templateXml = [xml]((Get-WinEvent -ListProvider Microsoft-FileSync-Agent).Events | Where-Object {$_.Id -eq $eventId}).Template

    $templateXml.template.data.name | ForEach-Object {
       $EventPropertiesNames += $_
    }

    return $EventPropertiesNames
}

function ConvertIntToUnsignedInt([int] $num)
{
    return [uint32]("0x$([System.Convert]::ToString([int32]$num, 16))")
}

function IsSystemErrorCode([int] $ErrorCode)
{
    # determine if the error code is in the Win32 (system) format 
    # that is, the high word is equal to 0x8007
    return (($ErrorCode -band 0xffff0000) -eq 0x80070000)
}
function GetSystemErrorMessage([int] $ErrorCode)
{
    # only process system error codes
    if(IsSystemErrorCode $ErrorCode)
    {
        $sizeOfBuffer = [int]16384 
        $FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200
        $FORMAT_MESSAGE_FROM_SYSTEM = 0x00001000

        $flags = $FORMAT_MESSAGE_FROM_SYSTEM -bor $FORMAT_MESSAGE_IGNORE_INSERTS

        $stringOutput = New-Object System.Text.StringBuilder $sizeOfBuffer 

        $SystemErrorMsg = $null

        $MaskFlags =  [uint32] 0x0000ffff;
        $MessageID = ($MaskFlags -band $(ConvertIntToUnsignedInt $ErrorCode))
        $result = $Win32FormatMessage::FormatMessage($flags, [System.IntPtr]::Zero, $MessageID, 0, $stringOutput, $sizeOfBuffer, $null) 

        if($result -gt 0) 
        { 
            $SystemErrorMsg = $stringOutput.ToString()
        } 
    }
    else
    {
        $SystemErrorMsg = $null
    }
    
    return $SystemErrorMsg
}
function GetStorageSyncErrorMessage([int] $ErrorCode)
{
    $sizeOfBuffer = [int]16384 
    $FORMAT_MESSAGE_IGNORE_INSERTS = 0x00000200
    $FORMAT_MESSAGE_FROM_HMODULE = 0x00000800
    $flags = $FORMAT_MESSAGE_FROM_HMODULE -bor $FORMAT_MESSAGE_IGNORE_INSERTS

    $stringOutput = New-Object System.Text.StringBuilder $sizeOfBuffer 

    $Msg = GetSystemErrorMessage $ErrorCode

    for($i = 0; ($i -lt $global:SyncErrorModules.Count) -and !$Msg; $i++)
    {
        if(!$global:SyncErrorModules[$i].ModuleHandle)
        {
            $global:SyncErrorModules[$i].ModuleHandle = $Win32LoadLibrary::LoadLibrary($global:SyncErrorModules[$i].Path)
        }

        $m = $global:SyncErrorModules[$i]

        if($m.ModuleHandle)
        {
            $MessageID = ($m.MaskFlags -band $(ConvertIntToUnsignedInt $ErrorCode))
            $result = $Win32FormatMessage::FormatMessage($flags, $m.ModuleHandle, $MessageID, 0, $stringOutput, $sizeOfBuffer, $null) 

            if($result -gt 0) 
            { 
                $Msg = $stringOutput.ToString()
                # calling break here would exit the script instead of breaking the look, I [josefig] do not understand why.
                # to work around, we check if #Msg is set to break the loop
                #break
            } 
            else 
            {
                #TODO: Add code to know if the error is "not found", anything else, should print the message below
                #Write-Output "FormatMessage failed with: $($Win32GetLastError::GetLastError())"
            }
        }
        else
        {
            Write-Error "Failed to load the resource file: $($m.Path)".
        }
    }

    return $Msg
}

# Main function of the script.
function MainFunction
{
    # constant definitions
    $UnknownSyncGroupName = 'SyncGroupName-UNKNOWN'
    $DownloadSyncDirection = 'Download'
    $UploadSyncDirection = 'Upload'

    # The agent version is helpful in certain cases to understand why some file errors are seen on this server.
    # Newer versions of an agent may prevent certain errors from happening. Show the agent version if the agent is currently installed on the machine the script is running on.
    Write-Progress "Fetching the File Storage Sync Service version..."

    $AfsAgentVersion = InstalledAgentVersion

    $LogsRootPath = Join-Path $env:systemroot "System32\winevt\Logs"

    $TelemetryEventsFilePath = (Join-Path $LogsRootPath "Microsoft-FileSync-Agent%4Telemetry.evtx")
    $ItemResultsEventsFilePath = (Join-Path $LogsRootPath "Microsoft-FileSync-Agent%4ItemResults.evtx")

    if ($AfsAgentVersion)
    {
         $AfsAgentVersionString = "Installed Azure File Sync agent version: $AfsAgentVersion" 
    }
    else
    {
        $AfsAgentVersionString = "No Azure File Sync agent detected." 
    }

    Write-Output "`n
==========================================================================
    Copyright (c) Microsoft Corporation.  All rights reserved.
    
    Azure File Sync: List per item sync errors
    Server Name: $env:computername
    Script version 1.4
    $AfsAgentVersionString
==========================================================================`n`n"


    Write-Progress "Collecting events from ItemResults channel..."
    $PerItemEventPropertyNames = GetEventPropertyNames 9900
    $PerItemEvents = GetEventsCollection $ItemResultsEventsFilePath $PerItemEventPropertyNames | Where-Object {$_.EventId -eq 9900} 

    #Check per-item error events for activity
    if((!$PerItemEvents) -or ($PerItemEvents.Count -eq 0))
    {
        Write-Output "`n`nThere have been no per-item errors recorded or the event log is missing."
        Write-Output "Check that this event log exists: $LogsRootPath\Microsoft-FileSync-Agent%4ItemResults.evtx" 
        return
    }

    Write-Progress "Collecting events from Telemetry channel..."
    $Sync9102EventPropertyNames = GetEventPropertyNames 9102
    $Sync9102EventsFromLogs = GetEventsCollection $TelemetryEventsFilePath $Sync9102EventPropertyNames | Where-Object { $_.EventId -eq 9102 } 

    if(!$Sync9102EventsFromLogs)
    {
        #Ensure Sync9102EventsFromLogs is never null.
        $Sync9102EventsFromLogs = @()
    }

    # Initialize the result table, now that there is a chance of reporting per-item errors.
    InitializeResultTable

     # Add progress message
     Write-Progress "Parsing event channels..."

     # Group the per-item errors by session correlation id
    $PerItemEventsGroups = $PerItemEvents |  Group-Object -Property CorrelationId

    # The per-item-error events are now grouped by correlation id, for each of this groups, 
    # find the sync session event that have the same correlation id, if none is found 
    # create an 'unknown' sync session event with the given correlation id to later add 
    # it to the list.
    $Sync9102UnknowSessionEvents = @()
    $PerItemEventsGroups | ForEach-Object {

        $ItemErrorEvent  = $($_.Group | Select-Object -First 1)
        
        $Sync9102 = $Sync9102EventsFromLogs | Where-Object{ $ItemErrorEvent.CorrelationId -eq $_.CorrelationId } | Select-object -First 1

        if(!$Sync9102)
        {
            $SyncUnknown9102 = New-Object -TypeName PSObject

            $SyncUnknown9102 | Add-Member -Type NoteProperty -Name SyncGroupName       -Value $UnknownSyncGroupName
            $SyncUnknown9102 | Add-Member -Type NoteProperty -Name EventTimeCreated    -Value $ItemErrorEvent.EventTimeCreated
            $SyncUnknown9102 | Add-Member -Type NoteProperty -Name CorrelationId       -Value $ItemErrorEvent.CorrelationId
            $SyncUnknown9102 | Add-Member -Type NoteProperty -Name SyncDirection       -Value $ItemErrorEvent.SyncDirection
            $SyncUnknown9102 | Add-Member -Type NoteProperty -Name HResult             -Value 0x8000ffff # E_UNEXPECTED
            $SyncUnknown9102 | Add-Member -Type NoteProperty -Name EventId             -Value 9102

            $Sync9102UnknowSessionEvents += $SyncUnknown9102
        } 
    }
    $Sync9102Events = @()
    $Sync9102Events += $Sync9102EventsFromLogs 
    $Sync9102Events += $Sync9102UnknowSessionEvents

    #  A sync session will be considered if:
    #  1. It is the most recent successful (upload, download or both) session for a given sync group
    #  2. It is a failed sync session for a given sync group which occurred after the most recent successful (upload and download) sync session.
    #       Note: This will include 'unknown' session that contains items which time-stamp comes after the last considered sync session.
    #
    # When -ReportAllErrors flag is present, all sync session will be considered.
    #

    #  An 'unknown' session will be created when for a given per-item-error event, there is no sync session event that correlate with
    #  any of the sync session events present in the event log; this may occur when:
    #    1. There is an ongoing sync session. Item errors reported by it would not be correlated because the sync session event has not been logged yet.
    #    2. The telemetry evet log wraps, removing all sync session event that correlate with per-item-error events in the log.
    
    $SyncSession9102EventsToBeConsidered = @()

    if(!$ReportAllErrors)
    {
        #  $ReportAllErrors is not set, we must only consider a sync session if:
        #  1. It is the most recent successful (upload, download or both) session for a given sync group
        #  2. It is a failed sync session for a given sync group which occurred after the most recent successful (upload and download) sync session.
        #       Note: This will include 'unknown' session that contains items which time-stamp comes after the last considered sync session.

        # Group the sync session events by Syncgroup id. Exclude the unknown sync groups now. They will be added later if they should be considered.
        $SyncEventGroupedBySyncGroupName = $Sync9102Events | Where-Object {$_.SyncGroupName -ne $UnknownSyncGroupName} | Group-Object -Property SyncGroupName
        $SyncEventGroupedBySyncGroupName | ForEach-Object {

            # Find the allsyngroup's session that succeeded.
            $SucceededSyncSessions = @()
            $SucceededSyncSessions += $_.Group | Where-Object {$_.HResult -eq 0} 

            if($SucceededSyncSessions)
            {                
                # There is one or more successful sync session, we must find the most recent
                # upload and download session and pick the oldest of the two. 
                $MostRecentUploadSession = $SucceededSyncSessions | Where-Object { $_.SyncDirection -eq $UploadSyncDirection } | Sort-Object -Descending -Property EventTimeCreated | Select-Object -First 1
                $MostRecentDownloadSession = $SucceededSyncSessions | Where-Object { $_.SyncDirection -eq $DownloadSyncDirection } | Sort-Object -Descending -Property EventTimeCreated | Select-Object -First 1

                if($MostRecentUploadSession -and $MostRecentDownloadSession)
                {
                    if($MostRecentUploadSession.EventTimeCreated -gt $MostRecentDownloadSession.EventTimeCreated){
                        $MostRecentSucceededSyncSession = $MostRecentDownloadSession
                    } else{
                        $MostRecentSucceededSyncSession = $MostRecentUploadSession 
                    }
                }
                else
                {
                    # All sync session events are for the same direction.   
                    $MostRecentSucceededSyncSession = $SucceededSyncSessions | Sort-Object -Descending -Property EventTimeCreated | Select-Object -First 1
                }

                # Get all the session that occurred after, including the successful one.
                # Note, this may lead to multiple session to consider in the same direction,
                # for example consider this sequence [D, U, U], since the download (D) session 
                # is older, the two subsequent upload sessions will be considered.
                $SyncSession9102EventsToBeConsidered += $_.Group | Where-Object {$_.EventTimeCreated -ge $MostRecentSucceededSyncSession.EventTimeCreated} 
            }
            else
            {
                # There are no successful sessions, so we will consider them all.
                $SyncSession9102EventsToBeConsidered += $_.Group
            }
        } # foreach

        # Now, let's consider the unknown-sync groups sessions, they need to be included
        # if they occurred after the most recent known-session that will be considered.
        # The goal is to include item-error events from the active sync session; which is 
        # unknown because the sync session event will be logged at the end of the session.

        $MostRecentSyncSessionConsidered = $SyncSession9102EventsToBeConsidered | Sort-Object -Descending -Property EventTimeCreated | Select-Object -First 1

        $SyncSession9102EventsToBeConsidered += $Sync9102Events | Where-Object {($_.SyncGroupName -eq $UnknownSyncGroupName) -and ($_.EventTimeCreated -gt $MostRecentSyncSessionConsidered.EventTimeCreated) }
    }
    else
    {
        # Consider them all
        $SyncSession9102EventsToBeConsidered = $Sync9102Events
    }

    # List of sync session to be considered when looking for per-item errors
    $SyncSessionsToConsider = @()
    
    $SyncSession9102EventsToBeConsidered | ForEach-Object {

        $SyncSessionObj = New-Object -TypeName PSObject

        $SyncSessionObj | Add-Member -Type NoteProperty -Name SyncGroupName -Value ($_.SyncGroupName)
        $SyncSessionObj | Add-Member -Type NoteProperty -Name CorrelationId -Value ($_.CorrelationId)

        # It is possible that a download and upload session share the same CorrelationId
        # hence we create a new unique session id to tell them apart in the report.
        # I (josefig) beleive this bug has been already fixed in the agent, if so
        # we can use the correlation id to uniquely identify the sync session.
        $SyncSessionObj | Add-Member -Type NoteProperty -Name SessionId -Value $(New-Guid).ToString()
        $SyncSessionObj | Add-Member -Type NoteProperty -Name SessionTime -Value (Get-Date -Date $_.EventTimeCreated).ToString("dd/MM/yyyy HH:MM")
        $SyncSessionObj | Add-Member -Type NoteProperty -Name SessionSyncDirection -Value $_.SyncDirection
        $SyncSessionObj | Add-Member -Type NoteProperty -Name SessionErrorCode -Value $_.HResult

        $SyncSessionsToConsider += $SyncSessionObj
    }

    # There now is a complete list of Sync Groups that could be found logging successful upload or download sessions.
    Write-Progress "Generating report...."

    # The next step is to identify all the per-item row which correlation id match any of the considred sync sessions correlation id.
    CreatePerItemErrorsTable $PerItemEventsGroups $SyncSessionsToConsider
} #end MainFunction()

function isValidUInt32([string] $number)
{
    try
    {
        $f = [System.Convert]::ToUInt32($number)
        $isValid = $true
    }
    catch 
    {
        Write-Warning "this: $number is not a valid unsigned 32 bits number"
        $isValid = $false;
    }

    $isValid
}

function GetEventsCollection($EventsFilePath, $eventPropertyNames)
{
    # Take a list of Windows Events logs, and from it create a list of custom objects, 
    # each custom object will have event's data items as properties to facilitate queries
    $EventList = @()

    Get-WinEvent -Path $EventsFilePath -ErrorAction SilentlyContinue | ForEach-Object { 

        $object = New-Object -TypeName PSObject

        $isvalid = isValidUInt32 $_.Id
        if(!$isvalid)
        {
            Write-Warning "Ignoring event with invalid Id: $($_.Id)"
            # return in powershell means continue, go to the top of the loop
            return 
        }

        $object | Add-Member -Type NoteProperty -Name EventTimeCreated -Value ($_.TimeCreated)
        $object | Add-Member -Type NoteProperty -Name EventId -Value ($_.Id) 

        $i = 0
        $_.Properties | ForEach-Object {

            $object | Add-Member -Type NoteProperty -Name $eventPropertyNames[$i] -Value ($_.Value)
            $i ++
        }

        $EventList += $object;
    }

    return $EventList
}

function TrimCIDecoration([string] $str)
{
    # remove the <CI></CI> decoration around the string
    return $str.Substring(4,($str.Length-(4+5)))
}

function GetErrorDescription($ErrorCode)
{
    $Msg = GetStorageSyncErrorMessage($ErrorCode)

    # If the error code does not belong to the Storage Sync, try to find it on the list of system errors
    if(!$Msg)
    {
        # If there is no mapping of the error code (ErrorCode) in the mapping table, then use the windows default message for the error code.
        $Msg = $(New-Object System.ComponentModel.Win32Exception([System.Convert]::ToInt32($ErrorCode))).Message
    }

    return $Msg
}

function CreatePerItemErrorsTable($PerItemEventsGroupedByCorrelationId, $SyncSessionObjects)
{
    # SyncSessionObjects is a list of sync session to consider.

    $AllSyncSessionsPerItemEvents = @()

    $CorrelationIdToSyncSessionMap = @{};

    # We want to find all per-item events with a matching correlation ID
    $SyncSessionObjects | ForEach-Object {

        $CurrentSyncObj = $_

        # Add the session object to the lookup table for fast access
        # when it is used later to build the row objects.
        $CorrelationIdToSyncSessionMap[$_.CorrelationId] = $_

        # find the group of per-item errors which match this sync session correlation id
        $PerItemGroup = $PerItemEventsGroupedByCorrelationId | Where-Object{ $_.Name -eq $CurrentSyncObj.CorrelationId }  

        if(!$PerItemGroup)
        {
            # continue the loop if there are no per-item errors for this correlation id 
            # this session either had no per-item errors, or they are no longer present
            # in the log.
            return 
        }

        # Collect all the per-item file event for all the sync session considered
        $AllSyncSessionsPerItemEvents += $PerItemGroup.Group 
        
    } #end iterating through the syncgroup's session

    # A given file item, may consistently fail over multiple syn sessions, to avoid reporting duplicated items, we will group them
    # by GlobalId, Direction and HResult. Hence an item with the same Direction and ErrorCode will appears only once in the report
    $AllSyncSessionsPerItemUniqueEvents = $AllSyncSessionsPerItemEvents | Group-Object -Property GlobalId, SyncDirection, HResult | ForEach-Object { $_.Group | Select-Object -First 1 }

    # There have been error events logged for the Sync Group in the latest sync session.
    # Iterate through them to extract the relevant information from the log and add that info to the result table of this script.
    $AllSyncSessionsPerItemUniqueEvents | ForEach-Object {

        $CurrentRow = $ResultTable.NewRow()

        $CurrentRow.SyncDirection = $_.SyncDirection
        $CurrentRow.Operation = $_.Operation
        $CurrentRow.ErrorCode = "0x$([System.Convert]::ToString([System.Convert]::ToInt32($_.HResult), 16))"
        $CurrentRow.ErrorDescription = GetErrorDescription $_.HResult
        $CurrentRow.ItemPath = TrimCIDecoration $_.FileName

        if ($UnsupportedCharsErrorList.Contains($_.HResult))
        {
            $invalidCharInfo = Get-InvalidCharInfo $CurrentRow.ItemPath

            if ($invalidCharInfo)
            {
                $CurrentRow.InvalidCharDescription = "Invalid Character found at position $($invalidCharInfo.Position) in the filename. Please remove the character to enable the file to sync. More Details: $($invalidCharInfo.Description)."
                $CurrentRow.InvalidCharPosition = $invalidCharInfo.Position
                $CurrentRow.InvalidCharCode = $invalidCharInfo.CharCode
            }
            else 
            {
                $CurrentRow.InvalidCharDescription = "The script failed to identify the invalid character in the filename. Please contact Microsoft Support for more help."
                $CurrentRow.InvalidCharPosition = ''
                $CurrentRow.InvalidCharCode = ''
            }
        }
        else
        {
            $CurrentRow.InvalidCharDescription = ''
            $CurrentRow.InvalidCharPosition = ''
            $CurrentRow.InvalidCharCode = ''
        }

        # Older Agents does not have the IsPersistentFailure or IsPersistentError column
        # default to 'n/a' if the property is missing.
        if($_.PSobject.Properties.name -match "IsPersistentFailure")
        {
            $CurrentRow.PersistentError = $_.IsPersistentFailure
        }
        elseif($_.PSobject.Properties.name -match "IsPersistentError")
        {
            $CurrentRow.PersistentError = $_.IsPersistentError
        }
        else
        {
            $CurrentRow.PersistentError = 'n/a'
        }

        $CurrentSyncObj = $CorrelationIdToSyncSessionMap[$_.CorrelationId]
        $CurrentRow.SyncGroup = $CurrentSyncObj.SyncGroupName
        $CurrentRow.SessionId = $CurrentSyncObj.SessionId
        $CurrentRow.SessionTime = $CurrentSyncObj.SessionTime
        $CurrentRow.SessionSyncDirection = $CurrentSyncObj.SessionSyncDirection
        $CurrentRow.SessionErrorCode = "0x$([System.Convert]::ToString([System.Convert]::ToInt32($CurrentSyncObj.SessionErrorCode), 16))"
        $CurrentRow.SessionErrorDescription = GetErrorDescription $CurrentSyncObj.SessionErrorCode
        
        # Even though there is a per-item error with a correlation ID we have been looking for, it wasn't possible to extract the necessary information.
        # An incomplete log, etc. could lead to that. Uncommon.
        # Avoid listing this error and continue evaluating the next.
        if($CurrentRow.ItemPath -and $CurrentRow.ErrorCode -and $CurrentRow.SyncDirection -and $CurrentRow.SyncGroup)
        {
            $ResultTable.Rows.Add($CurrentRow)
        }
        else
        {
            Write-Warning "Skipping per-item error because one or more of the key fields is missing."
        }
    } #end iterating through the per-item error list for the given SyncGroup
    
} #end function

function Get-InvalidCharInfo
{
    param(
        [string] $FileName
    )

    if ([string]::IsNullOrEmpty($FileName))
    {
        return $null
    }

    # Filenames with trailing dots are not supported
    if($FileName.EndsWith('.'))
    {
        $FileObj = New-Object -TypeName PSObject
        $FileObj | Add-Member -Type NoteProperty -Name 'FileName' -Value "$FileName"
        $FileObj | Add-Member -Type NoteProperty -Name 'Description' -Value "The name ends with a dot ('.'). If it is a directory, its children would not sync"
        $FileObj | Add-Member -Type NoteProperty -Name 'Position' -Value ($FileName.Length - 1)
        $FileObj | Add-Member -Type NoteProperty -Name 'CharCode' -Value 'U+22C5'

        return $FileObj
    }

    # Filenames with trailing spaces are not supported
    if($FileName.EndsWith(' '))
    {
        $FileObj = New-Object -TypeName PSObject
        $FileObj | Add-Member -Type NoteProperty -Name 'FileName' -Value "$FileName"
        $FileObj | Add-Member -Type NoteProperty -Name 'Description' -Value "The name ends with a space (' '). If it is a directory, its children would not sync"
        $FileObj | Add-Member -Type NoteProperty -Name 'Position' -Value ($FileName.Length - 1)
        $FileObj | Add-Member -Type NoteProperty -Name 'CharCode' -Value 'U+0020'

        return $FileObj
    }

    $FileNameArray = $FileName.ToCharArray()
    $charPosition = 0
    $charCode = $null

    for ($index = 0; $index -lt $FileNameArray.Length; $index++)
    {
        $curChar = $FileNameArray[$index]

        if ([char]::IsHighSurrogate($curChar))
        {
            if (($index + 1) -lt $FileNameArray.Length)
            {
                $nextChar = $FileNameArray[$index + 1]

                if (-not [char]::IsLowSurrogate($nextChar))
                {
                    # invalid surrogate pair found
                    $charArray = ($curChar, $nextChar)
                    $charString = -join $charArray
                    $msg = "Invalid surrogate pair found: $($charString)"
                    $charCode = Get-UnicodeCharCode $charString
                    $result = 1
                    $charPosition = $index + 1
                }
                else
                {
                    $charArray = ($curChar, $nextChar)
                    $charString = -join $charArray
                    $result = Test-IsSupported -charString $charString
                    if ($result -ne 0)
                    {
                        $charCode = $result
                        $msg = "Unsupported Character found. The character is outside the valid range or is disallowed by Azure File Sync."
                        $charPosition = $index + 1
                    }
                }
            }
            else 
            {
                $msg = "Found a high surrogate without a following low surrogate. Invalid Character: $($curChar)"
                $result = 1
                $charString = [string] $curChar
                $charCode = Get-UnicodeCharCode $charString
                $charPosition = $index + 1
            }
        }
        else
        {
            if ([char]::IsLowSurrogate($curChar))
            {
                if (($index - 1) -ge 0)
                {
                    $prevChar = $FileNameArray[$index - 1]

                    if (-not [char]::IsHighSurrogate($prevChar))
                    {
                        $charPosition = $index + 1
                        $result = 1
                        $msg = "Found a low surrogate char without a preceding high surrogate. Invalid Character: $($curChar)"
                        $charString = [string] $curChar
                        $charCode = Get-UnicodeCharCode $charString
                    }
                    else
                    {
                        $charArray = ($prevChar, $curChar)
                        $charString = -join $charArray
                        $result = Test-IsSupported -charString $charString
                        if ($result -ne 0)
                        {
                            $charCode = $result
                            $msg = "Unsupported Character found. The character is outside the valid range or is disallowed by Azure File Sync."
                            $charPosition = $index + 1
                        }
                    }
                }
                else
                {
                    $charPosition = $index + 1
                    $result = 1
                    $msg = "Found a low surrogate char without a preceding high surrogate. Invalid Character: $($curChar)"
                    $charString = [string] $curChar
                    $charCode = Get-UnicodeCharCode $charString
                }
            }
            else
            {
                $result = Test-IsSupported -CharString $curChar
                if ($result -ne 0)
                {
                    $charPosition = $index + 1
                    $charCode = $result
                    $msg = "Unsupported Character found. The character is outside the valid range or is disallowed by Azure File Sync."
                }
            }

            if($result -ne 0)
            {
                $FileObj = New-Object -TypeName PSObject
                $FileObj  | Add-Member -Type NoteProperty -Name FileName -Value "$FileName"
                $FileObj  | Add-Member -Type NoteProperty -Name 'Description' -Value $msg
                $FileObj  | Add-Member -Type NoteProperty -Name 'Position' -Value $charPosition
                $FileObj  | Add-Member -Type NoteProperty -Name 'CharCode' -Value $charCode

                return $FileObj
           }
        }
    }

    return $null
}

function Get-UnicodeCharCode($CharString)
{
    $char = [char]::ConvertToUtf32($CharString, 0)
    $charCode = 'U+{0:X4}' -f [int][char]$char
    return $charCode
}

# This function tests the validity for the char support by Azure File Sync
#    Chars outside the range as validated by this function are not supported by Azure File Sync.
function Test-IsSupported
{
    Param(
        [Parameter(Mandatory=$True)][string] $CharString
    )

    $codePoint = [char]::ConvertToUtf32($CharString, 0)
    
    if ((0x00    -le $codePoint -and $codePoint -le 0x007F)   -or
        (0xA0    -le $codePoint -and $codePoint -le 0xD7FF)   -or
        (0xF900  -le $codePoint -and $codePoint -le 0xFDCF)   -or
        (0xFDF0  -le $codePoint -and $codePoint -le 0xFFEF)   -or
        (0x10000 -le $codePoint -and $codePoint -le 0x1FFFD)  -or
        (0x20000 -le $codePoint -and $codePoint -le 0x2FFFD)  -or
        (0x30000 -le $codePoint -and $codePoint -le 0x3FFFD)  -or
        (0x40000 -le $codePoint -and $codePoint -le 0x4FFFD)  -or
        (0x50000 -le $codePoint -and $codePoint -le 0x5FFFD)  -or
        (0x60000 -le $codePoint -and $codePoint -le 0x6FFFD)  -or
        (0x70000 -le $codePoint -and $codePoint -le 0x7FFFD)  -or
        (0x80000 -le $codePoint -and $codePoint -le 0x8FFFD)  -or
        (0x90000 -le $codePoint -and $codePoint -le 0x9FFFD)  -or
        (0xA0000 -le $codePoint -and $codePoint -le 0xAFFFD)  -or
        (0xB0000 -le $codePoint -and $codePoint -le 0xBFFFD)  -or
        (0xC0000 -le $codePoint -and $codePoint -le 0xCFFFD)  -or
        (0xD0000 -le $codePoint -and $codePoint -le 0xDFFFD)  -or
        (0xE1000 -le $codePoint -and $codePoint -le 0xEFFFD)  -or 
        (0xE000  -le $codePoint -and $codePoint -le 0xF8FF)   -or
        (0xF0000  -le $codePoint -and $codePoint -le 0xFFFFD) -or
        (0x100000 -le $codePoint -and $codePoint -le 0x10FFFD) -or
        (0xE0000  -le $codePoint -and $codePoint -le 0xE0FFF))
    {
        # The character is within the range of valid characters supported by Azure Storage,
        # hence it is supported, unless it is part of the exception list
        if($DisallowedChars.Contains($codePoint))
        {
            return Get-UnicodeCharCode $CharString
        }
        else
        {
            return 0
        }
    }
    else 
    {
        # The character is outside the range of valid characters supported by Azure Storage
        return Get-UnicodeCharCode $CharString
    }    
}

function InstalledAgentVersion() 
{
    # Get the version of the agent for Azure File Sync - called "Storage Sync agent"
    $object = Get-WmiObject Win32_Product | Where-Object { $_.Name -like "*Storage Sync*"}

    if($object)
    { 
        return $object.Version
    } 
    else 
    { 
        return $null 
    }
}

function InitializeResultTable
{
    $col1 = New-Object system.Data.DataColumn SyncGroup,([string])
    $col2 = New-Object system.Data.DataColumn SyncDirection,([string])
    $col3 = New-Object system.Data.DataColumn ItemPath,([string])
    $col4 = New-Object system.Data.DataColumn ErrorDescription,([string])
    $col5 = New-Object system.Data.DataColumn ErrorCode,([string])
    $col6 = New-Object system.Data.DataColumn SessionId,([string])
    $col7 = New-Object system.Data.DataColumn SessionTime,([string])
    $col8 = New-Object system.Data.DataColumn SessionSyncDirection,([string])
    $col9 = New-Object system.Data.DataColumn SessionErrorCode,([string])
    $colA = New-Object system.Data.DataColumn SessionErrorDescription,([string])
    $colB = New-Object system.Data.DataColumn Operation,([string])
    $colC = New-Object system.Data.DataColumn PersistentError,([string])
    $colD = New-Object system.Data.DataColumn InvalidCharPosition,([string])
    $colE = New-Object system.Data.DataColumn InvalidCharCode,([string])
    $colF = New-Object system.Data.DataColumn InvalidCharDescription,([string])
    
    $ResultTable.Columns.Add($col1)
    $ResultTable.Columns.Add($col2)
    $ResultTable.Columns.Add($col3)
    $ResultTable.Columns.Add($col4)
    $ResultTable.Columns.Add($col5)
    $ResultTable.Columns.Add($col6)
    $ResultTable.Columns.Add($col7)
    $ResultTable.Columns.Add($col8)
    $ResultTable.Columns.Add($col9)
    $ResultTable.Columns.Add($colA)
    $ResultTable.Columns.Add($colB)
    $ResultTable.Columns.Add($colC)
    $ResultTable.Columns.Add($colD)
    $ResultTable.Columns.Add($colE)
    $ResultTable.Columns.Add($colF)
}

function PrintErrors($ErrorsTable)
{
    $ErrorsGroup = $ErrorsTable | Group-Object -Property ErrorCode
    Write-Output "Errors distribution:"
    $ErrorsSummary = @()
    $ErrorsGroup | ForEach-Object {
        $AnyGroup = $_.Group | Select-Object -First 1

        $GroupObj = New-Object -TypeName PSObject
        $GroupObj | Add-Member -Type NoteProperty -Name ErrorCode -Value ($AnyGroup.ErrorCode)
        $GroupObj | Add-Member -Type NoteProperty -Name ErrorDescription -Value ($AnyGroup.ErrorDescription)
        
        $GroupObj | Add-Member -Type NoteProperty -Name Count -Value ($_.Group.Count)

        $ErrorsSummary += $GroupObj
    }

    $ErrorsSummary | Format-Table @{Label= "Count";             Expression={ $_.Count};             Width = 5 },`
                                  @{Label= "ErrorCode";         Expression={ $_.ErrorCode};         Width = 10 },`
                                  @{Label= "ErrorDescription";  Expression={ $_.ErrorDescription};  Width = 4096 } -Wrap


    $ErrorsTable | Format-Table @{Label= "Sync`nDirection";         Expression={ $_.SyncDirection};},`
                                @{Label= "Operation";               Expression={ $_.Operation};},`
                                @{Label= "ErrorCode";               Expression={ $_.ErrorCode};},`
                                @{Label= "Persistent`nError";       Expression={ $_.PersistentError};},`
                                @{Label= "ItemPath";                Expression={ $_.ItemPath};},`
                                @{Label= "ErrorDescription";        Expression={ $_.ErrorDescription + " " + $_.InvalidCharDescription};} -Wrap -AutoSize
    
    Write-Output "Total number of errors: $($ErrorsTable.Count)"
}

# Start the script
MainFunction

if($ResultTable.Rows.Count -gt 0)
{
    $SyncGroupsGroups = $ResultTable | Group-Object -Property SyncGroup

    $SyncGroupsGroups | ForEach-Object {
        $SyncGroupName = $_.Name
        Write-Output "`n------------------------------------------------------------------"
        Write-Output "Sync Group: $SyncGroupName"
        Write-Output "------------------------------------------------------------------`n"
        # print the session information
        Write-Output "Sync Sessions considered:"
        # Group all per-item errors rows by session id, then pick the 
        # first row (Any row will do) to  gather the session information
        $SessionRows = @() 
        $_.Group | Group-Object -Property SessionId | ForEach-Object { $SessionRows += $_.Group | Select-Object -First 1 }
        
        $SessionRows | Format-Table @{Label= "SessionTime";         Expression={ $_.SessionTime};               Width = 16 },`
                                    @{Label= "SyncDirection";       Expression={ $_.SessionSyncDirection};      Width = 13 },`
                                    @{Label= "ErrorCode";           Expression={ $_.SessionErrorCode};          Width = 10 },`
                                    @{Label= "ErrorDescription";    Expression={ $_.SessionErrorDescription};   Width = 4096 } -Wrap

        # FINAL: print result table
        # Opting to print only a sub-section of the columns available.
        PrintErrors $_.Group
    }

    if($CsvPath)
    {
        $ResultTable | Select-Object SyncGroup,SyncDirection,SessionId,SessionTime,SessionSyncDirection,Operation,PersistentError,ItemPath,ErrorCode,ErrorDescription,InvalidCharCode,InvalidCharPosition,InvalidCharDescription | Export-Csv -NoTypeInformation -Path $CsvPath
        Write-Output "CSV file created: $CsvPath" 
    }
}
else
{
    Write-Output "There were no file errors found."
}

$global:SyncErrorModules.Clear()

Write-Output "Done."

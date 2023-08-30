
#
#  Copyright (C) Microsoft. All rights reserved.
#
#  THIS CODE IS PROVIDED *AS IS* WITHOUT WARRANTY OF
#  ANY KIND, EITHER EXPRESS OR IMPLIED, INCLUDING ANY
#  IMPLIED WARRANTIES OF FITNESS FOR A PARTICULAR
#  PURPOSE, MERCHANTABILITY, OR NON-INFRINGEMENT.
#

param(
    [switch]$Start,
    [switch]$Stop,
    [switch]$Continuous,
    [switch]$Cleanup,

    [int]$RecordSeconds,

    [switch]$OnAnomaly,
    [switch]$OnNamedEvent,

    [switch]$OnConnectivityError,
    [int[]]$OnConnectivityEventId,

    [switch]$OnSessionSetupTimeout,
    [int]$SessionSetupTimeoutInMs,

    [switch]$OnOperationalError,
    [int[]]$OnOperationalEventId,

    [switch]$OnSecurityError,
    [int[]]$OnSecurityEventId,

    [switch]$OnHighLatency,
    [switch]$OnHighAvgIOLatency,
    [int]$HighLatencyMs = 20000,
    [double]$HighLatencyPercentile = 1.0, # 0.99
    [int]$HighLatencyPercentileCount = 1,
    [int]$HighAvgIOLatencyMs = 5000,

    [switch]$OnCreditStall,
    [int]$CreditStallThreshold = 1000,

    [switch]$OnStatusCode,
    [int[]]$StatusCodes = @(),

    [int]$BufferSizeMB = 300,

    [int]$CounterSizeMB = 50,

    [string]$TempDirectory = "",
    [string]$OutputDirectory = ".",
    [int]$MaxOutputFiles = 10,

    [switch]$DetailedSmbTracing,
    [switch]$IncludeTcpLogs,

    [switch]$EnableAccessLog,

    [switch]$CaptureNetwork,
    [string[]]$NetworkAddress,
    [int]$NetworkBufferSizeMB,
    [int]$NetworkTruncationLength = 65535,
    [byte]$NetworkLevel = 4,
    [byte[]]$NetworkIpProtocols, # 6 for TCP

    [switch]$NoCompression,
    [switch]$UseCompression,

    [double]$RestartIntervalSeconds = 300,
    [int]$SampleIntervalSeconds = 1,

    [int]$SampleWindowSeconds = 1,

    [switch]$UseMemoryBuffer,
    [int]$AccessLogMemoryBufferLineCount = 1000000,

    [switch]$SkipKnownErrors,
    [string]$KnownConnectivityErrors = "30805, 30822",
    [int[]]$KnownOperationalErrors,
    [int[]]$KnownSecurityErrors,

    [string]$NamedEventName = "SmbClientLogsEvent",

    [string[]]$FlagsOverride,
    [string[]]$LevelOverride,

    [string[]]$Fskm,
    [string[]]$FskmAdd,
    [string[]]$FskmRemove,

    [switch]$Verbose,

    [switch]$AgentMode,

    [switch]$NoDateTimePrefix,

    [switch]$StopBeforeStart,

    [string[]]$LogChannels,

    [switch]$Silent

)

$ErrorActionPreference = "Stop"

$script:Settings = $null

function Get-IsElevated
{
    $principial = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $principial.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-Cmd
{
    $cmdName = $args[0]

    $cmdArgs = $args[1..($args.Length-1)]

    Write-Verbose "$cmdName $cmdArgs"

    $output = $null

    & $cmdName @cmdArgs 2>&1 | Write-Output -OutVariable output

    if (! $?)
    {
        $strOutput = $output | Out-String
        $msg = "$cmdName $cmdArgs\n$stroutput"
        Write-Error $msg
        throw $msg
    }
}

$script:PreviousEventsHashDict = @{}

function Get-WinEvent2
{
    param (
    [string]$logName,
    [int]$MaxEvents = 64,
    [switch]$SkipMessage)

    try
    {
        $query = [System.Diagnostics.Eventing.Reader.EventLogQuery]::new($logName, [System.Diagnostics.Eventing.Reader.PathType]::LogName)
        $query.ReverseDirection = $true
        $eventDetail = $null

        $reader = [System.Diagnostics.Eventing.Reader.EventLogReader]::new($query)

        for ($count = 0 ; $count -lt $MaxEvents; ++$count)
        {
            $eventDetail = $reader.ReadEvent();
            if (!$eventDetail)
            {
                break;
            }

            $message = ''

            if (! $SkipMessage)
            {
                $message = $eventDetail.FormatDescription()
            }

            $output = [PSCustomObject]@{
                RecordId = $eventDetail.RecordId
                Id = $eventDetail.Id
                Message = $message
                LevelDisplayName = $eventDetail.LevelDisplayName
                Level = $eventDetail.Level
                TimeCreated = $eventDetail.TimeCreated
            }

            Write-Output $output

            $eventDetail.Dispose()
            $eventDetail = $null
        }
    }
    catch
    {
        Write-Verbose "Get-WinEvent2 error $_"
    }
    finally
    {
        if ($eventDetail)
        {
            $eventDetail.Dispose()
        }

        $reader.Dispose()
    }
}

function Get-NewEventsInternal
{
    param(
        $LogName)

    $PreviousEventsHash = $script:PreviousEventsHashDict[$LogName]

    if (! $PreviousEventsHash)
    {
        throw "Eventshash not initialized"
    }

    $hasNewEvents = $false
    $getEventsSmall = @( Get-WinEvent2 -LogName $LogName -MaxEvents 1 -SkipMessage )

    if ($getEventsSmall)
    {
        $hasNewEvents = ! $previousEventsHash[ $getEventsSmall[0].RecordId ]
    }

    Write-Verbose "Get-WinEvent2 $LogName, count: $($getEventsSmall.Count), hasNewEvents: $hasNewEvents"

    if ($hasNewEvents)
    {
        $getEvents = @(Get-WinEvent2 -LogName $LogName -MaxEvents 256)

        Write-Verbose "Get-WinEvent2 $LogName, count: $($getEvents.Count)"

        $newEvents = @($getEvents | Where-Object { ! $previousEventsHash[$_.RecordId] })

        $newEvents | ForEach-Object{ $previousEventsHash[$_.RecordId] = $True; }

        return $newEvents
    }
}


function Get-SessionSetupTimeoutEventLogReasonHelper
{
    param([int]$timeoutTriggerInMs
    )

    $elapsedTimeStr = "ElapsedTime(ms):"
    $guidanceStr = "Guidance:"

    $events = Get-NewEventsInternal -LogName  "Microsoft-Windows-SMBClient/Connectivity"

    $matchingEvents = $events | Where-Object { ($_.Message.contains("Command: Session setup") )}

    foreach($evt in $matchingEvents)
    {
       $strIndex = $evt.Message.LastIndexOf($elapsedTimeStr)+$elapsedTimeStr.length
       $length = $evt.Message.LastIndexOf($guidanceStr)-$strIndex
       [int]$timeout = $evt.Message.Substring($strIndex, $length)

       if($timeout -gt $timeoutTriggerInMs)
       {
            return "SessionSetupTimeOut$timeout"
       }
    }
}

function Get-EventLogReasonHelper
{
    param(
        [string]$shortName,
        [string]$logName,
        [switch]$onError,
        [int[]]$eventId,
        [int[]]$knownErrors
    )

    $settings = Get-Settings

    if ($onError -or $eventId)
    {
        $events = Get-NewEventsInternal -LogName $logName

        if ($onError)
        {
            $matchingEvents = $events | Where-Object { $_.Level -le 2 }

            if ($matchingEvents -and $settings.SkipKnownErrors -and $knownErrors)
            {
                $matchingEvents = $events | Where-Object { ! ($knownErrors -contains $_.Id) }
            }

            if ($matchingEvents)
            {
                return "$shortName-$($matchingEvents[0].Id)"
            }
        }

        if ($eventId)
        {
            $matchingEvents = $events | Where-Object { $eventId -contains $_.Id }

            if ($matchingEvents)
            {
                return "$shortName-$($matchingEvents[0].Id)"
            }
        }
    }
}

function Initialize-EventLogHelper
{
    param ([string]$logName)

    $script:PreviousEventsHashDict[$LogName] = @{}

    Get-NewEventsInternal $LogName | Out-Null
}


function Initialize-EventLog
{
    $settings = Get-Settings

    if ($settings.OnConnectivityError -or $settings.OnConnectivityEventId -or $settings.OnSessionSetupTimeout)
    {
        Initialize-EventLogHelper "Microsoft-Windows-SMBClient/Connectivity"
    }

    if ($settings.OnOperationalError -or $settings.OnOperationalEventId)
    {
        Initialize-EventLogHelper "Microsoft-Windows-SMBClient/Operational"
    }

    if ($settings.OnSecurityError -or $settings.OnSecurityEventId)
    {
        Initialize-EventLogHelper "Microsoft-Windows-SMBClient/Security"
    }
}

function Get-EventLogReason
{
    $settings = Get-Settings

    $reason = ''

    if (!$reason -and $settings.OnSessionSetupTimeout)
    {
       $reason = Get-SessionSetupTimeoutEventLogReasonHelper $settings.SessionSetupTimeoutInMs
    }

    if (!$reason)
    {
        $reason = Get-EventLogReasonHelper "Connectivity" "Microsoft-Windows-SMBClient/Connectivity" -onError:$settings.OnConnectivityError  -eventId $settings.OnConnectivityEventId -knownErrors $settings.KnownConnectivityErrors
    }

    if (!$reason)
    {
        $reason = Get-EventLogReasonHelper "Operational" "Microsoft-Windows-SMBClient/Operational" -onError:$settings.OnOperationalError  -eventId $settings.OnOperationalEventId -knownErrors $settings.KnownOperationalErrors
    }

    if (!$reason)
    {
        $reason = Get-EventLogReasonHelper "Security" "Microsoft-Windows-SMBClient/Security" -onError:$settings.OnSecurityError -eventId $settings.OnSecurityEventId -knownErrors $settings.KnownSecurityErrors
    }

    return $reason
}


function Get-NamedEventReason
{
    $settings = Get-Settings

    if ($settings.OnNamedEvent -and $script:NamedEvent -and $script:NamedEvent.WaitOne(0))
    {
        return "NamedEvent"
    }

    return ""
}

$global:SmbAccessLogInstanceTypeLoaded = $false
function Get-SmbAccessLogType
{
    if (!$global:SmbAccessLogInstanceTypeLoaded)
    {
        $code = @'

namespace SmbAccessLog
{
    using System;
    using System.Collections.Generic;
    using System.ComponentModel;
    using System.Globalization;
    using System.IO;
    using System.Linq;
    using System.Runtime.InteropServices;
    using System.Text;
    using System.Threading;

    using SmbPacketId = System.Tuple<long, ulong, ulong>; // fragment.PeerAddressHash, SessionId, packet.Header.MessageId

    public enum SmbCommand : ushort
    {
        Negotiate = 0x0000,
        SessionSetup = 0x0001,
        Logoff = 0x0002,
        TreeConnect = 0x0003,
        TreeDisconnect = 0x0004,
        Create = 0x0005,
        Close = 0x0006,
        Flush = 0x0007,
        Read = 0x0008,
        Write = 0x0009,
        Lock = 0x000A,
        Ioctl = 0x000B,
        Cancel = 0x000C,
        Echo = 0x000D,
        QueryDirectory = 0x000E,
        ChangeNotify = 0x000F,
        QueryInfo = 0x0010,
        SetInfo = 0x0011,
        OplockBreak = 0x0012,
        MaxIndex = 0x0013
    }

    [StructLayout(LayoutKind.Explicit)]
    public struct SmbPacketHeader
    {
        [FieldOffset(0)] public uint ProtocolId;

        [FieldOffset(8)] public uint Status;

        [FieldOffset(6)] public ushort CreditCharge;

        [FieldOffset(12)] public SmbCommand Command;

        [FieldOffset(14)] public uint Credit;

        [FieldOffset(16)] public ushort Flags;

        [FieldOffset(24)] public ulong MessageId;

        [FieldOffset(20)] public uint NextCommand;

        [FieldOffset(36)] public ushort TreeId;

        [FieldOffset(40)] public ulong SessionId;
    }

    public struct Fragment
    {
        public DateTime StartTime;

        public long PeerAddressHash;

        public byte[] PreviousBuffer;

        public int NextBufferOffset;

    }

    public struct SmbPacket
    {
        public DateTime TimeStamp;

        public TimeSpan Elapsed;

        public SmbPacketHeader Header;

        public bool IsResponse;

        public static string CsvHeader = "TimeStamp,SessionId,TreeId,MessageId,Command,Status,Response,Flags,CreditCharge,Credit,ElapsedMs\r\n";

        public string ToNameValue()
        {
            var names = CsvHeader.Trim().Split(',');
            var values = ToString().Trim().Split(',');
            var n = Math.Min(names.Length, values.Length);
            var sb = new StringBuilder();

            for (var i = 0; i < n; ++i)
            {
                if (i > 0)
                {
                    sb.Append(';');
                }
                sb.Append(names[i]);
                sb.Append('=');
                sb.Append(values[i]);
            }

            return sb.ToString();
        }

        public override string ToString()
        {
            var sb = new StringBuilder();

            sb.Append(TimeStamp.ToString("yyyy-MM-dd HH:mm:ss.fff"));
            sb.Append(',');

            sb.Append("0x");
            sb.Append(Header.SessionId.ToString("x"));
            sb.Append(',');

            sb.Append(Header.TreeId);
            sb.Append(',');

            sb.Append("0x");
            sb.Append(Header.MessageId.ToString("x"));
            sb.Append(',');

            sb.Append(Header.Command);
            sb.Append(',');

            sb.Append("0x");
            sb.Append(Header.Status.ToString("x8"));
            sb.Append(',');

            sb.Append(IsResponse);
            sb.Append(',');

            sb.Append("0x");
            sb.Append(Header.Flags.ToString("x"));
            sb.Append(',');

            sb.Append(Header.CreditCharge);
            sb.Append(',');

            sb.Append(Header.Credit);
            sb.Append(',');

            sb.Append(Elapsed.TotalMilliseconds.ToString(CultureInfo.InvariantCulture));

            sb.AppendLine();

            return sb.ToString();
        }
    }

    public class SmbAccessLog : IDisposable
    {
        private long traceHandle = -1;

        private int currentFileNameIndex;

        private Thread thread;

        private EventTraceLogfile logFile;

        private StreamWriter textFile;

        private readonly Dictionary<SmbPacketId, DateTime> runningMessages = new Dictionary<SmbPacketId, DateTime>();

        private readonly Dictionary<Guid, Fragment> fragments = new Dictionary<Guid, Fragment>();

        private readonly Queue<SmbPacket> logs = new Queue<SmbPacket>();

        private DateTime nextFlush = DateTime.UtcNow;

        // percentile begin

        private SmbPacket? highLatencyPacketMax;

        private int highLatencyPacketCount;

        private int lowLatencyPacketCount;

        private DateTime nextHighLatencyCheck;

        // percentile end

        public string LoggerName { get; set; }

        public int TextFileSizeLimitMB { get; set; }

        public string FileNamePrefix { get; set; }

        public TimeSpan FlushInterval { get; set; }

        public double HighLatencyMs { get; set; }

        public double HighLatencyPercentile { get; set; }

        public int HighLatencyPercentileCount { get; set; }

        public List<uint> StatusCodesToFind { get; set; }

        public SmbPacket? HighLatencyPacket { get; set; }

        public SmbPacket? StatusCodePacket { get; set; }

        public int MemoryBufferLineCount { get; set; }

        public int MemoryBufferMB { get; set; }

        ~SmbAccessLog()
        {
            Cleanup();
        }

        public SmbAccessLog()
        {
            LoggerName = "SmbClientLogs-Packets";
            TextFileSizeLimitMB = 100;
            FileNamePrefix = "SmbAccessLog-";
            FlushInterval = TimeSpan.FromSeconds(5);
            HighLatencyMs = 1000.0;
            HighLatencyPercentile = 1.0;
            HighLatencyPercentileCount = 1;
        }

        public void Start()
        {
            if (StatusCodesToFind != null)
            {
                StatusCodesToFind.Sort();
            }

            if (MemoryBufferMB > 0)
            {
                var c = (((long)MemoryBufferMB) * 1024 * 1024) / (2 * Marshal.SizeOf<SmbPacket>());

                if (c < MemoryBufferLineCount || MemoryBufferLineCount <= 0)
                {
                    MemoryBufferLineCount = (int)c;
                }
            }

            logFile = new EventTraceLogfile
            {
                LoggerName = LoggerName,
                EventRecordCallback = new EventRecordCallback(EventRecordCallbackWrapper),
                ProcessTraceMode = 268435712U
            };

            traceHandle = NativeMethods.OpenTrace(ref logFile);
            if (traceHandle == -1)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            thread = new Thread(ThreadProc);
            thread.IsBackground = true;
            thread.Start();
        }

        public void StopAndFlush()
        {
            Cleanup();
            while (logs.Count > 0)
            {
                WritePacketToFile(logs.Dequeue());
            }
            if (textFile != null)
            {
                textFile.Flush();
                textFile.Dispose();
            }
        }

        public void Dispose()
        {
            Cleanup();
            GC.SuppressFinalize(this);
        }

        string GetFileName(int index)
        {
            return FileNamePrefix + index.ToString("D8") + ".csv";
        }

        void WritePacketToFile(SmbPacket packet)
        {
            if (textFile == null || textFile.BaseStream.Position / (1024 * 1024) >= TextFileSizeLimitMB)
            {
                if (textFile != null)
                {
                    textFile.Close();
                    textFile.Dispose();
                }

                if (currentFileNameIndex >= 1)
                {
                    var oldFileName = GetFileName(currentFileNameIndex - 1);
                    if (File.Exists(oldFileName))
                    {
                        File.Delete(oldFileName);
                    }
                }

                ++currentFileNameIndex;
                textFile = new StreamWriter(GetFileName(currentFileNameIndex), true, Encoding.ASCII, 512 * 1024);
                if (textFile.BaseStream.Position == 0)
                {
                    textFile.Write(SmbPacket.CsvHeader);
                }
            }

            textFile.Write(packet.ToString());

            var now = DateTime.UtcNow;
            if (now >= nextFlush)
            {
                textFile.Flush();
                nextFlush = now + FlushInterval;
            }
        }

        void OnPacket(ref SmbPacket packet, DateTime now)
        {
            if (MemoryBufferLineCount > 0)
            {
                if (logs.Count >= MemoryBufferLineCount)
                {
                    logs.Dequeue();
                }

                logs.Enqueue(packet);
            }
            else
            {
                WritePacketToFile(packet);
            }

            if (packet.IsResponse)
            {
                if (packet.Elapsed.TotalMilliseconds >= HighLatencyMs)
                {
                    if (highLatencyPacketMax == null || packet.Elapsed > highLatencyPacketMax.Value.Elapsed)
                    {
                        highLatencyPacketMax = packet;
                    }

                    ++highLatencyPacketCount;
                }
                else
                {
                    ++lowLatencyPacketCount;
                }

                if (nextHighLatencyCheck <= now)
                {
                    if (HighLatencyPacket == null &&
                        highLatencyPacketMax != null &&
                        highLatencyPacketCount >= Math.Max(HighLatencyPercentileCount,
                                                           (lowLatencyPacketCount + highLatencyPacketCount) * (1.0 - HighLatencyPercentile)))
                    {
                        HighLatencyPacket = highLatencyPacketMax;
                    }

                    lowLatencyPacketCount = 0;
                    highLatencyPacketCount = 0;
                    highLatencyPacketMax = null;
                    nextHighLatencyCheck = now + TimeSpan.FromSeconds(1);
                }
            }

            if (StatusCodesToFind != null && StatusCodesToFind.BinarySearch(packet.Header.Status) >= 0)
            {
                StatusCodePacket = packet;
            }
        }

        long ReadPeerAddressHash(IntPtr data, int length, out int consumed)
        {
            IntPtr initialData = data;
            consumed = 0;
            if (length <= 0)
            {
                return 0;
            }

            ulong end = (ulong)data + (ulong)length;

            data += 4; // ConnectionType

            if ((ulong)data + 4 > end)
            {
                return 0;
            }

            var peerAddressLength = Marshal.ReadInt32(data);
            data += 4;

            if ((ulong)data + (ulong)peerAddressLength > end)
            {
                return 0;
            }

            long peerAddressHash = 0;
            int i = peerAddressLength;
            while (i > 0)
            {
                if (i >= 8)
                {
                    peerAddressHash *= 1046527;
                    peerAddressHash ^= Marshal.ReadInt64(data);
                    data += 8;
                    i -= 8;
                }
                else if (i >= 4)
                {
                    peerAddressHash *= 947;
                    peerAddressHash ^= Marshal.ReadInt32(data);
                    data += 4;
                    i -= 4;
                }
                else
                {
                    peerAddressHash *= 31;
                    peerAddressHash ^= Marshal.ReadByte(data);
                    data += 1;
                    i -= 1;
                }
            }

            data += 4; // PacketSize

            if (end >= (ulong)data)
            {
                consumed = (int)((ulong)data - (ulong)initialData);

                return peerAddressHash;
            }

            return 0;
        }

        static readonly int SmbHeaderSize = Marshal.SizeOf<SmbPacketHeader>();

        bool ReadSmbPacket(ref SmbPacket packet, IntPtr data, ulong end, DateTime now, Fragment fragment)
        {
            if ((ulong)data + (ulong)SmbHeaderSize > end)
            {
                return false;
            }

            packet.Header = Marshal.PtrToStructure<SmbPacketHeader>(data);

            if (packet.Header.ProtocolId == 1112364031)
            {
                packet.Header = new SmbPacketHeader();
                packet.Header.Command = SmbCommand.Negotiate;
            }
            else if (packet.Header.ProtocolId != 0x424D53FE)
            {
                return false;
            }

            var isRequest = packet.Header.Flags % 2 == 0;

            packet.TimeStamp = now;
            packet.IsResponse = !isRequest;

            if (packet.Header.Command != SmbCommand.ChangeNotify && packet.Header.Command != SmbCommand.OplockBreak)
            {
                var key = new SmbPacketId(fragment.PeerAddressHash, packet.Header.Command == SmbCommand.SessionSetup ? 0 : packet.Header.SessionId, packet.Header.MessageId);

                if (isRequest)
                {
                    packet.TimeStamp = fragment.StartTime;
                }

                DateTime requestStartTime;

                if (isRequest)
                {
                    if (!runningMessages.ContainsKey(key))
                    {
                        runningMessages.Add(key, now);
                    }

                    if (runningMessages.Count > 250 * 1000)
                    {
                        foreach (var kp in runningMessages.OrderBy(item => item.Value).Take(runningMessages.Count / 2).ToList())
                        {
                            runningMessages.Remove(kp.Key);
                        }
                    }
                }
                else if (runningMessages.TryGetValue(key, out requestStartTime))
                {
                    packet.Elapsed = now - requestStartTime;
                    runningMessages.Remove(key);
                }
            }

            OnPacket(ref packet, now);

            return true;
        }

        void ProcessSmb(Guid activityId, DateTime now, Fragment fragment, IntPtr data, int length, bool isLast)
        {
            data += fragment.NextBufferOffset;
            length -= fragment.NextBufferOffset;

            if (length <= 0)
            {
                if (!isLast)
                {
                    fragment.NextBufferOffset = -length;
                    fragments.Add(activityId, fragment);
                }

                return;
            }

            ulong end = (ulong)data + (ulong)length;

            if (fragment.PreviousBuffer != null && fragment.PreviousBuffer.Length > 0)
            {
                var len2 = Math.Min(SmbHeaderSize, fragment.PreviousBuffer.Length + length);
                var data2 = Marshal.AllocHGlobal(len2);
                try
                {
                    var newBufferChunk = new byte[len2 - fragment.PreviousBuffer.Length];
                    Marshal.Copy(data, newBufferChunk, 0, newBufferChunk.Length);

                    Marshal.Copy(fragment.PreviousBuffer, 0, data2, fragment.PreviousBuffer.Length);
                    Marshal.Copy(newBufferChunk, 0, data2 + fragment.PreviousBuffer.Length, newBufferChunk.Length);

                    var packet = new SmbPacket();

                    if (!ReadSmbPacket(ref packet, data2, (ulong)data2 + (ulong)len2, now, fragment))
                    {
                        return;
                    }

                    if (packet.Header.NextCommand != 0)
                    {
                        data += (int)packet.Header.NextCommand;
                    }
                    else
                    {
                        return;
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(data2);
                }
            }

            while (true)
            {
                if ((ulong)data + (ulong)SmbHeaderSize > end)
                {
                    if ((ulong)data >= end)
                    {
                        fragment.PreviousBuffer = null;
                        fragment.NextBufferOffset = (int)((ulong)data - end);
                    }
                    else
                    {
                        fragment.PreviousBuffer = new byte[(int)(end - (ulong)data)];
                        Marshal.Copy(data, fragment.PreviousBuffer, 0, fragment.PreviousBuffer.Length);
                        fragment.NextBufferOffset = 0;
                    }

                    fragments.Add(activityId, fragment);
                    return;
                }

                var packet = new SmbPacket();

                if (!ReadSmbPacket(ref packet, data, end, now, fragment))
                {
                    return;
                }

                if (packet.Header.NextCommand != 0)
                {
                    data += (int)packet.Header.NextCommand;
                }
                else
                {
                    break;
                }
            }
        }

        void EventRecordCallbackWrapper([In] ref EventRecord eventRecord)
        {
            if (thread != null)
            {
                try
                {
                    EventRecordCallback(ref eventRecord);
                }
                catch
                {
                }
            }
        }

        void EventRecordCallback([In] ref EventRecord eventRecord)
        {
            const ulong StartKeyword = 0x40000000;
            const ulong EndKeyword = 0x80000000;

            if (eventRecord.UserData == IntPtr.Zero || eventRecord.UserDataLength == 0)
            {
                return;
            }

            var now = DateTime.FromFileTimeUtc(eventRecord.EventHeader.TimeStamp);
            var consumed = 0;

            if (eventRecord.EventHeader.EventDescriptor.Id == 40000)
            {
                var fragment = new Fragment
                {
                    StartTime = now,
                    PeerAddressHash = ReadPeerAddressHash(eventRecord.UserData, eventRecord.UserDataLength, out consumed)
                };

                ProcessSmb(eventRecord.EventHeader.ActivityId, now, fragment, eventRecord.UserData + consumed, eventRecord.UserDataLength - consumed, true);
            }
            else if (eventRecord.EventHeader.EventDescriptor.Id == 2000)
            {
                var isLast = (eventRecord.EventHeader.EventDescriptor.Keyword & EndKeyword) == EndKeyword;

                if ((eventRecord.EventHeader.EventDescriptor.Keyword & StartKeyword) == StartKeyword)
                {
                    fragments.Add(eventRecord.EventHeader.ActivityId, new Fragment
                    {
                        StartTime = now,
                        PeerAddressHash = ReadPeerAddressHash(eventRecord.UserData + 6, eventRecord.UserDataLength - 6, out consumed),
                        PreviousBuffer = new byte[0]
                    });
                }
                else
                {
                    Fragment fragment;
                    if (fragments.Count > 0 && fragments.TryGetValue(eventRecord.EventHeader.ActivityId, out fragment))
                    {
                        fragments.Remove(eventRecord.EventHeader.ActivityId);

                        ProcessSmb(eventRecord.EventHeader.ActivityId, now, fragment, eventRecord.UserData + 6, eventRecord.UserDataLength - 6, isLast);
                    }
                }
            }
        }

        void Cleanup()
        {
            var oldHandle = Interlocked.Exchange(ref traceHandle, -1);

            if (oldHandle != -1)
            {
                NativeMethods.CloseTrace(oldHandle);
            }

            var oldThread = Interlocked.Exchange(ref thread, null);

            if (oldThread != null)
            {
                try
                {
                    if (Thread.CurrentThread.ManagedThreadId != oldThread.ManagedThreadId && !oldThread.Join(TimeSpan.FromSeconds(10)))
                    {
                        oldThread.Abort();
                    }
                }
                catch
                {

                }
            }

            var oldFile = Interlocked.Exchange(ref textFile, null);
            if (oldFile != null)
            {
                oldFile.Dispose();
            }
        }

        void ThreadProc()
        {
            NativeMethods.ProcessTrace(new[] { traceHandle }, 1, IntPtr.Zero, IntPtr.Zero);
            Cleanup();
        }
    }

    class NativeMethods
    {
        [DllImport("advapi32.dll", EntryPoint = "OpenTraceW", CharSet = CharSet.Unicode, SetLastError = true)]
        [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
        public static extern long OpenTrace([In, Out] ref EventTraceLogfile logfile);

        [DllImport("advapi32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
        public static extern int ProcessTrace(
            [In] long[] handleArray,
            [In] uint handleCount,
            [In] IntPtr startTime,
            [In] IntPtr endTime);

        [DllImport("advapi32.dll")]
        [DefaultDllImportSearchPaths(DllImportSearchPath.SafeDirectories)]
        public static extern int CloseTrace(long traceHandle);
    }

    struct EtwEventDescriptor
    {
        public ushort Id;
        public byte Version;
        public byte Channel;
        public byte Level;
        public byte Opcode;
        public ushort Task;
        public ulong Keyword;
    }

    struct EventHeader
    {
        public ushort Size;
        public ushort HeaderType;
        public ushort Flags;
        public ushort EventProperty;
        public uint ThreadId;
        public uint ProcessId;
        public long TimeStamp;
        public Guid ProviderId;
        public EtwEventDescriptor EventDescriptor;
        public ulong ProcessorTime;
        public Guid ActivityId;
    }

    struct EventRecord
    {
        public EventHeader EventHeader;
        public uint BufferContext;
        public ushort ExtendedDataCount;
        public ushort UserDataLength;
        public IntPtr ExtendedData;
        public IntPtr UserData;
        public IntPtr UserContext;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct EventTraceLogfile
    {
        [MarshalAs(UnmanagedType.LPWStr)] internal string LogFileName;
        [MarshalAs(UnmanagedType.LPWStr)] internal string LoggerName;
        public long CurrentTime;
        public uint BuffersRead;
        public uint ProcessTraceMode;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] internal IntPtr[] Padding1;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 360)] internal byte[] Padding2;
        public EventRecordCallback EventRecordCallback;
        public uint IsKernelTrace;
        public IntPtr Context;
    }

    internal delegate void EventRecordCallback([In] ref EventRecord eventRecord);
}

'@

        try
        {
            Add-Type -TypeDefinition $code -IgnoreWarnings | Out-Null
        }
        catch
        {
            $_.Exception.LoaderExceptions | Write-Host
            throw
        }
        $global:SmbAccessLogInstanceTypeLoaded = $true
    }
}

$global:SmbAccessLogInstance = $null

function Start-SmbAccessLog
{
    param(
        [string]$directory,
        [string]$prefix)

    Stop-SmbAccessLog | Out-Null

    $settings = Get-Settings
    $name = "accesslog"

    Write-Log "Start access log trace $($prefix + $name)"

    $bufferSizeKB = 256
    $bufferCount = 32
    $flushTimerSec = 1

    if (Get-Command 'Start-EtwTraceSession' -ErrorAction SilentlyContinue)
    {
        $EVENT_TRACE_REAL_TIME_MODE = 0x00000100
        $mode = $EVENT_TRACE_REAL_TIME_MODE

        $result = Start-EtwTraceSession -name ($prefix + $name) -LogFileMode $mode -BufferSize $bufferSizeKB -MinimumBuffers $bufferCount -MaximumBuffers $bufferCount -FlushTimer $flushTimerSec
        if (!$result)
        {
            throw "Start-EtwTraceSession failed"
        }

        $result = Add-EtwTraceProvider -Guid "{988C59C5-0A1C-45B6-A555-0C62276E327D}" -Sessionname ($prefix + $name) -MatchAnyKeyword 0x0800440300000000 -Level 7
        if (!$result)
        {
            throw "Add-EtwTraceProvider failed"
        }
    }
    else
    {
        Invoke-Cmd logman create trace -n ($prefix + $name) -rt -nb $bufferCount $bufferCount -bs $bufferSizeKB -ets | Write-verbose
        Invoke-Cmd logman update -n ($prefix + $name) -p "{988C59C5-0A1C-45B6-A555-0C62276E327D}" "0x0800440300000000" 7 -ets | Write-Verbose
    }

    Get-SmbAccessLogType | Out-Null
    $global:SmbAccessLogInstance = [SmbAccessLog.SmbAccessLog]::new()
    $global:SmbAccessLogInstance.LoggerName = $prefix + $name
    $global:SmbAccessLogInstance.TextFileSizeLimitMB = $settings.BufferSizeMB
    $global:SmbAccessLogInstance.FileNamePrefix = Join-Path $directory $name
    $global:SmbAccessLogInstance.HighLatencyMs = $settings.HighLatencyMs
    $global:SmbAccessLogInstance.HighLatencyPercentile = $settings.HighLatencyPercentile
    $global:SmbAccessLogInstance.HighLatencyPercentileCount = $settings.HighLatencyPercentileCount
    if ($settings.StatusCodes)
    {
        $global:SmbAccessLogInstance.StatusCodesToFind = $settings.StatusCodes
    }
    if ($settings.UseMemoryBuffer)
    {
        $global:SmbAccessLogInstance.MemoryBufferLineCount = $settings.AccessLogMemoryBufferLineCount
        $global:SmbAccessLogInstance.MemoryBufferMB = $settings.BufferSizeMB
    }

    $global:SmbAccessLogInstance.Start()
}

function Stop-SmbAccessLog
{
    param(
        [string]$ExcludePrefix,
        [switch]$CreatePackage
    )

    if ($global:SmbAccessLogInstance -and ( !$ExcludePrefix -or  ! $global:SmbAccessLogInstance.LoggerName.StartsWith($ExcludePrefix)))
    {
        Write-Log "Stop access log tracer"
        if ($CreatePackage)
        {
            $global:SmbAccessLogInstance.StopAndFlush() | Out-Null
        }

        $global:SmbAccessLogInstance.Dispose()
        $global:SmbAccessLogInstance = $null
    }
}

function Get-SmbAccessLogReason
{
    $settings = Get-Settings

    if ($global:SmbAccessLogInstance)
    {
        if ($settings.OnHighLatency)
        {
            $packet = $global:SmbAccessLogInstance.HighLatencyPacket

            if ($packet)
            {
                [int]$latency = $packet.Elapsed.TotalMilliseconds

                return "AccessLogLatency-$($packet.Header.Command)-$latency-ms;$($packet.ToNameValue())"
            }
        }

        if ($settings.OnStatusCode)
        {
            $packet = $global:SmbAccessLogInstance.StatusCodePacket

            if ($packet)
            {
                return "StatusCode-$($packet.Header.Command)-0x$($packet.Header.Status.ToString("x8"));$($packet.ToNameValue())"
            }
        }
    }
}

function Get-CounterReason
{
    $settings = Get-Settings

    if ($settings.OnHighAvgIOLatency -or $settings.OnCreditStall)
    {
        $counters = @()

        if ($settings.OnHighAvgIOLatency)
        {
            $counters += @(
                "\SMB Client Shares(*)\avg. sec/write"
                "\SMB Client Shares(*)\avg. sec/read"
            )
        }

        if ($settings.OnCreditStall)
        {
            $counters += @(
                "\SMB Client Shares(*)\credit stalls/sec"
            )
        }

        $values = Get-Counter $counters -SampleInterval $settings.SampleIntervalSeconds -MaxSamples $settings.SampleWindowSeconds -ErrorAction SilentlyContinue

        $latencyMs = $settings.HighAvgIOLatencyMs
        if (!$latencyMs)
        {
            $latencyMs = $settings.HighLatencyMs
        }


        $sumWriteLatencyDict = @{}
        $sumReadLatencyDict = @{}
        $sumCreditStallDict = @{}

        foreach ($value in $values)
        {
            if ($value)
            {
                foreach ($sample in $value.CounterSamples)
                {
                    if($sample.InstanceName.Contains("_total"))
                    {
                         continue;
                    }

                     $sumCreditStallDict[$sample.InstanceName] = 0
                     $sumReadLatencyDict[$sample.InstanceName] = 0
                     $sumWriteLatencyDict[$sample.InstanceName] = 0
                }
            }
        }

        foreach ($value in $values)
        {
            if ($value)
            {

                Write-Verbose "Get-Counter samples: $($value.CounterSamples), latencyMs: $latencyMs"

                foreach ($sample in $value.CounterSamples)
                {
                    if($sample.InstanceName.Contains("_total"))
                    {
                         continue;
                    }

                    if ($settings.OnHighAvgIOLatency)
                    {
                        if ($sample.Path.EndsWith('avg. sec/write'))
                        {
                            $sumWriteLatencyDict[$sample.InstanceName] = $sumWriteLatencyDict[$sample.InstanceName] +  ($sample.CookedValue * 1000 )
                        }
                        elseif ($sample.Path.EndsWith('avg. sec/read'))
                        {
                            $sumReadLatencyDict[$sample.InstanceName] = $sumReadLatencyDict[$sample.InstanceName] +  ($sample.CookedValue * 1000 )
                        }
                    }

                    if ($settings.OnCreditStall)
                    {
                        $sumCreditStallDict[$sample.InstanceName] = $sumCreditStallDict[$sample.InstanceName] + $sample.CookedValue
                    }
                }
            }
            else
            {
                Write-Verbose "Get-Counter no samples, sleeping: $($settings.SampleIntervalSeconds)"
                Start-Sleep $settings.SampleIntervalSeconds
            }
        }

        if($values -ne $null -and $values.count -gt 0)
        {
            foreach($share in  $sumCreditStallDict.Keys)
            {
                [int]$avgWriteLatency = $sumWriteLatencyDict[$share]/$values.count
                [int]$avgReadLatency = $sumReadLatencyDict[$share]/$values.count
                [int]$avgCreditStall = $sumCreditStallDict[$share]/$values.count

                $smaples = $values.count
                $sumWriteLatency = $sumWriteLatencyDict[$share]
                $sumReadLatency = $sumReadLatencyDict[$share]
                $sumCreditStall = $sumCreditStallDict[$share]

                Write-Log "Share $share Time $smaples  WriteLatencyTotal $sumWriteLatency WriteLatencyAvg $avgWriteLatency "
                Write-Log "Share $share Time $smaples ReadLatencyTotal $sumReadLatency ReadLatencyAvg $avgReadLatency"
                Write-Log "Share $share Time $smaples CreditStallTotal $sumCreditStall CreditStallAvg $avgCreditStall"

                $nShare = $share.Replace("\","--")
                if($avgWriteLatency -ge $latencyMs)
                {
                    return "AvgIOLatency-Write-$avgWriteLatency-$nShare"
                }

                if($avgReadLatency -ge $latencyMs)
                {
                    return "AvgIOLatency-Read-$avgReadLatency-$nShare"
                }

               if($avgCreditStall -ge $settings.CreditStallThreshold)
               {
                    return "CreditStal-$avgCreditStall-$nShare"
               }
            }
        }
    }
}

function Get-Settings
{
    return $script:Settings
}

function Set-Settings
{
    param($settingsDict)

    $settingsDict = @{} + $settingsDict

    $agentMode = ! ! $settingsDict['AgentMode']

    if (!$settingsDict['Stop'] -and !$settingsDict['Cleanup'] -and !$settingsDict['Continuous'])
    {
        $settingsDict['StopBeforeStart'] = $true
    }

    if ($settingsDict['OnAnomaly'])
    {
        $settingsDict['OnConnectivityError'] = $true
        $settingsDict['OnOperationalError'] = $true
        $settingsDict['OnSecurityError'] = $true
        $settingsDict['OnHighAvgIOLatency'] = $true
        $settingsDict['OnCreditStall'] = $true
        $settingsDict['OnNamedEvent'] = $true
        $settingsDict['OnSessionSetupTimeout'] = $true

        if (! $agentMode)
        {
            $settingsDict['OnHighLatency'] = $true
            $settingsDict['OnStatusCode'] = $true
        }
    }

   if ($settingsDict['OnSessionSetupTimeout'])
   {
       $SessionSetupTimeoutInMs = 60000
   }

    if ($settingsDict['OnHighLatency'] -or $settingsDict['OnStatusCode'])
    {
        $settingsDict['EnableAccessLog'] = $true
    }

    if (!$settingsDict['LogChannels'])
    {
        if ($agentMode)
        {
            $settingsDict['LogChannels'] = @('fskm')
        }
        else
        {
            $settingsDict['LogChannels'] = @('fskm', 'fsum', 'rpcxdr', 'sec', 'counters')
        }
    }

    if (!$settingsDict['Fskm'])
    {
        $settingsDict['Fskm'] = @('handle', 'network', 'io', 'readwrite')
    }

    if ($agentMode)
    {
        $settingsDict['StopBeforeStart'] = $true
        $settingsDict['NoCompression'] = $true
    }

    if ($settingsDict['UseCompression'])
    {
        $settingsDict['NoCompression'] = $false
    }

    $settingsDict['LogChannels'] = [string[]] ($settingsDict['LogChannels'])

    if ($settingsDict['IncludeTcpLogs'])
    {
        $settingsDict['LogChannels'] += 'tcp'
    }

    if ($settingsDict['CaptureNetwork'])
    {
        $settingsDict['LogChannels'] += 'networkcapture'
    }

    if ($settingsDict['EnableAccessLog'])
    {
        $settingsDict['LogChannels'] += 'accesslog'
    }

    if ($settingsDict['TempDirectory'])
    {
        $settingsDict['TempDirectory'] = [IO.Path]::GetFullPath($settingsDict['TempDirectory'])
    }

    if ($settingsDict['OutputDirectory'])
    {
        $settingsDict['OutputDirectory'] = [IO.Path]::GetFullPath($settingsDict['OutputDirectory'])
    }

    if ($settingsDict['KnownConnectivityErrors'])
    {
        $settingsDict['KnownConnectivityErrors'] = [int[]] ($settingsDict['KnownConnectivityErrors'].Split(','))
    }

    $script:Settings = [PSCustomObject]$settingsDict
}

function Invoke-LogSettings
{
    $settings = Get-Settings
    $keys = $settings | Get-Member -MemberType NoteProperty | Select-Object -ExpandProperty Name

    foreach ($key in $keys)
    {
        if ($settings.$key)
        {
            if ($settings.$key -is [array])
            {
                Write-Log "Setting $key = $($settings.$key -join ', ')"
            }
            else
            {
                Write-Log "Setting $key = $($settings.$key)"
            }
        }
    }
}

function Get-IsCounterBased
{
    $settings = Get-Settings

    $eventBasedSettingsNames = @(
        'OnHighAvgIOLatency'
        'OnCreditStall'
    )

    foreach ($name in $eventBasedSettingsNames)
    {
        if ($settings.$name)
        {
            return $true
        }
    }

    return $false
}

function Get-EventBasedSettingsDict
{
    $settings = Get-Settings

    $result = @{}

    $eventBasedSettingsNames = @(
        "OnConnectivityError"
        "OnConnectivityEventId"
        "OnOperationalError"
        "OnOperationalEventId"
        "OnSecurityError"
        "OnSecurityEventId"
        "OnHighLatency"
        "OnStatusCode"
        "OnCreditStall"
        "OnSessionSetupTimeout"
    )

    foreach ($name in $eventBasedSettingsNames)
    {
        if ($settings.$name)
        {
            $result[$name] = $settings.$name
        }
    }

    return $result
}

function Get-IsEventBased
{
    return (Get-EventBasedSettingsDict).Count -gt 0
}

function Get-MainPrefix
{
    return "SmbClientLogs"
}

function Get-DirectoryPrefix
{
    return "$(Get-MainPrefix)-$env:computername"
}

function Get-DirectoryPrefixFilter
{
    return (Get-DirectoryPrefix) + "*"
}

function New-TracePrefix
{
    $prefix = (Get-MainPrefix) + "-" + [Guid]::NewGuid().ToString("N") + "-"
    Write-Verbose "New-TracePrefix $prefix"
    return $prefix
}

function Get-RunningDirectory
{
    $path = $settings.TempDirectory

    if (!$path)
    {
        $path = $settings.OutputDirectory
    }

    return $path
}

function New-Directory
{
    $settings = Get-Settings
    $path = Get-RunningDirectory

    $date = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd-HH-mm-ss")
    $namePrefix = "$(Get-DirectoryPrefix)-$date"
    $name = "$namePrefix-running"

    $idx = 0

    while (Test-Path (Join-Path $path $name))
    {
        ++$idx
        $name = "$namePrefix-$idx-running"
    }

    $directory = New-Item -ItemType Directory -Path (Join-Path $path $name)
    Write-Verbose "New-Directory $directory"
    return $directory
}

function Invoke-Start
{
    param(
        [switch]$CreatePackage,
        [string]$reason
    )

    Initialize-EventLog

    $settings = Get-settings

    if ($settings.StopBeforeStart)
    {
        Write-Log "Cleanup before starting ..." -ForegroundColor Yellow
        Invoke-Stop -CreatePackage:$CreatePackage -Reason $reason | Out-Null
        $CreatePackage = $false
        $reason = $null
    }

    try {
        Invoke-StartInternal -CreatePackage:$CreatePackage -Reason $reason
    }
    catch {
        Write-LogWarning "Failed to start, stopping all ..."
        Invoke-Stop
        throw $_
    }
}

function Get-DictFromArray
{
    param(
        [string[]]$base,
        [string[]]$add,
        [string[]]$remove
    )

    $dict = @{}

    foreach ($value in $base)
    {
        $dict[$value.Trim().ToLower()] = $true
    }

    foreach ($value in $add)
    {
        $dict[$value.Trim().ToLower()] = $true
    }

    foreach ($value in $remove)
    {
        $dict[$value.Trim().ToLower()] = $false
    }

    return $dict
}

function Get-UpdatedKeyword
{
    param(
        [uint64]$keyword,
        $enabled,
        [uint64]$keywordToEnable
    )

    if ($enabled)
    {
        return $keyword -bor $keywordToEnable
    }
    else
    {
        return $keyword -band (-bnot $keywordToEnable)
    }
}

function Invoke-StartInternal
{
    param(
        [switch]$CreatePackage,
        [string]$Reason
    )

    $settings = Get-Settings
    $BufferSizeMB = $settings.BufferSizeMB
    $DetailedSmbTracing = ! ! $settings.DetailedSmbTracing

    $prefix = New-TracePrefix
    $directory = New-Directory

    Write-Log "Start BufferSizeMB=$BufferSizeMB DetailedSmbTracing=$DetailedSmbTracing Channels=$($settings.LogChannels -join ',')"
    Write-Log "Directory: $directory"

    Save-Prefix $directory $prefix
    Save-Version $directory
    Save-Timestamp $directory "start"

    if ($settings.LogChannels -icontains 'accesslog')
    {
        Start-SmbAccessLog $directory $prefix | Out-Null
    }

    if ($settings.LogChannels -icontains 'fskm')
    {
        $fskmDict = Get-DictFromArray $settings.Fskm $settings.FskmAdd $settings.FskmRemove

        $rdbss = [uint64]"0xffffffff"
        $rdbss = Get-UpdatedKeyword $rdbss $fskmDict['io'] 0x4
        $rdbss = Get-UpdatedKeyword $rdbss $fskmDict['readwrite'] 0x10
        $rdbss = Get-UpdatedKeyword $rdbss $fskmDict['turboio'] 0x4000

        $smb20 = [uint64]"0xffffffff"
        $smb20 = Get-UpdatedKeyword $smb20 $fskmDict['network'] 0x4
        $smb20 = Get-UpdatedKeyword $smb20 $fskmDict['handle'] 0x40

        $mrxsmb = [uint64]"0xffffffff"
        $mrxsmb = Get-UpdatedKeyword $mrxsmb $fskmDict['network'] 0x4
        $mrxsmb = Get-UpdatedKeyword $mrxsmb $fskmDict['turboio'] 0x400

        Invoke-TraceCreate $directory $prefix "fskm"

        if ($DetailedSmbTracing)
        {
            Invoke-TraceUpdate $prefix "fskm" "20c46239-d059-4214-a11e-7d6769cbe020" "0xffff0f0"  "7"
            Invoke-TraceUpdate $prefix "fskm" "0086eae4-652e-4dc7-b58f-11fa44f927b4" "0xffffffff" "4"
            Invoke-TraceUpdate $prefix "fskm" "f818ebb3-fbc4-4191-96d6-4e5c37c8a237" "0xffffffff" "4"
            Invoke-TraceUpdate $prefix "fskm" "e4ad554c-63b2-441b-9f86-fe66d8084963" "0xffffffff" "4"
        }
        else
        {
            Invoke-TraceUpdate $prefix "fskm" "20c46239-d059-4214-a11e-7d6769cbe020" "0x3333030"  "0"
            Invoke-TraceUpdate $prefix "fskm" "0086eae4-652e-4dc7-b58f-11fa44f927b4" $rdbss "2"
            Invoke-TraceUpdate $prefix "fskm" "f818ebb3-fbc4-4191-96d6-4e5c37c8a237" $mrxsmb "2"
            Invoke-TraceUpdate $prefix "fskm" "e4ad554c-63b2-441b-9f86-fe66d8084963" $smb20 "2"
        }

        Invoke-TraceUpdate $prefix "fskm" "47eba62c-87e6-4564-9946-0dd4e361ed9b" "0x7fffffff" "7"
        Invoke-TraceUpdate $prefix "fskm" "17efb9ce-8cab-4f19-8b96-0d021d9c76f1" "0x7fffffff" "7"
        Invoke-TraceUpdate $prefix "fskm" "89d89015-c0df-414c-bc48-f50e114832bc" "0x7fffffff" "7"
        Invoke-TraceUpdate $prefix "fskm" "791cd79c-65b5-48a3-804c-786048994f47" "0x7fffffff" "7"
        Invoke-TraceUpdate $prefix "fskm" "d5418619-c167-44d9-bc36-765beb5d55f3" "0x7fffffff" "7"
        Invoke-TraceUpdate $prefix "fskm" "1f8b121d-45b3-4022-a9fb-3857177a65c1" "0x7fffffff" "7"
        Invoke-TraceUpdate $prefix "fskm" "355c2284-61cb-47bb-8407-4be72b5577b0" "0x7fffffff" "7"
    }

    if ($settings.LogChannels -icontains 'fsum')
    {
        Invoke-TraceCreate $directory $prefix "fsum"
        Invoke-TraceUpdate $prefix "fsum" "361f227c-aa14-4d19-9007-0c8d1a8a541b" "0x7fffffff" "7"
        Invoke-TraceUpdate $prefix "fsum" "0999b701-3e5d-4998-bc58-a775590a55d9" "0x7fffffff" "7"
        Invoke-TraceUpdate $prefix "fsum" "19ee4cf9-5322-4843-b0d8-bab81be4e81e" "0x7fffffff" "7"
        Invoke-TraceUpdate $prefix "fsum" "66418a2a-72af-4c1a-9c84-42f6865563bd" "0x7fffffff" "7"
        Invoke-TraceUpdate $prefix "fsum" "5e23b838-5b71-47e6-b123-6fe02ef573ef" "0x7fffffff" "7"
        Invoke-TraceUpdate $prefix "fsum" "91efb5a1-642d-42a4-9821-f15c73064fb5" "0x7fffffff" "7"
    }

    if ($settings.LogChannels -icontains 'rpcxdr')
    {
        Invoke-TraceCreate $directory $prefix "rpcxdr"
        Invoke-TraceUpdate $prefix "rpcxdr" "94b45058-6f59-4696-b6bc-b23b7768343d" "0x7fffffff" "7"
        Invoke-TraceUpdate $prefix "rpcxdr" "53c16bac-175c-440b-a266-1e5d5f38313b" "0x7fffffff" "7"
    }

    if ($settings.LogChannels -icontains 'sec')
    {
        Invoke-TraceCreate $directory $prefix "sec"
        Invoke-TraceUpdate $prefix "sec" "6b510852-3583-4e2d-affe-a67f9f223438" "0x43" "7"
        Invoke-TraceUpdate $prefix "sec" "5bbb6c18-aa45-49b1-a15f-085f7ed0aa90" "0x15003" "7"
        Invoke-TraceUpdate $prefix "sec" "5af52b0d-e633-4ead-828a-4b85b8daac2b" "0x73" "7"
        Invoke-TraceUpdate $prefix "sec" "2a6faf47-5449-4805-89a3-a504f3e221a6" "0x1f3" "7"
    }

    if ($settings.LogChannels -icontains 'tcp')
    {
        Invoke-TraceCreate $directory $prefix "tcp"
        Invoke-TraceUpdate $prefix "tcp" "eb004a05-9b1a-11d4-9123-0050047759bc" "0x1000" "2"
    }

    if ($settings.LogChannels -icontains 'network')
    {
        Invoke-CaptureNetworkStart $directory $prefix
    }

    if ($settings.LogChannels -icontains 'counters')
    {
        Invoke-CounterCreate $directory $prefix "counters" @('\SMB Client Shares(*)\*', '\Processor(*)\% Processor Time')
    }

    if (!$settings.StopBeforeStart)
    {
        Write-Log "Stopping previous one if any ..." -ForegroundColor Green
        Invoke-Stop -ExcludeDirectory $directory -ExcludePrefix $prefix -PreviousExecution -CreatePackage:$CreatePackage -Reason $Reason
    }

    Write-Log "Tracing started ..." -ForegroundColor Green
}

function Save-Version
{
    param ($directory)

    $path = Join-Path $directory "version.txt"

    reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion" /t REG_SZ | Out-String | Out-File $path -Encoding Ascii

    Write-Verbose "Save-Version $path"
}

function Get-DateUtcString
{
    return (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss.fff")
}

function Write-Log
{
    $settings = Get-Settings

    if (! $settings.Silent)
    {
        if ($settings.NoDateTimePrefix)
        {
            Write-Host @args
        }
        else
        {
            Write-Host "$(Get-DateUtcString):" @args
        }
    }
}

function Write-LogWarning
{
    $settings = Get-Settings

    if (! $settings.Silent)
    {
        if ($settings.UseWriteInformation)
        {
            Write-Information "$(Get-DateUtcString): WARNING: $($args[0])"
        }
        else
        {
            Write-Warning "$(Get-DateUtcString): $($args[0])"
        }
    }
}

function Save-Timestamp
{
    param ($directory, $name)

    $path = Join-Path $directory "timestamp-utc.txt"
    $data = "$(Get-DateUtcString) $name"

    $data | Out-File $path -Encoding Ascii -Append -Force

    Write-Verbose "Save-Timestamp $path $data"
}

function Save-Prefix
{
    param ($directory, $prefix)

    $path = Join-Path $directory "prefix.txt"

    $prefix | Out-File $path -Encoding Ascii

    Write-Verbose "Save-Prefix $path $prefix"
}

function Get-Prefix
{
    param ($directory)

    $path = Join-Path $directory "prefix.txt"
    $result = ""
    try {
        $result = ([string](Get-Content $path -Raw)).Trim()
    }
    catch {
        Write-LogWarning "Get-Prefix failed: $_"
        $result = Get-MainPrefix
        Write-Log "Returning default prefix - $result"
    }

    Write-Verbose "Get-Prefix $directory $result"

    return $result
}

function Invoke-TraceCreate
{
    param(
        [string]$directory,
        [string]$prefix,
        [string]$name
    )

    $settings = Get-Settings

    $EVENT_TRACE_USE_LOCAL_SEQUENCE = 0x00008000
    $EVENT_TRACE_BUFFERING_MODE     = 0x00000400
    $EVENT_TRACE_FILE_MODE_CIRCULAR = 0x00000002

    $path = $null
    $bufferCount = 0
    $MaximumFileSizeMB = 0
    $MemorybufferSizeKB = 0
    $mode = $EVENT_TRACE_USE_LOCAL_SEQUENCE
    $suffix = ''

    if ($settings.UseMemoryBuffer)
    {
        $suffix = '-mem'
        $bufferCount = 16
        $MemorybufferSizeKB = $settings.BufferSizeMB * 64
        $mode = $mode -bor $EVENT_TRACE_BUFFERING_MODE
    }
    else
    {
        $path = Join-Path $directory "$name.etl"
        $bufferCount = 16
        $MemorybufferSizeKB = 2048

        if ($settings.BufferSizeMB -eq 1)
        {
            $bufferCount = 2
            $MemorybufferSizeKB = 512
        }
        elseif ($settings.BufferSizeMB -le 32)
        {
            $bufferCount = $settings.BufferSizeMB
            $MemorybufferSizeKB = 1024
        }

        if ($settings.BufferSizeMB -gt 0)
        {
            $MaximumFileSizeMB = $settings.BufferSizeMB
            $mode = $mode -bor $EVENT_TRACE_FILE_MODE_CIRCULAR
        }
    }

    Write-Log "Create trace: $($prefix + $name + $suffix), BufferSizeMB: $($settings.BufferSizeMB)"

    if (Get-Command 'Start-EtwTraceSession' -ErrorAction SilentlyContinue)
    {
        $result = Start-EtwTraceSession -name ($prefix + $name + $suffix) -LogFileMode $mode -LocalFilePath $path -MaximumFileSize $MaximumFileSizeMB -BufferSize $MemorybufferSizeKB -MinimumBuffers $bufferCount -MaximumBuffers $bufferCount

        if (!$result)
        {
            throw "Start-EtwTraceSession failed"
        }
    }
    else
    {
        if ($settings.UseMemoryBuffer)
        {
            throw "Start-EtwTraceSession is required for -UseMemoryBuffer"
        }

        $circArgs = @()

        if ($settings.BufferSizeMB -gt 0)
        {
            $circArgs = "-f", "bincirc", "-max", $settings.BufferSizeMB
        }

        Invoke-Cmd logman create trace -n ($prefix + $name + $suffix) -o $path -mode localsequence -nb $bufferCount $bufferCount -bs $MemorybufferSizeKB -ets @circArgs | Write-verbose
    }
}

function Get-SettingOverride
{
    param (
        [string[]]$overrides,
        [guid]$provider
    )

    foreach ($pair in $overrides)
    {
        $s = $pair.Split(':')
        if ($provider -eq [guid]$s[0])
        {
            return $s[1]
        }
    }

    return $null
}

function Invoke-TraceUpdate
{
    param(
        [string]$prefix,
        [string]$name,
        [string]$provider,
        [uint64]$flags,
        [byte]$level
    )

    $settings = Get-Settings

    $suffix = ''
    if ($settings.UseMemoryBuffer)
    {
        $suffix = '-mem'
    }


    $flagsOverride = Get-SettingOverride $settings.FlagsOverride $provider
    if ($flagsOverride -ne $null)
    {
        $flags = [uint64]$flagsOverride
        Write-Log "FlagOverride: $provider -> 0x$($flags.ToString('x'))"
    }

    $levelOverride = Get-SettingOverride $settings.LevelOverride $provider
    if ($levelOverride -ne $null)
    {
        $level = [byte]$levelOverride
        Write-Log "LevelOverride: $provider -> $level"
    }

    Write-Log "Update: $($prefix + $name + $suffix) - $provider - 0x$($flags.ToString('x')) $level"

    if (Get-Command 'Start-EtwTraceSession' -ErrorAction SilentlyContinue)
    {
        $result = Add-EtwTraceProvider -Sessionname ($prefix + $name + $suffix) -Guid "{$provider}" -MatchAnyKeyword $flags -Level $level

        if (!$result)
        {
            throw "Add-EtwTraceProvider failed"
        }
    }
    else
    {
        Invoke-Cmd logman update -n ($prefix + $name + $suffix) -p "{$provider}" "0x$($flags.ToString('x'))" $level -ets | Write-Verbose
    }
}

function Invoke-TraceStop
{
    param(
        [string]$fullName,

        [switch]$useEts,

        [switch]$CreatePackage
    )

    if ($useEts)
    {
        Write-Log "Stop trace $fullName"
    }
    else
    {
        Write-Log "Stop counter $fullName"
    }

    $directory = ''
    foreach ($d in Get-SmbClientItems -Running)
    {
        $prefix = Get-Prefix $d

        if ($fullName.StartsWith($prefix))
        {
            $directory = $d
            break
        }
    }

    $name = ''
    $s = $fullName.Split('-')
    if ($s.Length -ge 2)
    {
        $name = $s[$s.Length-2]
    }

    if ($CreatePackage -and $fullName.EndsWith('-mem') -and $directory -and $name)
    {
        if (Get-Command 'Save-EtwTraceSession' -ErrorAction SilentlyContinue)
        {
            $path = Join-Path $directory "$name.etl"
            Write-Log "Saving $path"
            if ($path)
            {
                Save-EtwTraceSession -Name $fullName -OutputFile $path -Overwrite | Out-Null
            }
        }
        else
        {
            Write-LogWarning "Save-EtwTraceSession not available..."
        }
    }

    $etsArg = if ($useEts) { "-ets" } else { $null }

    $output = $null

    try {
        Invoke-Cmd logman stop -n $fullName $etsArg | Write-Output -OutVariable output | Write-Verbose
    } catch {
        $strOutput = $output | Out-String
        if (($strOutput.IndexOf("Data Collector Set is not running") -lt 0) -and
            ($strOutput.IndexOf("Data Collector Set was not found") -lt 0))
        {
            Write-Error $strOutput
            throw
        }
    }

    $output = $null

    try {
        Invoke-Cmd logman delete -n $fullName $etsArg | Write-Output -OutVariable output | Write-Verbose
    } catch {
        $strOutput = $output | Out-String
        if ($strOutput.IndexOf("Data Collector Set was not found") -lt 0)
        {
            Write-Error $strOutput
            throw
        }
    }

    if ($CreatePackage -and $directory)
    {
        Save-Timestamp $directory "stopped $fullName"

        return $directory
    }
}

function Invoke-CounterCreate
{
    param(
        [string]$directory,
        [string]$prefix,
        [string]$name,
        [string[]]$counters
    )

    $CounterSizeMB = (Get-Settings).CounterSizeMB

    $path = Join-Path $directory "$name.blg"

    if ($CounterSizeMB -gt 0)
    {
        $circArgs = "-f", "bincirc", "-max", $CounterSizeMB
    }

    Write-Log "Create counter: $($prefix + $name)"

    $countersFile = (New-TemporaryFile).FullName
    $counters | Out-File $countersFile -Encoding ASCII -Width 1000
    try {
        Invoke-Cmd logman create counter -n ($prefix + $name) --v -o $path @circArgs -cf $countersFile | Write-Verbose
    }
    finally {
        Remove-Item $countersFile -Force | Out-Null
    }

    Invoke-Cmd logman start -n ($prefix + $name) | Write-Verbose
}

function Invoke-CaptureNetworkStart
{
    param(
        [string]$directory,
        [string]$prefix
    )

    Write-Log "Closing all old net event capture sessions"
    Invoke-CaptureNetworkStopAll | Out-Null

    $settings = Get-Settings

    $name = "networkcapture"

    $NetworkBufferSizeMB = $settings.NetworkBufferSizeMB
    $NetworkTruncationLength = $settings.NetworkTruncationLength
    $NetworkLevel = $settings.NetworkLevel
    $NetworkIpProtocols = $settings.NetworkIpProtocols

    if ($NetworkBufferSizeMB -le 0)
    {
        $NetworkBufferSizeMB = $settings.BufferSizeMB
    }

    $NetworkAddress = $settings.NetworkAddress

    if (! $NetworkAddress)
    {
        $NetworkAddress = @()
    }

    $path = Join-Path $directory "$name.etl"

    Write-Log "Start network capture $($prefix + $name), NetworkBufferSizeMB: $NetworkBufferSizeMB, NetworkAddress: $NetworkAddress, NetworkTruncationLength: $NetworkTruncationLength, NetworkLevel: $NetworkLevel, NetworkIpProtocols: $NetworkIpProtocols"

    New-NetEventSession -Name ($prefix + $name) -LocalFilePath $path -CaptureMode SaveToFile -MaxFileSize $NetworkBufferSizeMB | Out-Null
    Add-NetEventPacketCaptureProvider -SessionName ($prefix + $name) -Level $NetworkLevel -TruncationLength $NetworkTruncationLength -IpProtocols $NetworkIpProtocols -IpAddresses $NetworkAddress | Out-Null
    Start-NetEventSession -Name ($prefix + $name) | Out-Null
}

function Invoke-CaptureNetworkStop
{
    param(
        [string]$prefix,

        [string]$name
    )

    Write-Log "Stop network capture $($prefix + $name)"

    Stop-NetEventSession -Name ($prefix + $name) -ErrorAction SilentlyContinue | Out-Null
    Remove-NetEventSession -Name ($prefix + $name) | Out-Null
}

function Invoke-CaptureNetworkStopAll
{
    Write-Verbose "Invoke-CaptureNetworkStopAll, closing all sessions from Get-NetEventSession"

    $names = @(Get-NetEventSession | Select-Object -ExpandProperty Name)

    foreach ($name in $names)
    {
        Invoke-CaptureNetworkStop -prefix "" -name $name
    }

    Write-Log "Stopped CaptureNetworks: $($names.Count)"
}

function Invoke-TraceQuery
{
    param(
        [bool]$useEts = $true,
        [string]$ExcludePrefix = ""
    )

    $etsArg = if ($useEts) { "-ets" } else { $null }
    $MainPrefix = Get-MainPrefix
    $nameMatch = { $_.StartsWith($MainPrefix) -and (!$ExcludePrefix -or !($_.StartsWith($ExcludePrefix))) }

    $tracers = $null

    try {
        if ($useEts)
        {
            $tracers = Get-EtwTraceSession -Name "*" | Select-Object -ExpandProperty Name | Where-Object $nameMatch
        }
        else
        {
            $tracers = Invoke-Cmd logman query | ForEach-Object{ $_.Split(' ')[0].Trim() } | Where-Object $nameMatch
        }
    }
    catch {
        $cmdName = if ($useEts) { "Get-ETWTraceSession" } else { "logman query" }
        Write-Log "$cmdName failed, waiting 5sec and retry"
        Start-sleep -Seconds 5 | Out-Null
    }

    if (! $tracers)
    {
        Write-Log "Using logman query $etsArg to query"
        $tracers = Invoke-Cmd logman query $etsArg | ForEach-Object{ $_.Split(' ')[0].Trim() } | Where-Object $nameMatch
    }

    return $tracers
}

function Invoke-TraceStopAll
{
    param(
        [string]$ExcludePrefix = "",

        [switch]$CreatePackage,

        [string]$Reason
    )

    $MainPrefix = Get-MainPrefix

    Write-Verbose "Stopping all tracing with prefix $MainPrefix excluding $ExcludePrefix"

    Stop-SmbAccessLog -ExcludePrefix $ExcludePrefix -CreatePackage:$CreatePackage | Out-Null

    $nameMatch = { $_.StartsWith($MainPrefix) -and (!$ExcludePrefix -or !($_.StartsWith($ExcludePrefix))) }

    $directory = ""

    foreach ($useEts in @($true, $false))
    {
        $tracers = @(Invoke-TraceQuery -useEts $useEts -ExcludePrefix $ExcludePrefix)

        foreach ($name in $tracers)
        {
            $tmp = Invoke-TraceStop $name -useEts:$useEts -CreatePackage:$CreatePackage
            if ($tmp)
            {
                $directory = $tmp
            }
        }

        $oldNames += $tracers
    }

    Write-Verbose "Calling Get-NetEventSession"

    $oldCaptureNetworks = @(Get-NetEventSession | Select-Object -ExpandProperty Name | Where-Object $nameMatch)

    foreach ($name in $oldCaptureNetworks)
    {
        Invoke-CaptureNetworkStop -prefix "" -name $name
    }

    Write-verbose "Excluding prefix: $ExcludePrefix"

    if ($oldCaptureNetworks.Count -gt 0)
    {
        Write-Log "Stopped capture networks: $($oldCaptureNetworks.Count)"
    }

    Write-Log "Stopped: $($oldNames.Count), directory: $directory"

    if ($CreatePackage -and $directory)
    {
        return Save-Package $directory -Reason $reason
    }
}

function Save-EventswevtutilWithRetry
{
    param ($name, $filePath)

    for ($i = 0; $i -lt 3; ++$i)
    {
        try {
            Invoke-Cmd wevtutil epl $name $filePath "/q:*[System[TimeCreated[timediff(@SystemTime) <= 86400000]]]"
            return $true
        }
        catch {
            $seconds = 2
            Write-LogWarning "Failed to write $name events, retrying in $seconds seconds..."
            Start-Sleep $seconds | Out-Null
        }
    }

    return $false
}

function Save-Events
{
    param (
        [string]$directory,
        [string]$name)

    Write-Verbose "Writing events $name"

    $fileName = $name.Replace('/', '-').Replace('Microsoft-', '').Replace('Windows-', '')

    $filePath = Join-Path $directory $fileName

    @(get-winevent2 -LogName $name -MaxEvents 256 -ErrorAction SilentlyContinue) | ForEach-Object {
        $id = $_.Id
        $level = $_.LevelDisplayName
        $date = $_.TimeCreated.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss.fffff")

        Write-Output ""
        Write-Output "Id=$id Level=$level DateUTC=$date"
        Write-Output "------------"
        Write-Output $_.Message
        Write-Output ""
        Write-Output "-"
    } | Out-File "$filePath.txt" -Encoding Ascii

    Save-EventswevtutilWithRetry $name "$filePath.evtx" | Out-Null
}


function Save-Package
{
    param (
        [Parameter(Mandatory=$true)]
        [string]$directory,
        [string]$reason)

    $settings = Get-Settings

    $OutputDirectory = $settings.OutputDirectory
    $NoCompression = $settings.NoCompression

    Write-Verbose "Save-Package $directory"

    $reasonShort = ''

    if ($reason)
    {
        $reasonShort = $reason.Split(';')[0]

        Save-Timestamp $directory "reason: $reason"
    }

    Save-Timestamp $directory "packaging, compression=$(! $NoCompression)"

    Save-Events $directory "Microsoft-Windows-SMBClient/Connectivity"
    Save-Events $directory "Microsoft-Windows-SMBClient/Operational"
    Save-Events $directory "Microsoft-Windows-SMBClient/Security"

    if ($directory.EndsWith('-running'))
    {
        $newDirectory = $directory.Substring(0, $directory.Length - '-running'.Length)
        if ($reasonShort)
        {
            $newDirectory = "$newDirectory-$reasonShort"
        }

        try
        {
            Rename-Item -Force $directory $newDirectory | Out-Null
        }
        catch
        {
            Write-Log "Rename failed trying to copy and zip"
            Write-Log $_
            Write-Log "copying $directory to $newDirectory"
            Copy-Item -Force -Recurse $directory $newDirectory

        }

        $directory = $newDirectory
    }

    $outputFileName = (Get-Item $directory).Name

    $outputFile = Join-Path $outputDirectory $outputFileName

    $compressed = $false

    if (! $NoCompression)
    {
        Write-Verbose "Compress-Archive $directory $outputFile.zip"

        try {
            Compress-Archive $directory "$outputFile.zip" | Out-Null

            $compressed = $true
        }
        catch {
            Write-Verbose $_
            Write-Log "Compression failed, leaving uncompressed" -ForegroundColor Yellow
        }
    }

    if ($compressed)
    {
        Write-Verbose "Remove $directory"

        Remove-Item $directory -Force -Recurse | Out-Null

        return [IO.Path]::GetFullPath("$outputFile.zip")
    }
    else
    {
        $resolvedDirectory = [IO.Path]::GetFullPath($directory)
        $resolvedOutputFile = [IO.Path]::GetFullPath($outputFile)

        if ($resolvedDirectory -ine $resolvedOutputFile)
        {
            Copy-Item $directory $outputFile -Force -Recurse | Out-Null
            Remove-Item $directory -Force -Recurse | Out-Null
        }

        return $resolvedOutputFile
    }
}

function Get-SmbClientItems
{
    param (
        [string[]]$Exclude,

        [switch]$Running
    )

    $settings = Get-Settings

    $directories = @( $settings.OutputDirectory )

    if ($settings.TempDirectory -and $settings.OutputDirectory -ine $settings.TempDirectory)
    {
        $directories += $settings.TempDirectory
    }

    foreach ($directory in $directories)
    {
        Write-verbose "Get-SmbClientItems $directory -Filter $(Get-DirectoryPrefixFilter)"
        Write-verbose "Get-SmbClientItems excludes: $Exclude"

        $output = Get-ChildItem $directory -Filter (Get-DirectoryPrefixFilter) |
            Sort-Object -Property LastWriteTime -Descending |
            Select-Object -ExpandProperty FullName |
            Where-Object { !($Exclude -icontains $_) }

        if ($Running)
        {
            $output = $output | Where-Object { ($_.EndsWith("-running")) -and (Test-Path -Path $_ -PathType Container) }
        }

        $output | Write-Output
    }
}

function Invoke-Stop
{
    param (
        [string]$ExcludeDirectory,

        [string]$ExcludePrefix,

        [switch]$PreviousExecution,

        [switch]$CreatePackage,

        [string]$Reason
    )

    $OutputDirectory = (Get-Settings).OutputDirectory
    $MaxOutputFiles = (Get-Settings).MaxOutputFiles

    Write-Verbose "Invoke-Stop $OutputDirectory $ExcludeDirectory $ExcludePrefix"

    $saved = Invoke-TraceStopAll -ExcludePrefix $ExcludePrefix -CreatePackage:$CreatePackage -Reason $Reason

    foreach ($directory in Get-SmbClientItems -Running -Exclude $ExcludeDirectory)
    {
        try
        {
            Remove-Item $directory -Recurse -Force | Out-Null
        }
        catch
        {
            Write-Log "Removing old item failed : $directory"
            Write-Log $_
        }
    }

    if ($MaxOutputFiles -gt 0)
    {
        Write-Log "Removing old items in $OutputDirectory, filter: $(Get-DirectoryPrefixFilter), MaxOutputFiles: $MaxOutputFiles"
        Write-Verbose "ExcludeDirectory: $ExcludeDirectory"
        Write-Verbose "Saved: $saved"
        $items = @(Get-SmbClientItems -Exclude $ExcludeDirectory, $saved) | Sort-Object

        Write-Verbose "items.count: $($items.Count), MaxOutputFiles: $MaxOutputFiles"

        if ($saved)
        {
            --$MaxOutputFiles
        }

        if ($items.Count -gt $MaxOutputFiles)
        {
            $items = $items[0..($items.Count - $MaxOutputFiles - 1)]

            foreach ($item in $items)
            {
                Write-Log "Removing old item: $item" -ForegroundColor Yellow
                try {
                    Remove-Item $item -Force -Recurse | Out-Null
                }
                catch {
                    Write-LogWarning $_
                }
            }
        }
    }

    if ($saved)
    {
        if ($PreviousExecution)
        {
            Write-Log "Package created for previous tracing session: $saved" -ForegroundColor Green
        }
        else
        {
            Write-Log "Package created: $saved" -ForegroundColor Green
        }
    }
}

function Invoke-StopOrRestart
{
    param([string]$reason)

    $settings = Get-Settings
    $continuous = ! ! $settings.Continuous

    if ($continuous)
    {
        Invoke-Start -CreatePackage -Reason $reason | Out-Null
    }
    else
    {
        Invoke-Stop -CreatePackage -Reason $reason | Out-Null
    }
}

function Get-LockFileName
{
    $settings = Get-Settings
    $tempDirectory = $settings.TempDirectory

    if ($tempDirectory)
    {
        return Join-Path $tempDirectory "$(Get-MainPrefix)-lock.txt"
    }
}

function Set-LockFile
{
    param ([string]$value)

    $lockFile = Get-LockFileName

    if ($lockFile)
    {
        Write-Log "SetLockFile: $lockFile $value"
        Set-Content $lockFile $value -Force -NoNewline -Encoding "ASCII" | Out-Null
    }
}

function Test-LockFile
{
    param([string]$value)

    $lockFile = Get-LockFileName

    if ($lockFile)
    {
        [string]$content = Get-Content $lockFile -Encoding "ASCII" -ErrorAction SilentlyContinue
        if ($content)
        {
            $content = $content.Trim()
        }
        if ($value -ne $content)
        {
            return $false
        }
    }

    return $true
}

function Initialize-Script
{
    $settings = Get-Settings

    if ($settings.OutputDirectory -and (! (Test-Path ($settings.OutputDirectory))))
    {
        New-Item $settings.OutputDirectory -ItemType Directory -Force | Out-Null
    }

    if ($settings.TempDirectory -and (! (Test-Path ($settings.TempDirectory))))
    {
        New-Item $settings.TempDirectory -ItemType Directory -Force | Out-Null
    }

    $lockFile = Get-LockFileName

    if ($lockFile)
    {
        Remove-Item $lockFile -Force -ErrorAction SilentlyContinue | Out-Null
    }

    Invoke-LogSettings

    Initialize-NamedEvent
}

$script:NamedEvent = $null

function Initialize-NamedEvent
{
    if ($script:NamedEvent)
    {
        $script:NamedEvent.Close()
        $script:NamedEvent.Dispose()
        $script:NamedEvent = $null
    }

    if ($settings.OnNamedEvent)
    {
        $mode = [System.Threading.EventResetMode]::AutoReset
        $name = $settings.NamedEventName

        $created = $false
        $reference = New-Object -TypeName System.Management.Automation.PSReference -ArgumentList $created

        $eventWaitHandleSecurity = New-Object System.Security.AccessControl.EventWaitHandleSecurity

        $sid = [System.Security.Principal.WellKnownSidType]::WorldSid
        $securityIdentifier = New-Object System.Security.Principal.SecurityIdentifier -ArgumentList $sid, $null

        $fullControl = [System.Security.AccessControl.EventWaitHandleRights]::FullControl
        $allow = [System.Security.AccessControl.AccessControlType]::Allow
        $eventWaitHandleAccessRule = New-Object System.Security.AccessControl.EventWaitHandleAccessRule -ArgumentList $securityIdentifier, $fullControl, $allow

        $eventWaitHandleSecurity.AddAccessRule($eventWaitHandleAccessRule)
        $script:NamedEvent = New-Object -TypeName System.Threading.EventWaitHandle -ArgumentList $false, $mode, $name, $reference, $eventWaitHandleSecurity

    }
}

function Invoke-EventLoopInternal
{
    Initialize-Script

    $lock = [Guid]::NewGuid().ToString("N")
    Set-LockFile $lock

    $settings = Get-Settings
    $continuous = ! ! $settings.Continuous

    Invoke-Start | Out-Null

    $isCounterBased = Get-IsCounterBased

    $eventsMsg = ((Get-EventBasedSettingsDict).GetEnumerator() | ForEach-Object { $_.Name + "=" + $_.Value }) -join ", "

    Write-Log "Waiting for events Continuous=$continuous, $eventsMsg" -ForegroundColor Green

    Write-Log "To stop it, press CTRL+C and run .\SmbClientLogs.ps1 -Stop" -ForegroundColor Green
    $lastRestartTime = [System.Diagnostics.Stopwatch]::StartNew()

    while (Test-LockFile $lock)
    {
        $reason = ''

        if ($isCounterBased)
        {
            $reason = Get-CounterReason
        }
        else
        {
            Start-Sleep $settings.SampleIntervalSeconds | Out-Null
        }

        if (!$reason)
        {
            $reason = Get-SmbAccessLogReason
        }

        if (!$reason)
        {
            $reason = Get-EventLogReason
        }

        if (!$reason)
        {
            $reason = Get-NamedEventReason
        }

        if ($reason)
        {
            Write-Log "Found new event=$reason" -ForegroundColor Green
            Start-Sleep -Milliseconds 100 | Out-Null

            $seconds = $settings.RestartIntervalSeconds - $lastRestartTime.Elapsed.TotalSeconds
            $lastRestartTime.Restart()

            Invoke-StopOrRestart -Reason $reason

            if (! $continuous)
            {
                break;
            }

            if ($seconds -gt 0)
            {
                Write-Log "Waiting $seconds seconds before next get event"
                Start-sleep $seconds | Out-Null
            }

            Write-Log "Waiting for events, to stop it press CTRL+C and run .\SmbClientLogs.ps1 -Stop" -ForegroundColor Green
        }
    }
}

function Invoke-EventLoop
{
    $settings = Get-Settings
    $continuous = ! ! $settings.Continuous

    if ($continuous)
    {
        while ($true)
        {
            try {
                Invoke-EventLoopInternal | Out-Null
                break
            }
            catch {
                Write-Log "Error: $_"
                Write-Log "Sleeping for 300 seconds before restarting"
                Start-Sleep 300
            }
        }
    }
    else
    {
        Invoke-EventLoopInternal | Out-Null
    }
}

#### main logic

if ($verbose)
{
    $VerbosePreference = "Continue"
}

if (! (Get-IsElevated))
{
    throw "Please run this script as administrator (elevated)"
}

$settingsDict = @{}
foreach ($name in $MyInvocation.MyCommand.Parameters.Keys)
{
    $settingsDict[$name] = Get-Variable -Name $name | Select-Object -ExpandProperty Value
}

Set-Settings $settingsDict

if ($Cleanup)
{
    Initialize-Script

    Invoke-Stop
}
elseif ($RecordSeconds -gt 0)
{
    Initialize-Script

    Invoke-Start
    Write-Log "Recording $RecordSeconds seconds"
    Start-Sleep -Seconds $RecordSeconds
    Invoke-Stop -Reason "RecordSeconds-$RecordSeconds" -CreatePackage
}
elseif (Get-IsEventBased)
{
    if ($Start)
    {
        throw "-Start is not supported with combination event triggers, use -Continuous or -Stop"
    }

    Invoke-EventLoop

    Write-Log "EventLoop exited stopping..."

    Invoke-Stop | Out-Null

    Write-Log "EventLoop end"
}
elseif ($Stop)
{
    if ($Start -or $Continuous)
    {
        throw '-Stop cannot be passed together with -Start or -Continuous'
    }

    Initialize-Script

    Invoke-Stop -Reason "Stop" -CreatePackage
}
elseif ($Start)
{
    Initialize-Script

    Invoke-Start
}
else
{
    Write-Log @"
SmbClientLogs.ps1 - script to capture SMB Client logs. After capture is done it creates zip package in the current directory (OutputDirectory).

Version: 3.60

Options:

    -Start
    -Stop
    -Continuous
    -Cleanup

    -RecordSeconds 0

    -OnAnomaly
    -OnNamedEvent

    -OnConnectivityError
    -OnConnectivityEventId 123

    -OnOperationalError
    -OnOperationalEventId 123

    -OnSecurityError
    -OnSecurityEventId 123

    -OnHighLatency
    -OnHighAvgIOLatency
    -HighLatencyMs 20000
    -HighLatencyPercentile 1.0 # 0.90
    -HighLatencyPercentileCount 1
    -HighAvgIOLatencyMs 5000

    -OnCreditStall
    -CreditStallThreshold 1000

    -OnStatusCode
    -StatusCodes

    -SkipKnownErrors
    -KnownConnectivityErrors "30805, 30822"
    -KnownOperationalErrors
    -KnownSecurityErrors

    -NamedEventName "SmbClientLogsEvent"

    -BufferSizeMB 300
    -CounterSizeMB 50

    -TempDirectory ""
    -OutputDirectory "."
    -MaxOutputFiles 10

    -DetailedSmbTracing
    -IncludeTcpLogs
    -EnableAccessLog

    -CaptureNetwork
    -NetworkAddress
    -NetworkBufferSizeMB 300
    -NetworkTruncationLength 65535
    -NetworkLevel 4
    -NetworkIpProtocols # 6 for tcp

    -NoCompression
    -UseCompression

    -RestartIntervalSeconds 300
    -SampleIntervalSeconds 1
    -SampleWindowSeconds 1
    -AccessLogMemoryBufferLineCount 1000000

    -StopBeforeStart
    -AgentMode
    -NoDateTimePrefix
    -LogChannels fskm, fsum, rpcxdr, sec, counters

    -FlagsOverride
    -LevelOverride

    -Fskm handle, network, io, readwrite
    -FskmAdd
    -FskmRemove

    -Silent
    -Verbose

Examples:

    .\SmbClientLogs.ps1 -OnAnomaly
    .\SmbClientLogs.ps1 -OnAnomaly -Continuous
    .\SmbClientLogs.ps1 -OnAnomaly -CaptureNetwork
    .\SmbClientLogs.ps1 -OnConnectivityEventId 30809 -IncludeTcpLogs -CaptureNetwork
    .\SmbClientLogs.ps1 -Start
    .\SmbClientLogs.ps1 -Stop

"@
}

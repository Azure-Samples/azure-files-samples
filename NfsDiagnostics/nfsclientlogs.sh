#!/bin/bash

# The first line of this file contains the pid of the trace-cmd instance that we
# spawn. If there is a second line, it will contain the pid of the tcpdump
# instance that we spawn.
BG_JOBS_PIDFILE="/tmp/nfsclientlog.pid"

invoke_trace_cmd="nohup trace-cmd record -e nfs"

# tcpdump
invoke_tcpdump="nohup tcpdump -p -s 0 -w nfs_traffic.pcap port 2049"
if [ "$1" == "v3b" ]
then
	invoke_tcpdump="nohup tcpdump -p -s 0 -w nfs_traffic.pcap port 111"
fi

# trace-nfsbpf
NFSBPF_ABSOLUTE_PATH="$(cd "$(dirname "trace-nfsbpf")" && pwd)/$(basename "trace-nfsbpf")"
invoke_trace_nfsbpf="nohup $NFSBPF_ABSOLUTE_PATH"

# Check if trace-cmd is installed.
which trace-cmd > /dev/null
if [ $? == 1 ]; then
	echo "trace-cmd is not installed."
	exit 1
fi

start() {
    local saved_pid;
    local trace_cmd_pid;
    local retry;

	rm -f nfs_traffic.pcap

	dmesg -Tc > /dev/null

    date >nfsstat.pre.out
    echo >>nfsstat.pre.out
    nfsstat -o nfs -l |sort -k5 -nr >>nfsstat.pre.out

    date >mountstats.pre.out
    echo >>mountstats.pre.out
    mountstats >>mountstats.pre.out

	rpcdebug -m rpc -s all
	rpcdebug -m nfs -s all

	retry=0
	if [ -f "$BG_JOBS_PIDFILE" ]; then
		read saved_pid < $BG_JOBS_PIDFILE;
		trace_cmd_pid=`pgrep trace-cmd | head -1`
		if [ "$saved_pid" == "$trace_cmd_pid" ]
		then
			echo "[error] [`date +'%FT%H:%M:%S%z'`] trace-cmd is already running, restarting trace-cmd."
			kill -INT $saved_pid
			ps -p "$saved_pid" > /dev/null
			while [ $? == 0 ] && [ $retry -lt 10 ]
			do
				retry=`expr $retry + 1`
				sleep 1
				ps -p "$saved_pid" > /dev/null
			done
			if [ $retry -eq 10 ]; then
				echo "[error] [`date +'%FT%H:%M:%S%z'`] Restarting trace-cmd failed. Exiting.."
				exit 1
			fi
			rm -rf trace.dat*
		fi
	fi

	$invoke_trace_cmd 0<&- > /dev/null 2>&1 &
    # save the trace_cmd pid
	echo $! > $BG_JOBS_PIDFILE

	if [ "$1" == "CaptureNetwork" ] || [ "$2" == "CaptureNetwork" ]; then
        # If we're spawning tcpdump, save its pid too.
		$invoke_tcpdump 0<&- > /dev/null 2>&1 &
		echo $! >> $BG_JOBS_PIDFILE
	fi

	if [ "$1" == "OnAnomaly" ] || [ "$2" == "OnAnomaly" ]; then
		$invoke_trace_nfsbpf 0<&- > /dev/null 2>&1 &
	fi
}

stop() {
    local trace_cmd_saved_pid;
    local tcpdump_saved_pid;
    local retry;

	rm -rf nfs_trace

	retry=0
	if [ -f "$BG_JOBS_PIDFILE" ]; then
		while read -r line
		do
			read -r tcpdump_saved_pid
			trace_cmd_saved_pid=$line
		done < $BG_JOBS_PIDFILE;
		trace_cmd_pid=`pgrep trace-cmd | head -1`
		if [ "$trace_cmd_saved_pid" != "" ] && [ "$trace_cmd_saved_pid" == "$trace_cmd_pid" ]
		then
			kill -INT $trace_cmd_saved_pid
			ps -p "$trace_cmd_saved_pid" > /dev/null
			while [ $? == 0 ] && [ $retry -lt 10 ]
			do
				retry=`expr $retry + 1`
				sleep 1
				ps -p "$trace_cmd_saved_pid" > /dev/null
			done
			trace-cmd report > nfs_trace
			if [ $? != 0 ]; then
				rm -f $BG_JOBS_PIDFILE
				return 1
			fi
			rm -f $BG_JOBS_PIDFILE
		else
			rm -f $BG_JOBS_PIDFILE
			return 1
		fi
		tcpdump_pid=`pgrep tcpdump | head -1`
		if [ "$tcpdump_saved_pid" == "$tcpdump_pid" ] && [ "$tcpdump_saved_pid" != "" ]
		then
			sudo kill -INT $tcpump_saved_pid
			ps -p "$tcpump_saved_pid" > /dev/null
			while [ $? == 0 ] && [ $retry -lt 10 ]
			do
				retry=`expr $retry + 1`
				sleep 1
				ps -p "$tcpdump_saved_pid" > /dev/null
			done
		fi
	else
		rm -f $BG_JOBS_PIDFILE
		return 1
	fi

	rpcdebug -m rpc -c all
	rpcdebug -m nfs -c all

	dmesg -T > nfs_dmesg
    date >nfsstat.post.out
    echo >>nfsstat.post.out
    nfsstat -o nfs -l |sort -k5 -nr >>nfsstat.post.out

    date >mountstats.post.out
    echo >>mountstats.post.out
    mountstats >>mountstats.post.out

	zip nfs_debug.zip       \
        nfs_dmesg           \
        nfs_trace           \
        nfs_traffic.pcap    \
        nfsstat.pre.out     \
        nfsstat.post.out    \
        mountstats.pre.out  \
        mountstats.post.out

	return 0;
}

case $2 in
	start)
		if [ "$3" != "" ]; then
			if [ "$4" != "" ]; then
				start $3 $4
			else
				start $3
			fi
		else
			start
		fi
		;;
	stop)
		stop
		;;
	*)
		echo "Usage: ./nfsclientlogs.sh <v3b | v4> <> <start | stop> <CaptureNetwork> <OnAnomaly>"
		;;
esac

exit $?

#!/bin/bash

#pid file
pidfile="/tmp/smbclientlog.pid"

# prog file
progfile="nohup trace-cmd record -e cifs"

# tcpdump
progfile1="nohup tcpdump -p -s 0 -w cifs_traffic.pcap port 445"

# trace-cifsbpf
ABSOLUTE_PATH="$(cd "$(dirname "trace-cifsbpf")" && pwd)/$(basename "trace-cifsbpf")"
progfile2="nohup $ABSOLUTE_PATH"

# Sanity to check whether trace-cmd is installed.
which trace-cmd > /dev/null
if [ $? == 1 ]; then
	echo "trace-cmd is not installed."
	exit 1
fi

dump_debug_stats() {
	echo -e "\nDate: `date -u`" >> cifs_diag.txt
	echo -e "\n======= CIFS Stats from /proc/fs/cifs/Stats =======" >> cifs_diag.txt
	cat /proc/fs/cifs/Stats >> cifs_diag.txt
	echo -e "\n======= CIFS DebugData from /proc/fs/cifs/DebugData =======" >> cifs_diag.txt
	cat /proc/fs/cifs/DebugData >> cifs_diag.txt
	echo -e "\n======= CIFS Open files from /proc/fs/cifs/open_files =======" >> cifs_diag.txt
	cat /proc/fs/cifs/open_files >> cifs_diag.txt
	echo -e "\n======= CIFS Mounts =======" >> cifs_diag.txt
	mount -t cifs >> cifs_diag.txt
	echo -e "\n======= CIFS TCP Connections =======" >> cifs_diag.txt
	ss -t | grep microsoft >> cifs_diag.txt
}

dump_os_information() {
	echo "======= Distro details =======" > os_details.txt
	cat /etc/os-release >> os_details.txt
	echo -e "\nKernel version: `uname -a`" >> os_details.txt
	echo -e "\nLast reboot:" >> os_details.txt
	last reboot -5 >> os_details.txt
	echo -e "\nSystem Uptime:" >> os_details.txt
	cat /proc/uptime >> os_details.txt
}

start() {
	dmesg -c > /dev/null
	echo 'module cifs +p' > /sys/kernel/debug/dynamic_debug/control
	echo 'file fs/cifs/* +p' > /sys/kernel/debug/dynamic_debug/control
	echo 7 > /proc/fs/cifs/cifsFYI
	rm -f cifs_traffic.pcap
	dump_os_information
	echo "======= Dumping CIFS Debug Stats at start =======" > cifs_diag.txt
	dump_debug_stats
	echo "=================================================" >> cifs_diag.txt
	retry=0
	if [ -f "$pidfile" ]; then
		read pid < $pidfile;
		pgrep_pid=`pgrep trace-cmd | head -1`
		if [ "$pid" == "$pgrep_pid" ]
		then
			echo "[error] [`date +'%FT%H:%M:%S%z'`] trace-cmd is already running, restarting trace-cmd."
			kill -INT $pid
			ps -p "$pid" > /dev/null
			while [ $? == 0 ] && [ $retry -lt 10 ]
			do
				retry=`expr $retry + 1`
				sleep 1
				ps -p "$pid" > /dev/null
			done
			if [ $retry -eq 10 ]; then
				echo "[error] [`date +'%FT%H:%M:%S%z'`] Restarting trace-cmd failed. Exiting.."
				exit 1
			fi
			rm -rf trace.dat*
		fi
	fi

	$progfile 0<&- > /dev/null 2>&1 &

	# save the pid to a file
	echo $! > $pidfile

	if [ "$1" == "CaptureNetwork" ] || [ "$2" == "CaptureNetwork" ]; then
		$progfile1 0<&- > /dev/null 2>&1 &
		echo $! >> $pidfile
	fi

	if [ "$1" == "OnAnomaly" ] || [ "$2" == "OnAnomaly" ]; then
		$progfile2 0<&- > /dev/null 2>&1 &
	fi	
}

stop() {
	retry=0
	rm -rf cifs_trace
	if [ -f "$pidfile" ]; then
		while read -r line
		do
			read -r tcpdump_pid
			pid=$line
		done < $pidfile;
		pgrep_pid=`pgrep trace-cmd | head -1`
		if [ "$pid" != "" ] && [ "$pid" == "$pgrep_pid" ]
		then
			kill -INT $pid
			ps -p "$pid" > /dev/null
			while [ $? == 0 ] && [ $retry -lt 10 ]
			do
				retry=`expr $retry + 1`
				sleep 1
				ps -p "$pid" > /dev/null
			done
			trace-cmd report > cifs_trace
			if [ $? != 0 ]; then
				rm -f $pidfile
				return 1
			fi
			rm -f $pidfile
		else
			rm -f $pidfile
			return 1
		fi
		pgrep_tcpdump_pid=`pgrep tcpdump | head -1`
		if [ "$tcpdump_pid" == "$pgrep_tcpdump_pid" ] && [ "$tcpdump_pid" != "" ]
		then
			kill -INT $tcpdump_pid
			ps -p "$tcpdump_pid" > /dev/null
			while [ $? == 0 ] && [ $retry -lt 10 ]
			do
				retry=`expr $retry + 1`
				sleep 1
				ps -p "$pid" > /dev/null
			done
		fi
	else
		rm -f $pidfile
		return 1
	fi
	echo -e "\n\n======= Dumping CIFS Debug Stats at the end =======" >> cifs_diag.txt
	dump_debug_stats
	sudo dmesg -Tc > cifs_dmesg
	echo 0 > /proc/fs/cifs/cifsFYI
	zip cifs_debug.zip cifs_dmesg cifs_trace cifs_traffic.pcap cifs_diag.txt os_details.txt
	return 0;
}

case $1 in
	start)
		if [ "$2" != "" ]; then
			if [ "$3" != "" ]; then
				start $2 $3
			else
				start $2
			fi
		else
			start
		fi
		;;
	stop)
		stop
		;;
	*)
		echo "Usage: ./smbclientlogs.sh <start | stop> <CaptureNetwork>"
		;;
esac

exit $?

#!/bin/bash

#pid file

PIDFILE="/tmp/smbclientlog.pid"
DIRNAME="./output"
# prog file
progfile="nohup trace-cmd record -e cifs"

if [ ! -d "$DIRNAME" ]; then
  mkdir -p "$DIRNAME"
fi

# tcpdump
progfile1="nohup tcpdump -p -s 0 -w cifs_traffic.pcap port 445"

# trace-cifsbpf
ABSOLUTE_PATH="$(cd "$(dirname "trace-cifsbpf")" && pwd)/$(basename "trace-cifsbpf")"
progfile2="nohup $ABSOLUTE_PATH"

# Sanity to check whether trace-cmd is installed.
which trace-cmd > /dev/null
if [ $? == 1 ]; then
	echo "trace-cmd is not installed, please install trace-cmd to continue"
	exit 1
fi

# Sanity to check whether zip is installed.
which zip > /dev/null
if [ $? == 1 ]; then
        echo "zip is not installed, please install zip to continue"
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
	echo -e "\nSMB/CIFS Kernel Module information:" >> os_details.txt
	modinfo cifs >> os_details.txt
	echo -e "\nMount.cifs version: `mount.cifs -V`" >> os_details.txt
	echo -e "\nLast reboot:" >> os_details.txt
	last reboot -5 >> os_details.txt
	echo -e "\nSystem Uptime:" >> os_details.txt
	cat /proc/uptime >> os_details.txt
}

init() { 
  dmesg -Tc > /dev/null
  rm -f "${DIRNAME}/cifs_dmesg" 
  rm -f "${DIRNAME}/cifs_trace"
  rm -f "${DIRNAME}/cifs_traffic.pcap"
}


start_trace() {
	echo 'module cifs +p' > /sys/kernel/debug/dynamic_debug/control
	echo 'file fs/cifs/* +p' > /sys/kernel/debug/dynamic_debug/control
	echo 7 > /proc/fs/cifs/cifsFYI
  trace-cmd start -e cifs
}

stop_trace() {
  trace-cmd extract
  sleep 1
  trace-cmd report > "${DIRNAME}/cifs_trace"
  trace-cmd stop 
  trace-cmd reset
  rm -rf trace.dat* 
	echo 0 > /proc/fs/cifs/cifsFYI
}

capture_network() {
  nohup tcpdump -p -s 0 port 445 -w "${DIRNAME}/cifs_traffic.pcap" &
  echo $! > "${PIDFILE}"
}

stop_capture_network() {
  [ ! -f "${PIDFILE}" ]  && return 1
  read -r pid < "${PIDFILE}"
  [ ! "${pid}" ] && return 1
  ps -p "${pid}" > /dev/null
  [ $? != 0 ] && return 1

  kill -INT ${pid}
  retry=0
  while [ $? == 0 ] && [ $retry -lt 10 ]
  do
      retry=$((retry + 1))
      sleep 1
      ps -p "${pid}" > /dev/null
    done
  ps -p "${pid}" > /dev/null
  [ $? == 0 ] && echo "Error closing tcpdump" >&2
  rm -f ${PIDFILE}
}

start() {
  init
  start_trace
	dump_os_information
	echo "======= Dumping CIFS Debug Stats at start =======" > cifs_diag.txt
	dump_debug_stats
	echo "=================================================" >> cifs_diag.txt


	if [ "$1" == "CaptureNetwork" ] || [ "$2" == "CaptureNetwork" ]; then
    capture_network
		# $progfile1 0<&- > /dev/null 2>&1 &
	fi

	if [ "$1" == "OnAnomaly" ] || [ "$2" == "OnAnomaly" ]; then
    echo "OnAnomaly Running"
		$progfile2 "${DIRNAME}" &
	fi	

}

stop() {
  dmesg -T > "${DIRNAME}/cifs_dmesg"
  stop_trace
  stop_capture_network

	echo -e "\n\n======= Dumping CIFS Debug Stats at the end =======" >> cifs_diag.txt
	dump_debug_stats
  mv cifs_diag.txt "${DIRNAME}"
  mv os_details.txt "${DIRNAME}"
  zip -r "$(basename ${DIRNAME}).zip" "${DIRNAME}" 
	# zip cifs_debug.zip cifs_dmesg cifs_trace cifs_traffic.pcap cifs_diag.txt os_details.txt
	return 0;
}

case $1 in
	start)
		if [ "$2" != "" ]; then
			if [ "$3" != "" ]; then
				start $2 $3 0<&- > "${DIRNAME}/stdlog.txt" 2>&1
			else
				start $2 0<&- > "${DIRNAME}/stdlog.txt" 2>&1
			fi
		else
			start 0<&- > "${DIRNAME}/stdlog.txt" 2>&1
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

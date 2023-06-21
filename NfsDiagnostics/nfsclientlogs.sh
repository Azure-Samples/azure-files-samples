#!/bin/bash

PIDFILE="/tmp/nfsclientlog.pid"
DIRNAME="./output"
# prog file

if [ $1 == "v3b" ]
then
  nfs_port=111
else
  nfs_port=2049
fi

if [ ! -d "$DIRNAME" ]; then
  mkdir -p "$DIRNAME"
fi

ABSOLUTE_PATH="$(cd "$(dirname "trace-nfsbpf")" && pwd)/$(basename "trace-nfsbpf")"
progfile2="nohup $ABSOLUTE_PATH"

which trace-cmd > /dev/null
if [ $? == 1 ]; then
	echo "trace-cmd is not installed."
	exit 1
fi

which zip > /dev/null
if [ $? == 1 ]; then
        echo "zip is not installed, please install zip to continue"
        exit 1
fi

init() { 
  dmesg -Tc > /dev/null
  rm -f "${DIRNAME}/nfs_dmesg" 
  rm -f "${DIRNAME}/nfs_trace"
  rm -f "${DIRNAME}/nfs_traffic.pcap"
}

start_trace() {
  rpcdebug -m rpc -s all
  rpcdebug -m nfs -s all
  trace-cmd start -e nfs 
}

stop_trace() {
  trace-cmd extract
  sleep 1
  trace-cmd report > "${DIRNAME}/nfs_trace"
  trace-cmd stop 
  trace-cmd reset
  rpcdebug -m rpc -c all
  rpcdebug -m nfs -c all
  rm -rf trace.dat* 
}

capture_network() {
  nohup tcpdump -p -s 0 port ${nfs_port} -w "${DIRNAME}/nfs_traffic.pcap" &
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

	if [ "$1" == "CaptureNetwork" ] || [ "$2" == "CaptureNetwork" ]; then
    capture_network
		# $progfile1 0<&- > /dev/null 2>&1 &
	fi

	if [ "$1" == "OnAnomaly" ] || [ "$2" == "OnAnomaly" ]; then
    echo "OnAnomaly Running"
		$progfile2 "${DIRNAME}" 0<&-   2>&1 &
	fi	
}

stop() {
  dmesg -T > "${DIRNAME}/nfs_dmesg"
  stop_trace
  stop_capture_network
  zip -r "$(basename ${DIRNAME}).zip" "${DIRNAME}" 

  return 0
}

case $2 in
	start)
		if [ "$3" != "" ]; then
			if [ "$4" != "" ]; then
				start $3 $4 0<&- > "${DIRNAME}/stdlog.txt" 2>&1
			else
				start $3 0<&- > "${DIRNAME}/stdlog.txt" 2>&1

			fi
		else
			start 0<&- > "${DIRNAME}/stdlog.txt" 2>&1

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

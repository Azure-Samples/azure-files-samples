#!/bin/bash

PIDFILE="/tmp/nfsclientlog.pid"
DIRNAME="./output"
NFS_PORT=2049
TRACE_NFSBPF_ABS_PATH="$(cd "$(dirname "trace-nfsbpf")" && pwd)/$(basename "trace-nfsbpf")"
PYTHON_PROG='python'
STDLOG_FILE='/dev/null'


main() {
  if [[ "$*" =~ "v3b" ]]
  then
    NFS_PORT=111
  else
    NFS_PORT=2049
  fi

  if [[ "$*" =~ "start" ]]
  then
    start "$@" 0<&- > "${STDLOG_FILE}" 2>&1
  elif [[  "$*" =~ "stop" ]]
  then
    stop 0<&- > "${STDLOG_FILE}" 2>&1
  else
    echo "Usage: ./nfsclientlogs.sh <v3b | v4> <> <start | stop> <CaptureNetwork> <OnAnomaly>"
    exit 1
  fi

  exit $?
}

start() {
  init
  start_trace

  if [[ "$*" =~ "CaptureNetwork" ]]; then
    capture_network
  fi

  if [[ "$*" =~ "OnAnomaly" ]]; then
    trace_nfsbpf
  fi
}

init() {
  check_utils
  rm -r "$DIRNAME" 
  mkdir -p "$DIRNAME"

  dmesg -Tc > /dev/null
  # rm -f "${DIRNAME}/nfs_dmesg"
  # rm -f "${DIRNAME}/nfs_trace"
  # rm -f "${DIRNAME}/nfs_traffic.pcap"
}

check_utils() {
  which trace-cmd > /dev/null
  if [ $? == 1 ]; then
    echo "trace-cmd is not installed, please install trace-cmd"
    exit 1
  fi

  which zip > /dev/null
  if [ $? == 1 ]; then
    echo "zip is not installed, please install zip to continue"
    exit 1
  fi

  which python > /dev/null
  if [ $? == 1 ]; then
    which python3 > /dev/null
    if [ $? == 1 ]; then
      echo "python is not installed, please install python to continue"
      exit 1
    else PYTHON_PROG='python3'
    fi
  fi
}

start_trace() {
  rpcdebug -m rpc -s all
  rpcdebug -m nfs -s all

  trace-cmd start -e nfs
}

capture_network() {
  nohup tcpdump -p -s 0 port ${NFS_PORT} -w "${DIRNAME}/nfs_traffic.pcap" &
  echo $! > "${PIDFILE}"
}

trace_nfsbpf() {
  nohup "${PYTHON_PROG}" "${TRACE_NFSBPF_ABS_PATH}" "${DIRNAME}" 0<&- 2>&1 &
}

stop() {
  dmesg -T  rm -rf trace.dat*
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


main "$@"

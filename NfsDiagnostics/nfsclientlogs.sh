#!/bin/bash

PIDFILE="/tmp/nfsclientlog.pid"
DIRNAME="./output"
NFS_PORT=2049
TRACE_NFSBPF_ABS_PATH="$(cd "$(dirname "trace-nfsbpf")" && pwd)/$(basename "trace-nfsbpf")"
PYTHON_PROG='python'
STDLOG_FILE='/dev/null'

am_i_root() {
    local euid=$(id -u)
    if (( $euid != 0 ));
    then
        echo "Please run $0 as root";
        exit
    fi
}

main() {
  am_i_root
  if [[ "$*" =~ "v3b" ]]
  then
    NFS_PORT=111
  else
    NFS_PORT=2049
  fi

  if [[ "$*" =~ "start" ]]
  then
    start "$@"
  elif [[  "$*" =~ "stop" ]]
  then
    stop
  else
    echo "Usage: ./nfsclientlogs.sh <v3b | v4> <> <start | stop> <CaptureNetwork> <OnAnomaly>"
    exit 1
  fi

  exit $?
}

start() {
  init
  start_trace
  dump_os_information

  echo "======= Dumping NFS Debug Stats at start =======" > nfs_diag.txt
  dump_debug_stats
  echo "=================================================" >> nfs_diag.txt

  if [[ "$*" =~ "CaptureNetwork" ]]; then
    capture_network
  fi

  if [[ "$*" =~ "OnAnomaly" ]]; then
    trace_nfsbpf
  fi
}

init() {
  check_utils

  if [[ -f $DIRNAME ]];
  then
    rm -rf "$DIRNAME"
  fi
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

  which tcpdump > /dev/null
  if [ $? != 0 ]; then
    echo "tcpdump is not installed. Please install tcpdump if you intend to capture network traces."
    #Not exiting since packet capture is optional
  fi

  which zip > /dev/null
  if [ $? == 1 ]; then
    echo "zip is not installed, please install zip to continue"
    exit 1
  fi

  which ss > /dev/null
  if [ $? == 1 ]; then
    echo "ss is not installed, please install ss to continue"
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

dump_os_information() {
  echo "======= Distro details =======" > os_details.txt
  cat /etc/os-release >> os_details.txt
  echo -e "\nKernel version: `uname -a`" >> os_details.txt
  echo -e "\nNFS Kernel Module information:" >> os_details.txt
  modinfo nfs >> os_details.txt
  echo -e "\nLast reboot:" >> os_details.txt
  last reboot -5 >> os_details.txt
  echo -e "\nSystem Uptime:" >> os_details.txt
  cat /proc/uptime >> os_details.txt
}

dump_debug_stats() {
  echo -e "\nDate: `date -u`" >> nfs_diag.txt
  echo -e "\n======= NFS mount stats from mountstats =======" >> nfs_diag.txt
  mountstats  >> nfs_diag.txt
  echo -e "\n======= NFS stats from nfsstat  =======" >> nfs_diag.txt
  nfsstat >> nfs_diag.txt
  echo -e "\n======= NFS Mounts =======" >> nfs_diag.txt
  mount -t nfs4 >> nfs_diag.txt
  echo -e "\n======= NFS TCP Connections =======" >> nfs_diag.txt
  ss -t | grep nfs >> nfs_diag.txt
  echo -e "\n======= List of processes in system =======" >> nfs_diag.txt
  ps -ef >> nfs_diag.txt
}

capture_network() {
  nohup tcpdump -p -s 0 port ${NFS_PORT} -w "${DIRNAME}/nfs_traffic.pcap" &
  echo $! > "${PIDFILE}"
}

trace_nfsbpf() {
  nohup "${PYTHON_PROG}" "${TRACE_NFSBPF_ABS_PATH}" "${DIRNAME}" 0<&- 2>&1 &
}

stop() {
  dmesg -T > "${DIRNAME}/nfs_dmesg"
  stop_trace
  stop_capture_network
  echo -e "\n\n======= Dumping CIFS Debug Stats at the end =======" >> nfs_diag.txt
  dump_debug_stats
  mv nfs_diag.txt "${DIRNAME}"
  mv os_details.txt "${DIRNAME}"
  zip -r "$(basename ${DIRNAME}).zip" "${DIRNAME}"
  return 0;
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

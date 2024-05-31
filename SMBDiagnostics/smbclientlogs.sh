#!/bin/bash

PIDFILE="/tmp/smbclientlog.pid"
DIRNAME="./output"
CIFS_PORT=445
TRACE_CIFSBPF_ABS_PATH="$(cd "$(dirname "trace-cifsbpf")" && pwd)/$(basename "trace-cifsbpf")"
PYTHON_PROG='python'
STDLOG_FILE='/dev/null'
CIFS_FYI_ENABLED=0

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

  if [[ "$*" =~ "start" ]]
  then
    start "$@"
  elif [[  "$*" =~ "stop" ]]
  then
    stop
  else
    echo "Usage: ./smbclientlogs.sh <start | stop> <CaptureNetwork> <VerboseLogs>"
    exit 1
  fi

  exit $?
}

start() {
  init
  start_trace $@
  dump_os_information
  echo "======= Dumping CIFS Debug Stats at start =======" > cifs_diag.txt
  dump_debug_stats
  echo "=================================================" >> cifs_diag.txt


  if [[ "$*" =~ "CaptureNetwork" ]]; then
    capture_network
  fi

  if [[ "$*" =~ "OnAnomaly" ]]; then
    trace_cifsbpf
  fi
}

init() {
  check_utils
  if [[ -f $DIRNAME ]];
  then
    rm -rf "$DIRNAME"
  fi
  mkdir -p "$DIRNAME"
}

check_utils() {
  which trace-cmd > /dev/null
  if [ $? == 1 ]; then
    echo "trace-cmd is not installed, please install trace-cmd"
    exit 1
  fi

  if (( ($(which apt |egrep -c apt) > 0) && ($(which zgrep |egrep -c zgrep) == 0) ));
  then
    echo "zgrep is not installed, please install zgrep"
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
  if [[ "$*" =~ "VerboseLogs" ]]; then
    echo 'module cifs +p' > /sys/kernel/debug/dynamic_debug/control
    echo 'file fs/cifs/* +p' > /sys/kernel/debug/dynamic_debug/control
    echo 7 > /proc/fs/cifs/cifsFYI
    CIFS_FYI_ENABLED=1
  fi
  trace-cmd start -e cifs
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
  echo -e "\npackage install details:" >> os_details.txt
  if (( $(which rpm |egrep -c rpm) > 0));
  then
    rpm -qa --last |grep keyutils >> os_details.txt
    rpm -qa --last |grep cifs-utils >> os_details.txt
    rpm -qi keyutils >> os_details.txt
    rpm -qi cifs-utils >> os_details.txt
  elif (( $(which apt |egrep -c apt) > 0 ));
  then
    zgrep -B5 -A5 keyutils /var/log/apt/history.log* >> os_details.txt
    zgrep -B5 -A5 cifs-utils /var/log/apt/history.log* >> os_details.txt
    dpkg -s keyutils cifs-utils >> os_details.txt 
  fi

}

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


capture_network() {
  nohup tcpdump -p -s 0 port ${CIFS_PORT} -w "${DIRNAME}/cifs_traffic.pcap" &
  echo $! > "${PIDFILE}"
}

trace_cifsbpf() {
  nohup "${PYTHON_PROG}" "${TRACE_CIFSBPF_ABS_PATH}" "${DIRNAME}" 0<&- 2>&1 &
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
  return 0;
}

stop_trace() {
  trace-cmd extract
  sleep 1
  trace-cmd report > "${DIRNAME}/cifs_trace"
  trace-cmd stop
  trace-cmd reset
  if [ $CIFS_FYI_ENABLED -ne 0 ]; then
    echo 0 > /proc/fs/cifs/cifsFYI
  fi
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

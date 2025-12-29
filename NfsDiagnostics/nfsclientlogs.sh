#!/bin/bash

PIDFILE="/tmp/nfsclientlog.pid"
DIRNAME="./output"
NFS_PORT=2049
TRACE_NFSBPF_ABS_PATH="$(cd "$(dirname "trace-nfsbpf")" && pwd)/$(basename "trace-nfsbpf")"
PYTHON_PROG='python'
STDLOG_FILE='/dev/null'

DEFAULT_TRACE_EVENTS_CSV="nfs,nfs4"

# Ring buffer defaults (override via env before invoking)
TCPDUMP_ROTATE_FILE_SIZE_MB=${TCPDUMP_ROTATE_FILE_SIZE_MB:-100}
TCPDUMP_ROTATE_FILE_COUNT=${TCPDUMP_ROTATE_FILE_COUNT:-10}
TCPDUMP_SNAPLEN=${TCPDUMP_SNAPLEN:-0}

AZNFS_STUNNEL_SHARE_DIR="/etc/stunnel/microsoft/aznfs/nfsv4_fileShare"
AZNFS_DATA_DIR="/opt/microsoft/aznfs/data"
AZNFS_PROXY_SERVICE="azurefile-proxy.service"

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
    stop "$@"
  else
    echo "Usage: ./nfsclientlogs.sh <v3b | v4> <> <start | stop> <CaptureNetwork> <OnAnomaly> <VerboseLogs> [TraceEvents=<comma-separated trace events>]"
    exit 1
  fi

  exit $?
}

start() {
  if [ -f "${PIDFILE}" ] && read -r _running_pid < "${PIDFILE}" 2>/dev/null && ps -p "$_running_pid" >/dev/null 2>&1; then
    echo "Warning: A network capture is already in progress (pid $_running_pid). Stop it before starting a new capture." >&2
    return 1
  fi

  init
  start_trace "$@" || return 1
  dump_os_information

  echo "======= Dumping NFS Debug Stats at start =======" > nfs_diag.txt
  dump_debug_stats
  echo "=================================================" >> nfs_diag.txt

  echo "======= Dumping Process callstacks at start =====" > process_callstack.txt
  date >> process_callstack.txt
  dump_process_callstacks
  echo "=================================================" >> process_callstack.txt
  date >> process_callstack.txt

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

  if id -u tcpdump >/dev/null 2>&1; then
    chown tcpdump:tcpdump "$DIRNAME" 2>/dev/null || true
    chmod 750 "$DIRNAME" 2>/dev/null || true
  fi

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

# Validate rotation parameters (simple integer & >0 checks)
validate_tcpdump_rotation() {
  case "$TCPDUMP_ROTATE_FILE_SIZE_MB" in
    ''|*[!0-9]*) echo "Invalid TCPDUMP_ROTATE_FILE_SIZE_MB=$TCPDUMP_ROTATE_FILE_SIZE_MB (must be integer >0)"; return 1;;
  esac

  case "$TCPDUMP_ROTATE_FILE_COUNT" in
    ''|*[!0-9]*) echo "Invalid TCPDUMP_ROTATE_FILE_COUNT=$TCPDUMP_ROTATE_FILE_COUNT (must be integer >0)"; return 1;;
  esac

  if [ "$TCPDUMP_ROTATE_FILE_SIZE_MB" -le 0 ] || [ "$TCPDUMP_ROTATE_FILE_COUNT" -le 0 ]; then
    echo "Rotation parameters must be > 0"
    return 1
  fi

  return 0
}

start_trace() {
  if [[ "$*" =~ "VerboseLogs" ]]; then
    rpcdebug -m rpc -s all
    rpcdebug -m nfs -s all
  fi

  local trace_events_csv="${DEFAULT_TRACE_EVENTS_CSV}"
  local arg
  for arg in "$@"; do
    case "$arg" in
      TraceEvents=*) trace_events_csv="${arg#TraceEvents=}" ;;
    esac
  done

  local -a trace_args=(start)
  local -a specs
  IFS=',' read -r -a specs <<< "$trace_events_csv"

  local spec
  for spec in "${specs[@]}"; do
    spec="${spec//[[:space:]]/}"
    [ -z "$spec" ] && continue
    trace_args+=( -e "$spec" )
  done

  trace-cmd "${trace_args[@]}"
}

dump_os_information() {
  echo "======= Distro details =======" > os_details.txt
  cat /etc/os-release >> os_details.txt
  echo -e "\nKernel version: `uname -a`" >> os_details.txt
  echo -e "\nNFS Kernel Module information:" >> os_details.txt
  modinfo nfs >> os_details.txt
  if command -v last >/dev/null 2>&1; then
    echo -e "\nLast reboot:" >> os_details.txt
    last reboot -5 >> os_details.txt
  fi
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

dump_process_callstacks() {
  local stack_file
  # Iterate through all stack files in /proc/*/stack
  for stack_file in /proc/*/stack; do
    if [ -r "$stack_file" ]; then
      echo "Process: $stack_file" >> process_callstack.txt
      cat "$stack_file" >> process_callstack.txt 2>/dev/null
      echo -e "\n\n" >> process_callstack.txt
    else
      echo "Skipping $stack_file (unreadable or disappeared)" >> process_callstack.txt
    fi
  done
}

capture_network() {
  if validate_tcpdump_rotation; then
    local total=$((TCPDUMP_ROTATE_FILE_SIZE_MB * TCPDUMP_ROTATE_FILE_COUNT))
    echo "Starting circular tcpdump in ${DIRNAME} (${TCPDUMP_ROTATE_FILE_COUNT} files x ${TCPDUMP_ROTATE_FILE_SIZE_MB}MB ~= ${total}MB max)" >&2
    nohup tcpdump -p -n -s "${TCPDUMP_SNAPLEN}" -C "${TCPDUMP_ROTATE_FILE_SIZE_MB}" -W "${TCPDUMP_ROTATE_FILE_COUNT}" -w "${DIRNAME}/nfs_traffic.pcap" port ${NFS_PORT} &
    echo $! > "${PIDFILE}"
  else
    echo "Falling back to single-file tcpdump capture in ${DIRNAME} (no rotation)." >&2
    nohup tcpdump -p -s "${TCPDUMP_SNAPLEN}" port ${NFS_PORT} -w "${DIRNAME}/nfs_traffic.pcap" &
    echo $! > "${PIDFILE}"
  fi
}

trace_nfsbpf() {
  nohup "${PYTHON_PROG}" "${TRACE_NFSBPF_ABS_PATH}" "${DIRNAME}" 0<&- 2>&1 &
}

collect_aznfs_logs() {
  local dest_dir="${DIRNAME}/aznfs"

  if [ -d "${AZNFS_STUNNEL_SHARE_DIR}" ]; then
    mkdir -p "${dest_dir}"
    cp -a "${AZNFS_STUNNEL_SHARE_DIR}" "${dest_dir}/" 2>/dev/null || true
  fi

  if [ -d "${AZNFS_DATA_DIR}" ]; then
    mkdir -p "${dest_dir}"
    cp -a "${AZNFS_DATA_DIR}" "${dest_dir}/" 2>/dev/null || true
  fi

  if command -v journalctl >/dev/null 2>&1; then
    mkdir -p "${dest_dir}"
    journalctl -u "${AZNFS_PROXY_SERVICE}" --no-pager --all > "${dest_dir}/azurefile-proxy.journalctl.txt" 2>&1 || true
  fi

  if command -v systemctl >/dev/null 2>&1; then
    mkdir -p "${dest_dir}"
    systemctl status "${AZNFS_PROXY_SERVICE}" --no-pager --full > "${dest_dir}/azurefile-proxy.systemctl-status.txt" 2>&1 || true
  fi
}

stop() {
  dmesg -T > "${DIRNAME}/nfs_dmesg"
  stop_trace "$@"
  stop_capture_network

  collect_aznfs_logs

  echo -e "\n\n======= Dumping Process callstacks at end  ========" >> process_callstack.txt
  dump_process_callstacks

  echo -e "\n\n======= Dumping NFS Debug Stats at the end =======" >> nfs_diag.txt
  dump_debug_stats
  mv nfs_diag.txt "${DIRNAME}"
  mv os_details.txt "${DIRNAME}"
  mv process_callstack.txt "${DIRNAME}"
  zip -r "$(basename ${DIRNAME}).zip" "${DIRNAME}"
  return 0;
}

stop_trace() {
  trace-cmd extract
  sleep 1
  trace-cmd report > "${DIRNAME}/nfs_trace"
  trace-cmd stop
  trace-cmd reset
  if [[ "$*" =~ "VerboseLogs" ]]; then
    rpcdebug -m rpc -c all
    rpcdebug -m nfs -c all
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

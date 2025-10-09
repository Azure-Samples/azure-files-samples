#!/bin/bash

PIDFILE="/tmp/nfsclientlog.pid"
DIRNAME="./output"
NFS_PORT=2049
TRACE_NFSBPF_ABS_PATH="$(cd "$(dirname "trace-nfsbpf")" && pwd)/$(basename "trace-nfsbpf")"
PYTHON_PROG='python'
STDLOG_FILE='/dev/null'
TRACE_RPCDEBUG_ENABLED=0  # Tracks whether rpcdebug was enabled so we can clean it up conditionally
CAPTURE_DIR_STATE_FILE="/tmp/nfsclientlogs_capture_dir"

# Default ring buffer settings for tcpdump (can be overridden by env vars before invoking script)
# Limit disk usage to (size * count) MB total. Example override:
#   TCPDUMP_ROTATE_FILE_SIZE_MB=100 TCPDUMP_ROTATE_FILE_COUNT=20 ./nfsclientlogs.sh v4 start CaptureNetwork
TCPDUMP_ROTATE_FILE_SIZE_MB=${TCPDUMP_ROTATE_FILE_SIZE_MB:-100}  # Per-file size in MB (default 100MB)
TCPDUMP_ROTATE_FILE_COUNT=${TCPDUMP_ROTATE_FILE_COUNT:-10}       # Number of files in circular buffer
# Snapshot length (bytes) for tcpdump captures; 512 captures all protocol headers for NFS while limiting payload size.
# Override with: TCPDUMP_SNAPLEN=1024 ./nfsclientlogs.sh v4 start CaptureNetwork
TCPDUMP_SNAPLEN=${TCPDUMP_SNAPLEN:-1024}

# Determine (or reuse) tcpdump capture directory. For a running capture we reuse the
# directory recorded in CAPTURE_DIR_STATE_FILE so that a separate "stop" invocation
# can find the files. For a new start (no running tcpdump PID) we create a unique dir
# unless the user explicitly supplied TCPDUMP_CAPTURE_DIR.
if [ -f "$CAPTURE_DIR_STATE_FILE" ] && [ -f "/tmp/nfsclientlog.pid" ]; then
  # Potential existing capture
  if read -r _existing_pid < "/tmp/nfsclientlog.pid" 2>/dev/null && ps -p "$_existing_pid" >/dev/null 2>&1; then
    if [ -z "${TCPDUMP_CAPTURE_DIR+x}" ]; then
      if read -r _prev_dir < "$CAPTURE_DIR_STATE_FILE" 2>/dev/null && [ -d "$_prev_dir" ]; then
        TCPDUMP_CAPTURE_DIR="$_prev_dir"
      fi
    fi
  fi
fi
if [ -z "${TCPDUMP_CAPTURE_DIR+x}" ]; then
  _CAP_BASE="/tmp/tcpdump"
  _RUN_ID="$(date +%Y%m%d-%H%M%S)-$$"
  TCPDUMP_CAPTURE_DIR="${_CAP_BASE}-${_RUN_ID}"
fi

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
    echo "Usage: ./nfsclientlogs.sh <v3b | v4> <> <start | stop> <CaptureNetwork> <OnAnomaly> <VerboseLogs>"
    exit 1
  fi

  exit $?
}

start() {
  # Detect existing capture to avoid overwriting PID/state and spawning duplicates
  if [ -f "${PIDFILE}" ]; then
    if read -r _running_pid < "${PIDFILE}" 2>/dev/null && ps -p "$_running_pid" >/dev/null 2>&1; then
      _running_dir="(unknown)"
      if [ -f "${CAPTURE_DIR_STATE_FILE}" ]; then
        if read -r _d < "${CAPTURE_DIR_STATE_FILE}" 2>/dev/null; then
          _running_dir="${_d}"
        fi
      fi
      echo "Warning: A network capture is already in progress (pid $_running_pid) using directory ${_running_dir}. Stop it before starting a new capture." >&2
      return 1
    fi
  fi
  init
  start_trace "$@"
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
  mkdir -p "$TCPDUMP_CAPTURE_DIR"
  # Make capture dir writable by tcpdump drop user (some distros auto-drop privileges)
  if id -u tcpdump >/dev/null 2>&1; then
    chown tcpdump:tcpdump "$TCPDUMP_CAPTURE_DIR" 2>/dev/null || true
    chmod 750 "$TCPDUMP_CAPTURE_DIR" 2>/dev/null || true
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
    echo "Rotation parameters must be > 0"; return 1
  fi
  return 0
}

start_trace() {
  # Enable rpcdebug only if explicitly requested via "VerboseLogs" argument
  if [[ "$*" =~ "VerboseLogs" ]]; then
    echo "Enabling rpcdebug for rpc and nfs modules" >&2
    rpcdebug -m rpc -s all
    rpcdebug -m nfs -s all
    TRACE_RPCDEBUG_ENABLED=1
  else
    TRACE_RPCDEBUG_ENABLED=0
  fi
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
  # Use tcpdump ring buffer (-C size MB, -W file count) in temporary directory to avoid filling working dir.
  # Files will be named nfs_traffic.pcap, nfs_traffic.pcap1, ...
  if validate_tcpdump_rotation; then
    local total=$((TCPDUMP_ROTATE_FILE_SIZE_MB * TCPDUMP_ROTATE_FILE_COUNT))
    echo "Starting circular tcpdump in ${TCPDUMP_CAPTURE_DIR} (${TCPDUMP_ROTATE_FILE_COUNT} files x ${TCPDUMP_ROTATE_FILE_SIZE_MB}MB ~= ${total}MB max)" >&2
    nohup tcpdump -p -n -s "${TCPDUMP_SNAPLEN}" \
      -C "${TCPDUMP_ROTATE_FILE_SIZE_MB}" \
      -W "${TCPDUMP_ROTATE_FILE_COUNT}" \
      -w "${TCPDUMP_CAPTURE_DIR}/nfs_traffic.pcap" \
      port ${NFS_PORT} &
    echo $! > "${PIDFILE}"
    echo "${TCPDUMP_CAPTURE_DIR}" > "${CAPTURE_DIR_STATE_FILE}" 2>/dev/null || true
  else
    echo "Falling back to single-file tcpdump capture in ${TCPDUMP_CAPTURE_DIR} (no rotation)." >&2
    nohup tcpdump -p -s "${TCPDUMP_SNAPLEN}" port ${NFS_PORT} -w "${TCPDUMP_CAPTURE_DIR}/nfs_traffic.pcap" &
    echo $! > "${PIDFILE}"
    echo "${TCPDUMP_CAPTURE_DIR}" > "${CAPTURE_DIR_STATE_FILE}" 2>/dev/null || true
  fi
}

trace_nfsbpf() {
  nohup "${PYTHON_PROG}" "${TRACE_NFSBPF_ABS_PATH}" "${DIRNAME}" 0<&- 2>&1 &
}

stop() {
  dmesg -T > "${DIRNAME}/nfs_dmesg"
  stop_trace
  stop_capture_network
  # Move pcaps from capture directory into output directory
  if ls "${TCPDUMP_CAPTURE_DIR}"/nfs_traffic.pcap* >/dev/null 2>&1; then
    for pcap in "${TCPDUMP_CAPTURE_DIR}"/nfs_traffic.pcap*; do
      [ -f "$pcap" ] || continue
      mv "$pcap" "${DIRNAME}" 2>/dev/null || { cp -p "$pcap" "${DIRNAME}" 2>/dev/null && rm -f "$pcap"; }
    done
  fi
  # Attempt cleanup of auto-generated temporary capture directory if empty and pattern matches
  if [ -d "${TCPDUMP_CAPTURE_DIR}" ]; then
    # Directory considered auto-generated if it starts with /tmp/tcpdump-
    case "${TCPDUMP_CAPTURE_DIR}" in
      /tmp/tcpdump-*)
        # If no remaining pcaps, remove directory
        if ! ls -A "${TCPDUMP_CAPTURE_DIR}" >/dev/null 2>&1; then
          rmdir "${TCPDUMP_CAPTURE_DIR}" 2>/dev/null || rm -rf "${TCPDUMP_CAPTURE_DIR}" 2>/dev/null || true
        else
          echo "Leaving non-empty capture dir ${TCPDUMP_CAPTURE_DIR}" >&2
        fi
        ;;
    esac
  fi
  # Remove state file after stop (safe even if file not present)
  rm -f "${CAPTURE_DIR_STATE_FILE}" 2>/dev/null || true
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
  if [ ${TRACE_RPCDEBUG_ENABLED} -eq 1 ]; then
    echo "Clearing rpcdebug settings" >&2
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

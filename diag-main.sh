#!/usr/bin/bash

PACKAGE_TREE="$(dirname $(dirname $(readlink -f $0)))"
run() {
  if [[ $1 == "nfs" ]] || [[ $1 == "cifs" ]];
  then 
    if [[ $1 == "nfs" ]]
    then script_path="${PACKAGE_TREE}/lib/NfsDiagnostics/nfsclientlogs.sh"
    else script_path="${PACKAGE_TREE}/lib/SMBDiagnostics/smbclientlogs.sh"
    fi
    $script_path "$@"

  else 
    echo "Usage: diag-main.sh <cifs | nfs> <start | stop> [Version] [CaptureNetwork] [OnAnomaly]" >&2
  fi
}

run "$@"

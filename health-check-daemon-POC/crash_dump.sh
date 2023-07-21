#!/usr/bin/bash

temp_action() {
  echo "encountered error patterns"
}

install_crashdump() {
  export DEBIAN_FRONTEND=noninteractive
  sudo DEBIAN_FRONTEND=noninteractive apt install -y linux-crashdump 
  echo 'GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT crashkernel=512M-:512M"' | sudo tee '/etc/default/grub.d/kdump-tools.cfg'
  _update_configuration
}


_update_configuration() {
  echo "This action requires a restart. Do you want to restart now. Enter (y|N)"
  read -r var;
  res=${var:0:1}
  if [ "$res" == "y" ] || [ "$res" == "Y" ]
  then
    update-grub
    echo restarting
    reboot
    return 0
  fi
  return 1
}

enable_crash_dump() {
  LOAD_KEXEC=$(awk -F= '/^LOAD_KEXEC/ {print $2}' /etc/default/kexec)
  USE_KDUMP=$(awk -F= '/^USE_KDUMP/ {print $2}' /etc/default/kdump-tools)
  echo $LOAD_KEXEC $USE_KDUMP

  if [ "$LOAD_KEXEC" == true ] && [ "$USE_KDUMP" == 1 ]
  then
    echo "Crash Dump is already enabled"
    return 0
  fi
  
  if ! grep -q '^LOAD_KEXEC' /etc/default/kexec
  then
    echo LOAD_KEXEC=true >> /etc/default/kexec
  else
    sed 's/LOAD_KEXEC=false/LOAD_KEXEC=true/' -i /etc/default/kexec
  fi

  if ! grep -q '^USE_KDUMP' /etc/default/kdump-tools
  then
    echo USE_KDUMP=1 >> /etc/default/kdump-tools
  else
    sed 's/USE_KDUMP=0/USE_KDUMP=1/' -i /etc/default/kdump-tools
  fi

  kdump-config load
  echo "Crash Dump Enabled"
}

disable_crash_dump() {
  LOAD_KEXEC=$(awk -F= '/^LOAD_KEXEC/ {print $2}' /etc/default/kexec)
  USE_KDUMP=$(awk -F= '/^USE_KDUMP/ {print $2}' /etc/default/kdump-tools)
  echo $LOAD_KEXEC $USE_KDUMP

  if [ "$LOAD_KEXEC" != true ] && [ "$USE_KDUMP" != 1 ]
  then
    echo "Crash Dump is already disabled"
    return 0
  fi

  sed 's/LOAD_KEXEC=true/LOAD_KEXEC=false/' -i /etc/default/kexec
  sed 's/USE_KDUMP=1/USE_KDUMP=0/' -i /etc/default/kdump-tools

  echo "Crash Dump Disabled"
  _update_configuration

}

if [ "$1" == "enable" ]
then
  enable_crash_dump
elif [ "$1" == "disable" ]
then
  disable_crash_dump
elif [ "$1" == "install" ]
then
  install_crashdump
else
  echo "Usage: ./crash_dump.sh <enable|disable>"
fi

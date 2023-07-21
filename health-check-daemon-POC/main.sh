SLEEP_DURATION=15

input_logs() {
  # cat ./crashdmesg070501.txt ./VMcrashdmesg-20.97.25.82.txt
  # journalctl -ro short-unix
  dmesg
}

signal_handler() {
  sudo bash ./crash_dump.sh disable
}

main() {
  while true;
  do
    input_logs | sudo ./t.awk
    # input_logs | sudo ./t2.awk
    sleep ${SLEEP_DURATION}
  done
}

main


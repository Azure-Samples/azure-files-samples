#!/usr/bin/awk -f

BEGIN {
  i=0;
}

$0 ~ "general protection fault" || $0 ~ "use-after-free" || $0 ~ "kernel NULL pointer dereference" {
  i++;
  system("sudo bash ./crash_dump.sh enable");
  end();
}

END {
  end();
}

function end() {
  # print i;
  # print "End";
  exit 0;
}

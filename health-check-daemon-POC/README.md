# Steps to simulate fault and test the daemon:
1. Install the linux-crashdump using `./crash_dump.sh install`. This step requires a reboot. 
2. Start the daemon by running 'sudo ./main.sh'.
3. Simulate fault by inserting module from `./buggy-module/moduleA.ko`.
4. Wait for daemon to print "Crash Dump Enabled".
5. Once crash dump is enabled, insert the other copy of buggy module `./buggy-module/moduleB.ko`
6. This should trigger a kernel panic and the system should enter into a reboot.
7. Crashdumps will be generated inside `/var/crash` directory.
8. Disable crashdumps manually running `sudo ./crash_dump.sh disable`.

# Note:
- crashdumps can be enabled without a restart.
- disabling crashdumps require a restart.
- moduleB is a copy of moduleA. We need two copies because when the buggy module is inserted, it cannot be removed from kernel by running `rmmod <i>Module Name</i>`. So instead of inserting, removing and reinserting the same module, we instead use a copy of the same module.

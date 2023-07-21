# Generate Packages:
Run `make` to generate both .deb and .rpm packages and clean the build directories or individually run the following:

- Run `make debian` to generate .deb package
- Run `make rpm` to generate .rpm package
- Run `make clean` once the packages are created.

Edit `DEBIAN/control` and `RPM/spec.spec` files to change package description or maintainer information. \
Edit `Makefile` to make changes to PKG_NAME, RELEASE or VERSION, etc.

# Installation:
Debian: 
    `sudo apt install -f ./azure-files-diag.deb`

RPM:
    `sudo dnf install ./azure-files-diag-*.x86_64.rpm`

Add `/opt/xstore/bin/diag-main.sh` to `PATH` for root user. __[Optional]__

# How to use:

These scripts require root priveleges.
1. Start trace:
`sudo diag-main.sh <cifs|nfs> start [<v4|v3b>] [CaptureNetwork] [OnAnomaly]`.
    - NFS defaults to __v4__ (if no version is specified).
    - [<u>OPTION</u>] are optional arguments.

2. Stop:
If __OnAnomaly__ option is enabled, the script will auto detect and collect the traces and generate the zip file. No action needed here. Otherwise: `sudo diag-main.sh <cifs|nfs> stop`


# Uninstall:
Debian:
    `sudo apt remove azure-files-diag`

RPM:
    `sudo dnf remove azure-files-diag`

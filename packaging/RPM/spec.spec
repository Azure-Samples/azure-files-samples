Name:           $PKG_NAME
Version:        $VERSION
Release:        $RELEASE
Summary:        Diagnostics scripts for NFS and CIFS
License:        GPL
URL:            https://example.com

%description
Diagnostics scripts for NFS and CIFS

%prep

%install
# Install script and related files
# install -m 454 ~/opt/xstore/bin/diag-main.sh %{buildroot}/opt/xstore/bin/diag-main.sh 
cp -r ~/rpmbuild/SOURCES/opt %{buildroot}
echo %{buildroot}

%post 
chmod 454 $SYS_DIR/bin/diag-main.sh

%files
# List all the files that are part of the package
# /opt/xstore/bin/diag-main.sh
$SYS_DIR/bin/diag-main.sh
$SYS_DIR/lib/NfsDiagnostics/README
$SYS_DIR/lib/NfsDiagnostics/nfsclientlogs.sh
$SYS_DIR/lib/NfsDiagnostics/trace-nfsbpf
$SYS_DIR/lib/SMBDiagnostics/README
$SYS_DIR/lib/SMBDiagnostics/smbclientlogs.sh
$SYS_DIR/lib/SMBDiagnostics/trace-cifsbpf
%changelog

%postun
rm -r $SYS_DIR

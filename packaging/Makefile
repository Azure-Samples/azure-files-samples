export sles=
export PKG_NAME=nfs-cifs-diag
export RELEASE=1
export VERSION=1
export SYS_DIR=/opt/xstore
export SRC_DIR=..
# export PKG_BUILD=$(PKG_NAME)$(sles)-$(RELEASE)-1.x86_64
# export PKG_DIR=BUILDROOT/$(PKG_BUILD)
export PKG_DIR=$(PKG_NAME)
export DEB_PKG_DIR=$(PKG_DIR)/DEBIAN
export OPT_DIR=$(PKG_DIR)$(SYS_DIR)

build: init 
	echo $(SRC_DIR)
	echo hello

init: 
	mkdir -p $(OPT_DIR)/bin 
	mkdir -p $(OPT_DIR)/lib
	cp -r ../NfsDiagnostics $(OPT_DIR)/lib
	cp -r ../SMBDiagnostics $(OPT_DIR)/lib
	cp -r ../wrapper.sh $(OPT_DIR)/bin

debian: init 
	cp -r ./DEBIAN ./$(PKG_DIR)
	# sed -i "s/\$$PKG_NAME/${PKG_NAME}/g" ./$(PKG_DIR)/DEBIAN/control ./$(PKG_DIR)/DEBIAN/postrm ./$(PKG_DIR)/DEBIAN/postinst
	# sed -i "s/\$$SYS_DIR/${SYS_DIR}/g" ./$(PKG_DIR)/DEBIAN/control ./$(PKG_DIR)/DEBIAN/postrm ./$(PKG_DIR)/DEBIAN/postinst 
	# sed -i "s/\$$VERSION/${VERSION}/g" ./$(PKG_DIR)/DEBIAN/control ./$(PKG_DIR)/DEBIAN/postrm ./$(PKG_DIR)/DEBIAN/postinst
	for file in ./$(PKG_DIR)/DEBIAN/*; do \
		sed -i "s/\$$PKG_NAME/${PKG_NAME}/g" $$file; \
		sed -i "s:\$$SYS_DIR:${SYS_DIR}:g"  $$file; \
		sed -i "s/\$$VERSION/${VERSION}/g" $$file; \
	done
	dpkg-deb --build ./$(PKG_DIR)

rpm: init
	mkdir -p ~/rpmbuild/SOURCES
	cp -r $(PKG_DIR)/opt ~/rpmbuild/SOURCES
	cp ./RPM/spec.spec .
	sed -i "s:\$$SYS_DIR:${SYS_DIR}:g" spec.spec
	sed -i "s:\$$PKG_NAME:${PKG_NAME}:g" spec.spec
	sed -i "s:\$$VERSION:${VERSION}:g" spec.spec
	sed -i "s:\$$RELEASE:${RELEASE}:g" spec.spec
	rpmbuild -bb spec.spec
	mv ~/rpmbuild/RPMS/x86_64/*.rpm .
	rm -r ~/rpmbuild

	

suse:
	echo suse


clean:
	rm -rf ./$(PKG_DIR) spec.spec

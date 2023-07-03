Run `make` to generate both .deb and .rpm packages and clean the build directories or individually run the following:

- Run `make debian` to generate .deb package
- Run `make rpm` to generate .rpm package
- Run `make clean` once the packages are created.

Edit `DEBIAN/control` and `RPM/spec.spec` files to change package description or maintainer information. \
Edit `Makefile` to make changes to PKG_NAME, RELEASE or VERSION, etc.

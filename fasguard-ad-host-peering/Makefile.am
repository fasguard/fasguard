AUTOMAKE_OPTIONS = \
	1.6 \
	foreign \
	subdir-objects \
	parallel-tests \
	-Wall \
	-Wno-extra-portability

ACLOCAL_AMFLAGS = -I build-aux


AM_CXXFLAGS = \
	-Wall \
	-Wextra \
	-g


CLEANFILES =
EXTRA_DIST =
TESTS =
bin_PROGRAMS =


bin_PROGRAMS += \
	fasguard-ad-host-peering

fasguard_ad_host_peering_SOURCES = \
	src/anomaly.cpp \
	src/anomaly.hpp \
	src/container.hpp \
	src/linkheader.cpp \
	src/linkheader.hpp \
	src/logging.hpp \
	src/main.cpp \
	src/network.cpp \
	src/network.hpp

.PHONY: doc
doc: doc/Doxyfile
	doxygen doc/Doxyfile

clean-local: clean-local-doc
.PHONY: clean-local-doc
clean-local-doc:
	rm -rf doc/html doc/latex

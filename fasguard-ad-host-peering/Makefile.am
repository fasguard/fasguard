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
	src/logging.hpp \
	src/main.cpp

.PHONY: doc
doc: doc/Doxyfile
	doxygen doc/Doxyfile

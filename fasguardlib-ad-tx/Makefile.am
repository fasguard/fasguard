AUTOMAKE_OPTIONS = \
	1.6 \
	foreign \
	subdir-objects \
	parallel-tests \
	-Wall \
	-Wno-extra-portability

ACLOCAL_AMFLAGS = -I m4 -I build-aux

AM_CPPFLAGS =

AM_CFLAGS = \
	-Wall \
	-Wextra \
	-g

AM_CXXFLAGS = \
	-Wall \
	-Wextra \
	-g

BUILT_SOURCES =
CLEANFILES =
EXTRA_DIST =
TESTS =
bin_PROGRAMS =
include_HEADERS =
lib_LTLIBRARIES =
noinst_PROGRAMS =

AM_CPPFLAGS += \
	-isystem $(top_srcdir)/include

include_HEADERS += \
	include/fasguardlib-ad-tx.h

.PHONY: doc
doc: doc/Doxyfile
	doxygen doc/Doxyfile

clean-local: clean-local-doc
.PHONY: clean-local-doc
clean-local-doc:
	rm -rf doc/html doc/latex

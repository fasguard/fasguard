AUTOMAKE_OPTIONS = \
	1.6 \
	foreign \
	subdir-objects \
	parallel-tests \
	-Wall \
	-Wno-extra-portability

ACLOCAL_AMFLAGS = -I m4 -I build-aux

AM_CPPFLAGS =

AM_CXXFLAGS = \
	-Wall \
	-Wextra \
	-g

bin_PROGRAMS =
include_HEADERS =
lib_LTLIBRARIES =

######################################################################
# libfasguardfilter
######################################################################
AM_CPPFLAGS += \
	-isystem $(top_srcdir)/src

lib_LTLIBRARIES += \
	src/libfasguardfilter.la

LDADD_LIBFASGUARDFILTER = \
	src/libfasguardfilter.la

include_HEADERS += \
	src/fasguardfilter.hpp \
	src/MurmurHash3.h \
	src/bloomfilter.hpp

src_libfasguardfilter_la_SOURCES = \
	src/bloomfilter.cpp \
	src/filter.cpp \
	src/MurmurHash3.cpp

src_libfasguardfilter_la_LDFLAGS = \
	-version-info 0:0:0

######################################################################
# makebloom
######################################################################
bin_PROGRAMS += \
	src/makebloom

src_makebloom_SOURCES = \
	src/makebloom.cpp

src_makebloom_LDADD = \
	$(LDADD_LIBFASGUARDFILTER)

AUTOMAKE_OPTIONS = \
	1.6 \
	foreign \
	subdir-objects \
	parallel-tests \
	-Wall \
	-Wno-extra-portability

ACLOCAL_AMFLAGS = -I m4 -I build-aux


include mk/flags.mk

bin_PROGRAMS =
include_HEADERS =
lib_LTLIBRARIES =


include mk/libfasguardfilter.mk
include mk/makebloom.mk
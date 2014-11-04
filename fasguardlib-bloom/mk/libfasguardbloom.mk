AM_CPPFLAGS += \
	-isystem $(top_srcdir)/src

lib_LTLIBRARIES += \
	src/libfasguardbloom.la

LDADD_LIBFASGUARDBLOOM = \
	src/libfasguardbloom.la

include_HEADERS += \
	src/fasguardbloom.hpp

src_libfasguardbloom_la_SOURCES =

src_libfasguardbloom_la_LDFLAGS = \
	-version-info 0:0:0

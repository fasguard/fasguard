AM_CPPFLAGS += \
	-isystem $(top_srcdir)/src

lib_LTLIBRARIES += \
	src/libfasguardfilter.la

LDADD_LIBFASGUARDFILTER = \
	src/libfasguardfilter.la

include_HEADERS += \
	src/fasguardfilter.hpp

src_libfasguardfilter_la_SOURCES = \
	src/filter.cpp

src_libfasguardfilter_la_LDFLAGS = \
	-version-info 0:0:0

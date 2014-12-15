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

AUTOMAKE_OPTIONS = \
	1.6 \
	foreign \
	subdir-objects \
	parallel-tests \
	-Wall \
	-Wno-extra-portability

ACLOCAL_AMFLAGS = -I m4 -I build-aux

AM_CPPFLAGS =
AM_CXXFLAGS =
AM_LDFLAGS =

fasguardfilterincludedir = $(includedir)/fasguardfilter
fasguardfilterinclude_HEADERS =
bin_PROGRAMS =
include_HEADERS =
lib_LTLIBRARIES =

######################################################################
# libfasguardfilter
######################################################################
lib_LTLIBRARIES += \
	libfasguardfilter.la

fasguardfilterinclude_HEADERS += \
	include/fasguardfilter/BenignNgramStorage.hh \
	include/fasguardfilter/BloomFilterBase.hh \
	include/fasguardfilter/BloomFilterThreaded.hh \
	include/fasguardfilter/BloomFilterUnthreaded.hh \
	include/fasguardfilter/HashThread.hh \
	include/fasguardfilter/lru_cache_using_std.h

libfasguardfilter_la_SOURCES = \
	src/BenignNgramStorage.cpp \
	src/BloomFilterBase.cpp \
	src/BloomFilterThreaded.cpp \
	src/BloomFilterUnthreaded.cpp \
	src/BloomInsertThread.cpp \
	src/BloomInsertThread.hh \
	src/HashThread.cpp \
	src/MurmurHash3.cpp \
	src/MurmurHash3.h \
	src/fasguardfilter.hpp \
	src/filter.cpp

libfasguardfilter_la_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	$(BOOST_CPPFLAGS) \
	-I$(top_srcdir)/include

libfasguardfilter_la_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(BOOST_DATE_TIME_LDFLAGS) \
	$(BOOST_LOG_LDFLAGS) \
	$(BOOST_REGEX_LDFLAGS) \
	$(BOOST_THREAD_LDFLAGS) \
	-version-info 0:0:0 \
	--no-undefined

libfasguardfilter_la_LIBADD = \
	$(BOOST_DATE_TIME_LDPATH) \
	$(BOOST_DATE_TIME_LIBS) \
	$(BOOST_LOG_LDPATH) \
	$(BOOST_LOG_LIBS) \
	$(BOOST_REGEX_LDPATH) \
	$(BOOST_REGEX_LIBS) \
	$(BOOST_THREAD_LDPATH) \
	$(BOOST_THREAD_LIBS)

######################################################################
# makebloom
######################################################################
bin_PROGRAMS += \
	makebloom

makebloom_SOURCES = \
	src/BloomFilter.hh \
	src/BloomPacketEngine.cpp \
	src/BloomPacketEngine.hpp \
	src/PcapFileEngine.cpp \
	src/PcapFileEngine.hpp \
	src/makebloom.cpp

makebloom_CPPFLAGS = \
	$(AM_CPPFLAGS) \
	$(BOOST_CPPFLAGS) \
	-I$(top_srcdir)/include

makebloom_LDFLAGS = \
	$(AM_LDFLAGS) \
	$(BOOST_DATE_TIME_LDFLAGS) \
	$(BOOST_LOG_LDFLAGS) \
	$(BOOST_PROGRAM_OPTIONS_LDFLAGS) \
	$(BOOST_THREAD_LDFLAGS)

makebloom_LDADD = \
	libfasguardfilter.la \
	$(BOOST_DATE_TIME_LDPATH) \
	$(BOOST_DATE_TIME_LIBS) \
	$(BOOST_LOG_LDPATH) \
	$(BOOST_LOG_LIBS) \
	$(BOOST_PROGRAM_OPTIONS_LDPATH) \
	$(BOOST_PROGRAM_OPTIONS_LIBS) \
	$(BOOST_THREAD_LDPATH) \
	$(BOOST_THREAD_LIBS) \
	$(PCAP_LIBS)

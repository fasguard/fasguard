AC_PREREQ([2.59])
AC_INIT([fasguardlib-filter], [0.1], [fasguard@bbn.com])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([1.11 foreign])
AM_SILENT_RULES
AC_CONFIG_SRCDIR([src/libfasguardfilter/fasguardfilter.hpp])

AM_MAINTAINER_MODE

# note whether the user has specified a value for CXXFLAGS.  this must
# be done very early, before anything else might test the compiler.
AC_MSG_CHECKING([whether CXXFLAGS is set])
AS_IF([test x"${CXXFLAGS+set}" = xset], [
    AC_MSG_RESULT([yes: ${CXXFLAGS:-<empty>}])
    fasguard_cxxflags_given=yes
], [
    AC_MSG_RESULT([no])
    fasguard_cxxflags_given=no
])
AC_PROG_CXX
# change CXXFLAGS default to use -O3 instead of -O2 (if GXX).  this
# must be done immediately after testing the compiler in case later
# tests modify CXXFLAGS
AS_IF([test x"${GXX}" = xyes && test x"${fasguard_cxxflags_given}" != xyes], [
    CXXFLAGS="-g -O3"
    AC_MSG_NOTICE([CXXFLAGS set to: ${CXXFLAGS:-<empty>}])
])

AC_PROG_CXX_C_O
AX_CXX_COMPILE_STDCXX_11

AS_IF([test x"${GXX}" = xyes], [CXXFLAGS="${CXXFLAGS} -Wall -Wextra"])

LT_INIT
AC_PROG_MAKE_SET
AC_PROG_LN_S

AC_CHECK_HEADERS([pcap/pcap.h], [], [
    AC_MSG_FAILURE([pcap/pcap.h not found])
])
AC_CHECK_LIB([pcap], [pcap_open_live], [
    PCAP_LIBS=-lpcap
    AC_SUBST([PCAP_LIBS])
], [
    AC_MSG_FAILURE([libpcap not found])
])

BOOST_REQUIRE([1.54])
BOOST_STATIC
AS_IF([test x"${enable_static_boost}" != xyes], [
    AC_DEFINE([BOOST_ALL_DYN_LINK], [1],
              [Define to 1 if dynamically linking to Boost])
])
BOOST_FIND_HEADER([boost/atomic.hpp])
BOOST_FIND_HEADER([boost/lockfree/queue.hpp])
BOOST_DATE_TIME
BOOST_LOG
BOOST_PROGRAM_OPTIONS
BOOST_REGEX
BOOST_SMART_PTR
BOOST_THREAD
BOOST_UNORDERED

AC_TYPE_SIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT64_T


AC_CONFIG_FILES([
    Makefile
])


AC_OUTPUT

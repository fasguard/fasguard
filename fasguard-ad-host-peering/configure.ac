AC_PREREQ(2.59)
AC_INIT(fasguard-ad-host-peering, 0.1, fasguard@bbn.com)
PACKAGE_LONGNAME="Reference Anomaly Detector"
AC_SUBST([PACKAGE_LONGNAME])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([1.11 foreign])
AM_SILENT_RULES
AC_CONFIG_SRCDIR([src/logging.hpp])
LT_INIT

AM_MAINTAINER_MODE
: ${CFLAGS=""}
AC_PROG_CC
AC_PROG_CC_C_O
AC_PROG_CC_C99
AC_PROG_CXX
AC_PROG_CXX_C_O
AX_CXX_COMPILE_STDCXX_11
AC_PROG_MAKE_SET
AC_PROG_LN_S


AC_SEARCH_LIBS([pcap_open_live], [pcap], [], [
    AC_MSG_FAILURE([libpcap is required])
])

AC_SEARCH_LIBS([fasguard_open_attack_output], [fasguardlib-ad-tx], [], [
    AC_MSG_FAILURE([libfasguardlib-ad-tx is required])
])

AC_CHECK_HEADERS([pcap/pcap.h syslog.h fasguardlib-ad-tx.h], [], [
    AC_MSG_FAILURE([a required header file is missing or does not compile properly])
])

BOOST_REQUIRE([1.40])
BOOST_FIND_HEADER([boost/multi_index/hashed_index.hpp])
BOOST_FIND_HEADER([boost/multi_index/member.hpp])
BOOST_FIND_HEADER([boost/multi_index/ordered_index.hpp])
BOOST_FIND_HEADER([boost/multi_index_container.hpp])
BOOST_HASH
BOOST_MATH

AC_TYPE_INTMAX_T
AC_TYPE_SIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINTMAX_T

AC_FUNC_MALLOC
AC_FUNC_REALLOC

AC_CHECK_FUNCS([getopt_long], [], [
    AC_MSG_FAILURE([a required function is missing])
])


AC_CONFIG_FILES([
    Makefile
    doc/Doxyfile
])


AC_OUTPUT

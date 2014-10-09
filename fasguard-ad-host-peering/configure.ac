AC_PREREQ(2.59)
AC_INIT(fasguard-ad-host-peering, 0.1, fasguard@bbn.com)
PACKAGE_LONGNAME="Reference Anomaly Detector"
AC_SUBST([PACKAGE_LONGNAME])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([1.11 foreign])
AM_SILENT_RULES
AC_CONFIG_SRCDIR([src/logging.hpp])

AM_MAINTAINER_MODE
: ${CFLAGS=""}
AC_PROG_CXX
AC_PROG_CXX_C_O
AC_PROG_MAKE_SET
AC_PROG_RANLIB
AC_PROG_LN_S


AC_SEARCH_LIBS([pcap_open_live], [pcap], [], [
    AC_MSG_FAILURE([libpcap is required])
])

AC_CHECK_HEADERS([syslog.h], [], [
    AC_MSG_FAILURE([a required header file is missing or does not compile properly])
])

AC_TYPE_SIZE_T
AC_TYPE_UINT8_T

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

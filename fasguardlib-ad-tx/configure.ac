AC_PREREQ(2.59)
AC_INIT(fasguardlib-ad-tx, 0.1, fasguard@bbn.com)
PACKAGE_LONGNAME="FASGuard Anomaly Detector Transmission Library"
AC_SUBST([PACKAGE_LONGNAME])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([1.11 foreign])
AM_SILENT_RULES
AC_CONFIG_SRCDIR([include/fasguardlib-ad-tx.h])
LT_INIT

AM_MAINTAINER_MODE
: ${CFLAGS=""}
AC_PROG_CC
AC_PROG_CC_C_O
AC_PROG_CC_C99
AC_PROG_CXX
AC_PROG_CXX_C_O
AC_PROG_MAKE_SET
AC_PROG_LN_S


AC_SEARCH_LIBS([uuid_generate], [uuid], [], [
    AC_MSG_FAILURE([libuuid is required])
])

AC_CHECK_HEADERS([uuid/uuid.h], [], [
    AC_MSG_FAILURE([a required header file is missing or does not compile properly])
])

AC_TYPE_INTMAX_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
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

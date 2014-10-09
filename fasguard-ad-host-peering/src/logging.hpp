/**
    @file
    @brief Macros for logging.

    This file contains macros that should be used for logging.
*/

#ifndef _HOST_PEERING_LOGGING_H
#define _HOST_PEERING_LOGGING_H

#include <syslog.h>
#include <stdbool.h>

/**
    @brief Open the log for writing.

    @note This should be called before any calls to #LOG().
*/
#define OPEN_LOG() \
    do \
    { \
        openlog(PACKAGE_NAME, LOG_PID | LOG_PERROR, LOG_USER); \
    } while (false)

/**
    @brief Close the log.

    @note This should be called before the program exits.
*/
#define CLOSE_LOG() \
    do \
    { \
        closelog(); \
    } while (false)

/**
    @brief Log a message.

    @param[in] priority One of LOG_EMERG, LOG_ALERT, LOG_CRIT, LOG_ERR,
                               LOG_WARNING, LOG_NOTICE, LOG_INFO, or LOG_DEBUG.
    @param[in] format A printf-style format string. Subsequent parameters are
                      subsituted into this string as appropriate.
*/
#define LOG(priority, format, ...) \
    do \
    { \
        syslog((priority), (format), ## __VA_ARGS__); \
    } while (false)

#endif

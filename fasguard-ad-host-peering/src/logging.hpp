/**
    @file
    @brief Macros for logging.

    This file contains macros that should be used for logging.
*/

#ifndef HOST_PEERING_LOGGING_H
#define HOST_PEERING_LOGGING_H

#include <errno.h>
#include <syslog.h>
#include <stdbool.h>
#include <string.h>

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

/**
    @brief Log a message, appending a description of the error in
           errno.

    @sa LOG
*/
#define LOG_PERROR_R(priority, format, ...) \
    do \
    { \
        char _log_perror_buf[256]; \
        if (strerror_r(errno, _log_perror_buf, \
            sizeof(_log_perror_buf)) == 0) \
        { \
            LOG((priority), format ": %s", ## __VA_ARGS__, \
                _log_perror_buf); \
        } \
        else \
        { \
            LOG((priority), format ": error code %d", \
                ## __VA_ARGS__, errno); \
        } \
    } while (false)

#endif

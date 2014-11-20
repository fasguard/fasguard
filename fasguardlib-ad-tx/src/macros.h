/**
    @file
    @brief Useful macros.
*/

#ifndef MACROS_H
#define MACROS_H

/**
    @brief Mark a function as using a printf-style format string and
           variable arguments. This helps the compiler produce
           warnings if the arguments don't match the format string.

    @param[in] fmt 1-based index of the format string argument.
    @param[in] vararg 1-based index of the <tt>...</tt> argument.
*/
#if defined(__GNUC__) && !defined(__APPLE__)
#define FORMAT_PRINTF(fmt, vararg) \
    __attribute__((format(printf, fmt, vararg)))
#else
#define FORMAT_PRINTF(fmt, vararg)
#endif

#endif

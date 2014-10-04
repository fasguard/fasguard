#include <stdlib.h>

#include "logging.h"

int main(
    int argc,
    char **argv)
{
    (void)argc;
    (void)argv;

    OPEN_LOG();

    CLOSE_LOG();

    return EXIT_SUCCESS;
}

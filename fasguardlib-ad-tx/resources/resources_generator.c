#include <getopt.h>
#include <libgen.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int main(
    int argc,
    char **argv)
{
    bool header = false;
    char const * include = NULL;

    static char const options[] = "hi:";
    static struct option const long_options[] = {
        {"header", no_argument, NULL, 'h'},
        {"include", required_argument, NULL, 'i'},
        {NULL, 0, NULL, 0},
    };

    int opt;
    while ((opt = getopt_long(argc, argv, options, long_options, NULL)) != -1)
    {
        switch (opt)
        {
            case 'h':
                header = true;
                break;

            case 'i':
                include = optarg;
                break;

            default:
                fprintf(stderr, "error parsing arguments\n");
                return EXIT_FAILURE;
        }
    }

    srandom(clock());

    if (header)
    {
        long int const header_id[] = {
            random(),
            random(),
            random(),
            random(),
        };
        printf("#ifndef RESOURCES_%ld_%ld_%ld_%ld_H\n",
            header_id[0], header_id[1], header_id[2], header_id[3]);
        printf("#define RESOURCES_%ld_%ld_%ld_%ld_H\n",
            header_id[0], header_id[1], header_id[2], header_id[3]);
    }

    if (include != NULL)
    {
        printf("#include %s\n", include);
    }

    if (header)
    {
        printf("#ifdef __cplusplus\n");
        printf("extern \"C\" {\n");
        printf("#endif\n");
    }

    for (int i = optind; i < argc; ++i)
    {
        char * filename = strdup(argv[i]);
        if (filename == NULL)
        {
            fprintf(stderr, "error copying filename: %s\n", argv[i]);
            return EXIT_FAILURE;
        }

        printf("%sunsigned char const %s[]%s",
            (header ? "extern " : ""),
            basename(filename),
            (header ? ";\n" : " = {"));

        free(filename);
        filename = NULL;

        if (!header)
        {
            FILE * file = fopen(argv[i], "r");
            if (file == NULL)
            {
                fprintf(stderr,
                    "error opening file for reading: %s\n", argv[i]);
                return EXIT_FAILURE;
            }

            int c;
            while ((c = fgetc(file)) != EOF)
            {
                printf("%d,", c);
            }
            printf("0");

            if (fclose(file) != 0)
            {
                fprintf(stderr, "error closing file: %s\n", argv[i]);
                return EXIT_FAILURE;
            }

            printf("};\n");
        }
    }

    if (header)
    {
        printf("#ifdef __cplusplus\n");
        printf("}\n");
        printf("#endif\n");

        printf("#endif\n");
    }
}

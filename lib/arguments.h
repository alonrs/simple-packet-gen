#ifndef ARGUMENTS_H
#define ARGUMENTS_H

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#define MAX_LINE_WIDTH 80
#define MSG_SEPERATOR "\n------\n"

/* Returns argument "NAME" from "ARGS" with default value "DEF" */
#define ARG_INTEGER(ARGS, NAME, DEF)                   \
    arg_find(ARGS, NAME) == NULL ?                     \
    DEF : atoi(arg_find(ARGS, NAME)->value)
#define ARG_DOUBLE(ARGS, NAME, DEF)                    \
    arg_find(ARGS, NAME) == NULL ?                     \
    DEF : atof(arg_find(ARGS, NAME)->value)
#define ARG_BOOL(ARGS, NAME, DEF)                      \
    arg_find(ARGS, NAME) == NULL ?                     \
    DEF : arg_find(ARGS, NAME)->available
#define ARG_STRING(ARGS, NAME, DEF)                    \
    arg_find(ARGS, NAME) == NULL ?                     \
    DEF : arg_find(ARGS, NAME)->value

const char* help_0 = "-h";
const char* help_1 = "--help";

/* Used to define and acquire command line arguments */
struct arguments {
    /* Set by the user */
    const char* name;
    int required;
    int is_boolean;
    const char* value;
    const char* help;

    /* Private */
    int available;
};

/* Prototypes */
void arg_parse(int argc, char **argv, struct arguments*);
struct arguments* arg_find(struct arguments*, const char*);

/* Print long help with (almost) fixed line width */
static inline int
print_next_word(const char *str, int *cursor, int indent)
{
    char buffer[64];
    static int n = 0;
    int i;

    memset(buffer, 0, 64);
    i = 0;

    /* Get next word */
    while ((str[n] != '\0') && (str[n] != ' ')) {
        buffer[i] = str[n];
        ++n;
        ++i;
    }

    /* Skip whitespace */
    while ((str[n] == ' ')) {
        ++n;
    }

    *cursor += i;

    printf("%s ", buffer);
    if (*cursor >= MAX_LINE_WIDTH) {
        printf("\n");
        for (int i=0; i<indent; ++i) {
            printf(" ");
        }
        *cursor=indent;
    }

    if (str[n] != '\0') {
        return 1;
    } else {
        n = 0;
        return 0;
    }
}


/* Parse program arguments */
void
arg_parse(int argc, char **argv, struct arguments *required_args)
{

    struct arguments* current_arg;
    int return_value, width, cursor, n;
    char buffer[1024];
    bool show_optinal_options;

    return_value = 0;
    current_arg = NULL;

    /* Parse the arguments */
    for(int idx=1; idx<argc; ++idx) {

        /* Check which argument is it */
        current_arg = required_args;
        while (current_arg->name != NULL) {

            /* Remove leading dashes */
            n = 0;
            while (argv[idx][n] == '-') {
                ++n;
            }

            /* Check whether there is match */
            if (strcmp(argv[idx]+n, current_arg->name) == 0) {

                /* Check that the current argument prefix is "--" */
                if (strncmp("--",argv[idx],2)) {
                    printf("Argument \"%s\" must begin with '--'" MSG_SEPERATOR,
                            current_arg->name);
                    return_value = 1;
                    goto show_help;
                }

                /* Update the current argument */
                current_arg->available=1;
                if (current_arg->is_boolean==0) {
                    idx++;
                    if (idx == argc) {
                        printf("Missing value for argument \"%s\"" MSG_SEPERATOR,
                                current_arg->name);
                        return_value = 1;
                        goto show_help;
                    }
                    current_arg->value = argv[idx];
                }
                break;
            }
            /* Check whether help is requested */
            else if ((strcmp(argv[idx], help_0) == 0) ||
                     (strcmp(argv[idx], help_1) == 0))
            {
                goto show_help;
            }

            /* Go to the next argument */
            ++current_arg;
        }

        /* In case the argument was found */
        if (current_arg->available==1) {
            continue;
        }

        /* No argument was found, show error */
        printf("Argument %s is not defined" MSG_SEPERATOR, argv[idx]);
        return_value = 1;
        goto show_help;
    }

    /* Check all the required arguments are available */
    current_arg = required_args;
    while (current_arg->name != NULL) {
        if (current_arg->required && !current_arg->available) {
            printf("Argument %s is missing" MSG_SEPERATOR, current_arg->name);
            return_value = 1;
            goto show_help;
        }
        ++current_arg;
    }

    return;

    /* Show help */
    show_help:

    /* Try to print general description */
    current_arg = required_args;
    while (current_arg->name != NULL) {
        ++current_arg;
    };
    if (current_arg->help != NULL) {
        printf("%s\n", current_arg->help);
    }
    printf("MIT License, see LICENSE file for more details\n");

    printf("Usage %s ", argv[0]);

    /* Print mandatory arguments */
    current_arg = required_args;
    while (current_arg->name != NULL) {
        if (current_arg->required) {
            printf("--%s ", current_arg->name);
            if (!current_arg->is_boolean) {
                printf("VALUE ");
            }
        }
        ++current_arg;
    }

    /* Print optional arguments */
    show_optinal_options = false;
    current_arg = required_args;
    while (current_arg->name != NULL) {
        if (!current_arg->required) {
            show_optinal_options = true;
            break;
        }
        ++current_arg;
    }
    if (show_optinal_options) {
        printf("[options...]");
    }
    printf("\n");

    /* Print show help */
    printf("Use %s or %s to show this message\n", help_0, help_1);

    /* What is the longest argument width? */
    width = 0;
    for (current_arg = required_args; current_arg->name != NULL; ++current_arg) {
        int current = strlen(current_arg->name);
        if (!current_arg->is_boolean) current += 8;
        if (!current_arg->required) current += 11;
        if (current > width) width = current;
    }

    /* Space */
    width += 2;

    /* Print help */
    current_arg = required_args;
    while (current_arg->name != NULL) {
        /* Build argument name */
        memset(buffer, 0, 1024);
        strcat(buffer, "--");
        strcat(buffer, current_arg->name);
        if (!current_arg->is_boolean) strcat(buffer, " VALUE");
        if (!current_arg->required) strcat(buffer, " (optional)");
        /* Print spec */
        printf("%s", buffer);
        for (int i=strlen(buffer); i<width; ++i) {
            printf(" ");
        }
        cursor = width;
        while (print_next_word(current_arg->help, &cursor, width));

        if (current_arg->value) {
            sprintf(buffer, "(default: %s)", current_arg->value);
            while (print_next_word(buffer, &cursor, width));
        }
        printf("\n");
        ++current_arg;
    }

    exit(return_value);
}


/* Returns the relevant argument by its name, or NULL if not found */
struct arguments*
arg_find(struct arguments *required_args, const char *name)
{
    while ((required_args->name != NULL) &&
           (strcmp(name, required_args->name) != 0))
    {
        ++required_args;
    }
    if (required_args->name == NULL) {
        return NULL;
    }
    return required_args;
}

#endif
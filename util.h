#ifndef UTIL_H
#define UTIL_H 0

#include <string.h>
#include <stdlib.h>

#define INTERFACE "ath0"
#define DATAPATH "nl:0"

/*void getargs(char *argstr, char **ret; int *numargs)
{
    char *token;
    *numargs = 0;
    int i;
    for(token = strtok(argstr, " "); token != NULL; token = strtok(NULL, " ")) {
        *numargs++;
    }
    ret = malloc(sizeof(char*)*(*numargs));
    for(token = strtok(argstr, " "), i = 0; token != NULL; token = strtok(NULL, " "), i++) {
        (char *)(*(ret+i)) = malloc(sizeof(char)*(strlen(token)+1));
        strncpy(*(ret+i), token, strlen(token));
        (*(ret+i))[strlen(token)] = '\0';
    }
    return ret;
}


void freeargs(char **args, int numargs)
{
    int i = 0;
    for(i = 0; i < numargs; i++) {
        free((char*)(*(args + i)));
    }
    free(args);
}*/

#endif //UTIL_H

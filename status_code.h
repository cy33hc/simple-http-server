#ifndef STATUS_CODE_H
#define STATUS_CODE_H

#include <stdio.h>
#include <stdlib.h>

typedef struct {
    int status;
    const char* status_str;
    const char* message;
} StatusCodeType;

StatusCodeType get_status(int status);

#endif
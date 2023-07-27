#ifndef STATUS_CODE_H
#define STATUS_CODE_H

#include <stdio.h>
#include <stdlib.h>

typedef struct {
    int status;
    const char* status_str;
    const char* message;
} status_pair;

typedef struct  {
    status_pair **statuses;
    size_t size;
} status_table;

status_pair* make_status_pair(int status, char* status_str, const char* message);
void status_table_clear(status_table *tbl);
size_t find_status(status_table *tbl, int status);
const char* get_status_message(status_table *tbl, int status);
void status_table_insert(status_table *tbl, int status, char* status_str, const char* message);
status_pair *get_status(status_table *tbl, int status);

#endif
#include "status_code.h"

status_pair* make_status_pair(int status, char* status_str, const char* message)
{
    status_pair* pair = (status_pair*) malloc(sizeof(status_pair));
    pair->status = status;
    pair->status_str = status_str;
    pair->message = message;
}

void status_table_clear(status_table *tbl)
{
    for (size_t i=0; i < tbl->size; i++)
    {
        free(tbl->statuses[i]);
        tbl->statuses[i] = NULL;
    }
    free(tbl->statuses);
    tbl->size = 0;
}

size_t find_status(status_table *tbl, int status)
{
    for (size_t i=0; i < tbl->size; i++)
    {
        if (tbl->statuses[i]->status == status)
            return i;
    }

    return -1;
}

const char* get_status_message(status_table *tbl, int status)
{
    size_t i = find_status(tbl, status);
    if (i < 0)
        return "";

    return tbl->statuses[i]->message;
}

void status_table_insert(status_table *tbl, int status, char* status_str, const char* message)
{
    if (tbl->size == 0)
    {
        tbl->size = 1;
        tbl->statuses = malloc(sizeof(status_pair*));
    }
    else
    {
        size_t i = find_status(tbl, status);
        if (i != -1)
        {
            tbl->statuses[i]->message = message;
            return;
        }

        tbl->size++;
        tbl->statuses = realloc(tbl->statuses, tbl->size * sizeof(status_pair*));
    }

    status_pair* pair = make_status_pair(status, status_str, message);
    tbl->statuses[tbl->size-1] = pair;
}

status_pair *get_status(status_table *tbl, int status)
{
    size_t i = find_status(tbl, status);
    return tbl->statuses[i];
}
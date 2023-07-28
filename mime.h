#ifndef MIME_H
#define MIME_H

typedef struct
{
    const char *extension;
    const char *type;
} MimeType;

const char *get_mime_type(const char *filename);

#endif
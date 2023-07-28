#include <stdio.h>
#include <string.h>

#include "mime.h"

// MIME type list
static const MimeType mime_type_list[] =
    {
        // Text MIME types
        {".css", "text/css"},
        {".csv", "text/csv"},
        {".htc", "text/x-component"},
        {".htm", "text/html"},
        {".html", "text/html"},
        {".shtm", "text/html"},
        {".shtml", "text/html"},
        {".stm", "text/html"},
        {".txt", "text/plain"},
        {".vcf", "text/vcard"},
        {".vcard", "text/vcard"},
        {".xml", "text/xml"},

        // Image MIME types
        {".gif", "image/gif"},
        {".ico", "image/x-icon"},
        {".jpg", "image/jpeg"},
        {".jpeg", "image/jpeg"},
        {".png", "image/png"},
        {".svg", "image/svg+xml"},
        {".tif", "image/tiff"},
        {".bmp", "image/bmp"},

        // Audio MIME types
        {".aac", "audio/x-aac"},
        {".aif", "audio/x-aiff"},
        {".mp3", "audio/mpeg"},
        {".wav", "audio/x-wav"},
        {".wma", "audio/x-ms-wma"},

        // Video MIME types
        {".avi", "video/x-msvideo"},
        {".flv", "video/x-flv"},
        {".mov", "video/quicktime"},
        {".mp4", "video/mp4"},
        {".mpg", "video/mpeg"},
        {".mpeg", "video/mpeg"},
        {".wmv", "video/x-ms-wmv"},

        // Application MIME types
        {".doc", "application/msword"},
        {".gz", "application/x-gzip"},
        {".gzip", "application/x-gzip"},
        {".js", "application/javascript"},
        {".json", "application/json"},
        {".ogg", "application/ogg"},
        {".pdf", "application/pdf"},
        {".ppt", "application/vnd.ms-powerpoint"},
        {".rar", "application/x-rar-compressed"},
        {".rtf", "application/rtf"},
        {".tar", "application/x-tar"},
        {".tgz", "application/x-gzip"},
        {".xht", "application/xhtml+xml"},
        {".xhtml", "application/xhtml+xml"},
        {".xls", "application/vnd.ms-excel"},
        {".zip", "application/zip"}
    };
static size_t mime_type_len = 48;

const char *get_mime_type(const char *filename)
{
    unsigned int i;
    unsigned int n;
    unsigned int m;

    static const char default_mime_type[] = "application/octet-stream";

    if (filename != NULL)
    {
        n = strlen(filename);

        for (i = 0; i < 47; i++)
        {
            m = strlen(mime_type_list[i].extension);
            if (m <= n && !strcasecmp(filename + n - m, mime_type_list[i].extension))
                return mime_type_list[i].type;
        }
    }

    return default_mime_type;
}

#include "util.h"

static const char wday_name[7][4] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
static const char mon_name[12][4] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};

char *url_decode(const char *src)
{
    size_t src_len = strlen(src);
    char *decoded = malloc(src_len + 1);
    size_t decoded_len = 0;

    // decode %2x to hex
    for (size_t i = 0; i < src_len; i++)
    {
        if (src[i] == '%' && i + 2 < src_len)
        {
            int hex_val;
            sscanf(src + i + 1, "%2x", &hex_val);
            decoded[decoded_len++] = hex_val;
            i += 2;
        }
        else
        {
            decoded[decoded_len++] = src[i];
        }
    }

    // add null terminator
    decoded[decoded_len] = '\0';
    return decoded;
}

void get_current_gmt_date_time(char *date_time_out)
{
    time_t t;
    struct tm *current_date;
    t = time(NULL);
    current_date = gmtime(&t);

    sprintf(date_time_out, "%.3s, %d %.3s %d %.2d:%.2d:%.2d GMT",
            wday_name[current_date->tm_wday], current_date->tm_mday,
            mon_name[current_date->tm_mon], 1900 + current_date->tm_year,
            current_date->tm_hour, current_date->tm_min, current_date->tm_sec);
    return;
}

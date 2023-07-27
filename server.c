#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <regex.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/time.h>

#include "status_code.h"

#define PORT 8080
#define BUFFER_SIZE 1024L
#define MAX_CONTENT_SIZE 12582912L
#define OUT_BUFFER_SIZE 32768L

#define ERROR(rc) if ((rc) < 0) return -1
#define MIN(a, b) (((a) < (b)) ? (a) : (b))

enum HTTP_METHOD
{
    GET,
    HEAD,
    POST,
    PUT,
    DELETE,
    PATCH,
    OPTIONS
};

typedef struct
{
    char *key;
    char *value;
} key_pair;

typedef struct
{
    int sock_fd;
    char *method;
    char *protocol;
    char *path;
    key_pair **params;
    uint16_t params_len;
    key_pair **headers;
    uint16_t headers_len;
    char *body;
    size_t body_len;
    char *_url_line;
    char **_header_lines;
    int _header_lines_len;
} http_request;

typedef struct
{
    int sock_fd;
    int status;
    key_pair **headers;
    uint16_t headers_len;
} http_response;

typedef int (*request_handler_cb)(http_request *req, http_response *res);

typedef struct
{
    char *request_path;
    request_handler_cb request_handler;
} request_handler_pair;

static const char wday_name[7][3] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
static const char mon_name[12][3] = {"Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
static const char error_message[] =  "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\"><html><head><title>%s %s</title></head><body><h1>%s</h1></body></html>";

static request_handler_pair **request_handlers;
static size_t request_handlers_size = 0;
static status_table _status_code_table = {0};
static status_table *status_code_table = &_status_code_table;

static void init_status_codes()
{
    status_table_insert(status_code_table, 100, "100", "Continue");
    status_table_insert(status_code_table, 101, "101", "Switching Protocols");
    status_table_insert(status_code_table, 102, "102", "Processing");
    status_table_insert(status_code_table, 103, "103", "Early Hints");
    status_table_insert(status_code_table, 200, "200", "OK");
    status_table_insert(status_code_table, 201, "201", "Created");
    status_table_insert(status_code_table, 202, "202", "Accepted");
    status_table_insert(status_code_table, 203, "203", "Non-Authoritative Information");
    status_table_insert(status_code_table, 204, "204", "No Content");
    status_table_insert(status_code_table, 205, "205", "Reset Content");
    status_table_insert(status_code_table, 206, "206", "Partial Content");
    status_table_insert(status_code_table, 207, "207", "Multi-Status");
    status_table_insert(status_code_table, 208, "208", "Already Reported");
    status_table_insert(status_code_table, 226, "226", "IM Used");
    status_table_insert(status_code_table, 300, "300", "Multiple Choices");
    status_table_insert(status_code_table, 301, "301", "Moved Permanently");
    status_table_insert(status_code_table, 302, "302", "Found");
    status_table_insert(status_code_table, 303, "303", "See Other");
    status_table_insert(status_code_table, 304, "304", "Not Modified");
    status_table_insert(status_code_table, 307, "307", "Temporary Redirect");
    status_table_insert(status_code_table, 308, "308", "Permanent Redirect");
    status_table_insert(status_code_table, 400, "400", "Bad Request");
    status_table_insert(status_code_table, 401, "401", "Unauthorized");
    status_table_insert(status_code_table, 402, "402", "Payment Required");
    status_table_insert(status_code_table, 403, "403", "Forbidden");
    status_table_insert(status_code_table, 404, "404", "Not Found");
    status_table_insert(status_code_table, 405, "405", "Method Not Allowed");
    status_table_insert(status_code_table, 406, "406", "Not Acceptable");
    status_table_insert(status_code_table, 407, "407", "Proxy Authentication Required");
    status_table_insert(status_code_table, 408, "408", "Request Timeout");
    status_table_insert(status_code_table, 409, "409", "Conflict");
    status_table_insert(status_code_table, 410, "410", "Gone");
    status_table_insert(status_code_table, 411, "411", "Length Required");
    status_table_insert(status_code_table, 412, "412", "Precondition Failed");
    status_table_insert(status_code_table, 413, "413", "Content Too Large");
    status_table_insert(status_code_table, 414, "414", "URI Too Long");
    status_table_insert(status_code_table, 415, "415", "Unsupported Media Type");
    status_table_insert(status_code_table, 416, "416", "Range Not Satisfiable");
    status_table_insert(status_code_table, 417, "417", "Expectation Failed");
    status_table_insert(status_code_table, 421, "421", "Misdirected Request");
    status_table_insert(status_code_table, 422, "422", "Unprocessable Content");
    status_table_insert(status_code_table, 423, "423", "Locked");
    status_table_insert(status_code_table, 424, "424", "Failed Dependency");
    status_table_insert(status_code_table, 425, "425", "Too Early");
    status_table_insert(status_code_table, 426, "426", "Upgrade Required");
    status_table_insert(status_code_table, 428, "428", "Precondition Required");
    status_table_insert(status_code_table, 429, "429", "Too Many Requests");
    status_table_insert(status_code_table, 431, "431", "Request Header Fields Too Large");
    status_table_insert(status_code_table, 451, "451", "Unavailable for Legal Reasons");
    status_table_insert(status_code_table, 500, "500", "Internal Server Error");
    status_table_insert(status_code_table, 501, "501", "Not Implemented");
    status_table_insert(status_code_table, 502, "502", "Bad Gateway");
    status_table_insert(status_code_table, 503, "503", "Service Unavailable");
    status_table_insert(status_code_table, 504, "504", "Gateway Timeout");
    status_table_insert(status_code_table, 505, "505", "HTTP Version Not Supported");
    status_table_insert(status_code_table, 506, "506", "Variant Also Negotiates");
    status_table_insert(status_code_table, 507, "507", "Insufficient Storage");
    status_table_insert(status_code_table, 508, "508", "Loop Detected");
    status_table_insert(status_code_table, 511, "511", "Network Authentication Required");
}

static void add_request_handler(char *path, request_handler_cb handler)
{
    if (request_handlers_size == 0)
    {
        request_handlers_size = 1;
        request_handlers = malloc(sizeof(request_handler_pair*));
    }
    else
    {
        request_handlers_size++;
        request_handlers = realloc(request_handlers, request_handlers_size * sizeof(request_handler_pair*));
    }

    request_handler_pair *pair = malloc(sizeof(request_handler_pair));
    pair->request_path = path;
    pair->request_handler = handler;
    request_handlers[request_handlers_size-1] = pair;

    return;
}

bool case_insensitive_compare(const char *s1, const char *s2)
{
    while (*s1 && *s2)
    {
        if (tolower((unsigned char)*s1) != tolower((unsigned char)*s2))
        {
            return false;
        }
        s1++;
        s2++;
    }
    return *s1 == *s2;
}

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

char *readline(int sock, char *buffer, size_t buffer_size)
{
    size_t ix = 0, bytes_malloced = 0;
    char ch;
    int rc;

    if (!buffer)
    {
        bytes_malloced = 64;
        buffer = malloc(bytes_malloced);
        buffer_size = bytes_malloced;
    }

    for (;; ++ix)
    {
        if (ix == buffer_size - 1)
        {
            if (!bytes_malloced)
                break;
            bytes_malloced += bytes_malloced;
            buffer = realloc(buffer, bytes_malloced);
            buffer_size = bytes_malloced;
        }

        rc = recv(sock, &ch, 1, 0);
        if (rc == 1)
        {
            if (ch == '\n')
                break;
            buffer[ix] = ch;
        }
        else if (rc == 0)
        {
            break;
        }
        else
        {
            if (bytes_malloced)
                free(buffer);
            return NULL;
        }
    }

    if (ix > 0 && buffer[ix - 1] == '\r')
        ix--;

    buffer[ix] = '\0';

    return buffer;
}

char *read_content(int sock, char *buffer, size_t *bytes_read, size_t max_len)
{
    size_t ix = 0, bytes_malloced = 0, buffer_size = 0, remaining = max_len, buffer_remaining, bytes_to_read;
    char *buf_ptr;
    int rc;

    *bytes_read = 0;
    if (!buffer)
    {
        bytes_malloced = BUFFER_SIZE;
        buffer = malloc(bytes_malloced);
        buf_ptr = buffer;
        buffer_size = bytes_malloced;
        buffer_remaining = buffer_size;
    }

    while (remaining > 0)
    {
        bytes_to_read = MIN(buffer_remaining, buffer_size);
        rc = recv(sock, buf_ptr, bytes_to_read, 0);

        if (rc <= 0)
            return buffer;
        else
        {
            buffer_remaining -= rc;
            remaining -= rc;
            buf_ptr += rc;
            *bytes_read += rc;

            if (buffer_remaining == 0 && remaining > 0)
            {
                if (!bytes_malloced)
                    break;
                size_t bytes_to_max = MAX_CONTENT_SIZE - bytes_malloced;
                if (bytes_to_max <= 0)
                    break;
                size_t bytes_to_allocate = MIN(bytes_to_max, bytes_malloced);
                bytes_malloced += bytes_to_allocate;
                size_t offset = buf_ptr - buffer;
                buffer = realloc(buffer, bytes_malloced);
                buf_ptr = buffer + offset;
                buffer_remaining = bytes_malloced - buffer_size;
                buffer_size = bytes_malloced;
            }
        }
    }

    return buffer;
}

void http_request_free(http_request *req)
{
    for (int i = 0; i < req->params_len; i++)
    {
        free(req->params[i]->key);
        free(req->params[i]->value);
        free(req->params[i]);
    }
    if (req->params_len > 0)
        free(req->params);

    for (int i = 0; i < req->headers_len; i++)
    {
        free(req->headers[i]);
    }
    if (req->headers_len > 0)
        free(req->headers);

    for (int i = 0; i < req->_header_lines_len; i++)
    {
        free(req->_header_lines[i]);
    }
    if (req->_header_lines_len > 0)
        free(req->_header_lines);

    if (req->_url_line)
        free(req->_url_line);

    if (req->body)
        free(req->body);

    free(req);
}

void http_response_free(http_response *res)
{
    for (int i = 0; i < res->headers_len; i++)
    {
        free(res->headers[i]->key);
        free(res->headers[i]->value);
        free(res->headers[i]);
    }
    if (res->headers_len > 0)
        free(res->headers);

    free(res);
}

int parse_param_pair(char *param_pair_str, http_request *req)
{
    char *strtok_save;
    char *key = strtok_r(param_pair_str, "=", &strtok_save);
    char *value = strtok_r(NULL, "", &strtok_save);

    if (req->params == NULL)
    {
        req->params = malloc(sizeof(key_pair *));
        req->params_len = 1;
    }
    else
    {
        req->params_len += 1;
        req->params = realloc(req->params, req->params_len * sizeof(key_pair *));
    }

    key_pair *param_pair = malloc(sizeof(key_pair));
    param_pair->key = url_decode(key);
    param_pair->value = url_decode(value == NULL ? "" : value);
    req->params[req->params_len - 1] = param_pair;
}

int parse_url_line(char *buf, http_request *req)
{
    req->_url_line = buf;

    char *strtok_save;
    req->method = strtok_r(buf, " ", &strtok_save);
    char *url = strtok_r(NULL, " ", &strtok_save);
    char *prev_token = strtok_r(NULL, " ", &strtok_save);
    char *cur_token = prev_token;
    while ((cur_token = strtok_r(NULL, " ", &strtok_save)) != NULL)
    {
        prev_token--;
        *prev_token = ' ';
        prev_token = cur_token;
    }
    req->protocol = prev_token;

    strtok_save = NULL;
    req->path = strtok_r(url, "?", &strtok_save);

    char *param_pair = NULL;
    while ((param_pair = strtok_r(NULL, "&", &strtok_save)) != NULL)
    {
        parse_param_pair(param_pair, req);
    }

    return 1;
}

int parse_request_header_line(char *buf, http_request *req)
{
    if (strlen(buf) < 1)
        return 1;

    if (req->_header_lines_len == 0)
    {
        req->_header_lines_len = 1;
        req->headers_len = req->_header_lines_len;
        req->_header_lines = malloc(sizeof(char *));
        req->headers = malloc(sizeof(key_pair *));
    }
    else
    {
        req->_header_lines_len += 1;
        req->headers_len = req->_header_lines_len;
        req->_header_lines = realloc(req->_header_lines, sizeof(char *) * req->_header_lines_len);
        req->headers = realloc(req->headers, sizeof(key_pair *) * req->headers_len);
    }
    req->_header_lines[req->_header_lines_len - 1] = buf;

    key_pair *header_pair = malloc(sizeof(key_pair));

    char *strtok_save;
    header_pair->key = strtok_r(buf, ":", &strtok_save);
    header_pair->value = strtok_r(NULL, "", &strtok_save);

    size_t value_len = strlen(header_pair->value);
    for (int i = 0; i < value_len; i++)
    {
        if (header_pair->value[0] == ' ')
            (header_pair->value)++;
        else
            break;
    }
    req->headers[req->headers_len - 1] = header_pair;

    return 1;
}

const char *get_request_header(http_request *req, const char *key)
{
    for (int i = 0; i < req->headers_len; i++)
    {
        if (case_insensitive_compare(key, req->headers[i]->key))
        {
            return (const char *)req->headers[i]->value;
        }
    }

    return "";
}

int get_request_parameter_count(http_request *req, const char *key)
{
    int count = 0;
    for (int i = 0; i < req->params_len; i++)
    {
        if (case_insensitive_compare(key, req->params[i]->key))
        {
            count++;
        }
    }

    return count;
}

const char *get_request_parameter_idx(http_request *req, const char *key, int idx)
{
    int count = 0;
    for (int i = 0; i < req->params_len; i++)
    {
        if (case_insensitive_compare(key, req->params[i]->key))
        {
            if (count == idx)
                return (const char *)req->params[i]->value;
            count++;
        }
    }

    return "";
}

const char *get_request_parameter(http_request *req, const char *key)
{
    return get_request_parameter_idx(req, key, 0);
}

int parse_request(http_request *req)
{
    char *buf = NULL;

    buf = readline(req->sock_fd, NULL, 0);
    if (buf == NULL)
        return -1;

    parse_url_line(buf, req);

    do
    {
        buf = readline(req->sock_fd, NULL, 0);
        parse_request_header_line(buf, req);
    } while (buf != NULL && strlen(buf) != 0);

    req->body = read_content(req->sock_fd, NULL, &req->body_len, MAX_CONTENT_SIZE);
}

void set_response_header(http_response *res, char* key, char* value)
{
    if (res->headers_len == 0)
    {
        res->headers_len = 1;
        res->headers = malloc(sizeof(key_pair *));
    }
    else
    {
        res->headers_len++;
        res->headers = realloc(res->headers, sizeof(key_pair *) * res->headers_len);
    }

    key_pair *header_pair = malloc(sizeof(key_pair));
    header_pair->key = malloc(strlen(key)+1);
    header_pair->value = malloc(strlen(value)+1);
    strcpy(header_pair->key, key);
    strcpy(header_pair->value, value);
    res->headers[res->headers_len-1] = header_pair;
}

int write_response_headers(http_response *res)
{
    char *out;
    
    out = malloc(2048);
    snprintf(out, 2047, "HTTP/1.1 %d %s\n", res->status, get_status_message(status_code_table, res->status));

    ssize_t rc = send(res->sock_fd, out, strlen(out), 0);
    if (rc < 0) { free(out); return -1; }

    for (size_t i=0; i < res->headers_len; i++)
    {
        snprintf(out, 2047, "%s: %s\n", res->headers[i]->key, res->headers[i]->value);
        rc = send(res->sock_fd, out, strlen(out), 0);
        if (rc < 0) { free(out); return -1; }
    }
    send(res->sock_fd, "\n", 1, 0);

    free(out);
    return 1;
}

void socket_init(int sock_fd)
{
    int yes = 1;
    setsockopt(sock_fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

http_request *http_request_init(int sock_fd)
{
    http_request *request = malloc(sizeof(http_request));
    memset(request, 0, sizeof(http_request));
    request->sock_fd = sock_fd;
    return request;
}

http_response *http_response_init(int sock_fd)
{
    http_response *response = malloc(sizeof(http_response));
    memset(response, 0, sizeof(http_response));
    response->sock_fd = sock_fd;
    return response;
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

int default_error_handler(http_response *res)
{
    write_response_headers(res);
    status_pair *status = get_status(status_code_table, res->status);
    size_t bytes_to_alloc = strlen(error_message) + strlen(status->status_str) + (strlen(status->message)*2) + 10;
    char *err_buf = malloc(bytes_to_alloc);
    snprintf(err_buf, bytes_to_alloc, error_message, status->status_str, status->message, status->message);
    int rc = send(res->sock_fd, err_buf, strlen(err_buf), 0);
    free(err_buf);
    ERROR(rc);
    return 1;
}

int stream_file(http_response *res, const char *file)
{
    int rc, bytes_read, bytes_written;
    char size_buf[64];
    char *out_buf;

    FILE *fp = fopen(file, "rb");
    if (fp == NULL)
    {
        res->status = 404;
        default_error_handler(res);
        return 1;
    }

    rc = fseek(fp, 0L, SEEK_END);
    ERROR(rc);
    ssize_t size = ftell(fp);
    ERROR(size);

    res->status = 200;
    snprintf(size_buf, 63, "%lu", size);
    set_response_header(res, "Content-Length", size_buf);
    set_response_header(res, "Content-Type", "application/octet-stream");
    write_response_headers(res);

    out_buf = malloc(OUT_BUFFER_SIZE);
    rc = fseek(fp, 0L, SEEK_SET);
    do
    {
        bytes_read = fread(out_buf, 1, OUT_BUFFER_SIZE, fp);
        if (bytes_read)
            bytes_written = send(res->sock_fd, out_buf, bytes_read, 0);
        else
            bytes_written = 0;

    } while ((bytes_read > 0) && (bytes_read == bytes_written));
    fclose(fp);
    free(out_buf);
    ERROR(bytes_written);

    return 1;
}

int default_request_handler(http_request *req, http_response *res)
{
    return stream_file(res, req->path);
}

int root_handler(http_request *req, http_response *res)
{
    res->status = 302;
    set_response_header(res, "Location", "/index.html");
    write_response_headers(res);
    return 1;
}

int index_handler(http_request *req, http_response *res)
{
    return stream_file(res, "/home/cyee/projects/angular-filemanager/index.html");
}

void add_default_headers(http_response *res)
{
    char date_time[64];
    get_current_gmt_date_time(date_time);
    set_response_header(res, "Date", date_time);
    set_response_header(res, "Server", "ezRemote Client");
}

request_handler_cb get_request_handler(const char *path)
{
    for (size_t i=0; i < request_handlers_size; i++)
    {
        if (strcmp(path, request_handlers[i]->request_path) == 0)
            return request_handlers[i]->request_handler;
    }

    return default_request_handler;
}

void *handle_client(void *arg)
{
    int client_fd = *((int *)arg);
    socket_init(client_fd);

    http_request *request = http_request_init(client_fd);
    http_response *response = http_response_init(client_fd);

    parse_request(request);
    add_default_headers(response);

    request_handler_cb handler = get_request_handler(request->path);
    if (handler != NULL)
        handler(request, response);

    http_request_free(request);
    http_response_free(response);

    close(client_fd);
    free(arg);
    return NULL;
}

int main(int argc, char *argv[])
{
    int server_fd;
    struct sockaddr_in server_addr;

    init_status_codes();

    add_request_handler("/", root_handler);

    // create server socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
    {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // config socket
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // bind socket to port
    if (bind(server_fd,
             (struct sockaddr *)&server_addr,
             sizeof(server_addr)) < 0)
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // listen for connections
    if (listen(server_fd, 10) < 0)
    {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d\n", PORT);
    while (1)
    {
        // client info
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        int *client_fd = malloc(sizeof(int));

        // accept client connection
        if ((*client_fd = accept(server_fd,
                                 (struct sockaddr *)&client_addr,
                                 &client_addr_len)) < 0)
        {
            perror("accept failed");
            continue;
        }

        // create a new thread to handle client request
        pthread_t thread_id;
        pthread_create(&thread_id, NULL, handle_client, (void *)client_fd);
        pthread_detach(thread_id);
    }

    close(server_fd);
    return 0;
}
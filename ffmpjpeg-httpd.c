#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <err.h>
#include <stdlib.h>
#include <getopt.h>
#include <time.h>

/* libevent */
#include <event2/event_struct.h>
#include <event2/event.h>

#define STDIN_READ_SIZE 32768
#define HTTP_DEFAULT_ADDR "127.0.0.1"
#define HTTP_DEFAULT_PORT 8080
#define HTTP_READ_TIMEOUT 30
#define HTTP_READ_BUFFER 16384

const static char boundary_charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
static struct event_base *eb;
static char *boundary = NULL;  // --ffmpeg\r\n
static int boundary_len = 0;   // strlen(boundary)
static int verbose = 0;

static char stdin_buffer[2097152];  // 2MiB
static int stdin_buflen = 0;
static char *headers = NULL;
static char *frame = NULL;
static int frame_size = 0;
static int skip = 0;

struct http_client {
    struct http_client *next;
    char boundary[32];
    struct event ev;
    size_t reqsize;
    char *request;
    int waitreq;
    int skip;
    int fd;
};

static struct http_client *http_clients = NULL;
char http_reply_fmt[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Type: multipart/x-mixed-replace; boundary=\"%s\"\r\n"
    "Cache-Control: no-store, no-cache, must-revalidate, pre-check=0, post-check=0, max-age=0\r\n"
    "Pragma: no-cache\r\n"
    "Expires: Sun, 1 Jan 2000 00:00:00 GMT\r\n"
    "Connection: close\r\n\r\n--%s\r\n";


static void http_client_close(struct http_client *client)
{
    if (client == http_clients)
        http_clients = client->next;
    else {
        struct http_client *curr;
        for (curr = http_clients; curr->next != client; curr = curr->next);
        curr->next = client->next;
    }

    event_del(&client->ev);

    if (client->request)
        free(client->request);

    close(client->fd);

    free(client);
}


static void on_stdin_read(int fd, short ev, void *arg)
{
    struct http_client *client;
    size_t size;
    void *c;
    int ret;

    size = sizeof(stdin_buffer) - stdin_buflen;
    if (size > STDIN_READ_SIZE)
        size = STDIN_READ_SIZE;

    if (size == 0) {
        fprintf(stderr, "stdin buffer overflow (bad boundary?)\n");
        exit(EXIT_FAILURE);
    }

    ret = read(fd, stdin_buffer + stdin_buflen, size);

    if (ret == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return;

        err(EXIT_FAILURE, "failed to read from stdin");
    }

    if (ret == 0)
        exit(EXIT_SUCCESS);

    stdin_buflen += ret;

    /* autodetect boundary */
    if (boundary == NULL) {
        int i;

        if (stdin_buflen < 5)
            return;

        if (stdin_buffer[0] != '-' && stdin_buffer[1] != '-') {
            fprintf(stderr, "cannot find boundary in input data\n");
            exit(EXIT_FAILURE);
        }

        for (i = 2; i < stdin_buflen && stdin_buffer[i] != '\r' && stdin_buffer[i] != '\n'; i++);
        if (i == stdin_buflen)
            return;

        boundary = malloc(i + 3);
        if (boundary == NULL) {
            fprintf(stderr, "cannot allocate memory\n");
            exit(EXIT_FAILURE);
        }

        memcpy(boundary, stdin_buffer, i);
        strcpy(boundary + i, "\r\n");
        boundary_len = strlen(boundary);
    }

    parse:
    /* search headers start */
    if (headers == NULL) {
        c = memmem(stdin_buffer, stdin_buflen, boundary, boundary_len);
        if (c == NULL)
            return;

        headers = c + boundary_len;
    }

    /* search headers end */
    if (frame == NULL) {
        c = memmem(headers, stdin_buflen - (headers - stdin_buffer), "\r\n\r\n", 4);
        if (c == NULL)
            return;

        *((char *)c + 2) = '\0';
        frame = c + 4;
    }

    /* parse headers */
    if (frame_size == 0) {
        char *header, *endptr;

        header = strcasestr(headers - 1, "\ncontent-length:");
        if (header == NULL) {
            fprintf(stderr, "cannot find content-length header\n");
            exit(EXIT_FAILURE);
        }

        header += 16;
        while (*header == ' ' || *header == '\t' || *header == '\r' || *header == '\n')
            header++;

        frame_size = strtol(header, &endptr, 10);
        if ((*endptr != ' ' && *endptr != '\t' && *endptr != '\r' && *endptr != '\n' && *endptr != '\0') || frame_size <= 0) {
            fprintf(stderr, "cannot parse content-length: %s\n", header);
            exit(EXIT_FAILURE);
        }
    }

    /* check frame size */
    if (frame_size > stdin_buflen - (frame - stdin_buffer))
        return;

    /* send frame to http clients */
    for (client = http_clients; client;) {
        struct iovec iov[3];
        char headers[128];
        char bndbuf[64];
        ssize_t ret;

        if (client->waitreq) {
            client = client->next;
            continue;
        }

        if (client->skip) {
            client->skip--;
            client = client->next;
            continue;
        }

        iov[0].iov_base = headers;
        iov[0].iov_len = snprintf(headers, sizeof(headers),
            "Content-Type: image/jpeg\r\n"
            "Content-Length: %d\r\n"
            "X-Timestamp: 0.000000\r\n"
            "\r\n", frame_size);
        iov[1].iov_base = frame;
        iov[1].iov_len = frame_size;
        iov[2].iov_base = bndbuf;
        iov[2].iov_len = snprintf(bndbuf, sizeof(bndbuf),
            "--%s\r\n", client->boundary);

        ret = writev(client->fd, iov, 3);

        if (ret == -1) {
            struct http_client *to_close = client;

            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                client = client->next;
                continue;
            }

            warn("error writing packet");
            client = client->next;
            http_client_close(to_close);
            continue;
        }

        client->skip = skip;
        client = client->next;
    }

    headers = NULL;
    size = stdin_buflen - (frame - stdin_buffer) - frame_size;

    if (size > 0)
        memmove(stdin_buffer, frame + frame_size, size);

    frame = NULL;
    frame_size = 0;
    stdin_buflen = size;

    if (stdin_buflen > 0)
        goto parse;
}


static void on_http_read(int fd, short ev, void *arg)
{
    struct http_client *client = (struct http_client *)arg;
    char *http_reply;
    char *buffer;
    ssize_t ret;
    int start;
    void *b;

    /* client read timeout */
    if (ev == EV_TIMEOUT) {
        fprintf(stderr, "http client read timeout\n");
        goto close;
    }

    /* client already sent request */
    if (!client->waitreq)
        goto close;

    /* reallocate request buffer */
    buffer = realloc(client->request, client->reqsize + HTTP_READ_BUFFER);
    if (buffer == NULL) {
        fprintf(stderr, "cannot allocate memory\n");
        goto close;
    }
    client->request = buffer;

    /* read (part of) request */
    ret = read(fd, buffer + client->reqsize, HTTP_READ_BUFFER);

    if (ret == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            return;
        else
            goto close;
    }

    if (ret == 0)
        goto close;

    /* search \r\n\r\n in request */
    start = client->reqsize - 3;
    client->reqsize += ret;

    if (start < 0) {
        if (client->reqsize > 4)
            b = memmem(client->request, client->reqsize, "\r\n\r\n", 4);
        else
            b = NULL;
    } else
        b = memmem(client->request + start, client->reqsize - start, "\r\n\r\n", 4);

    if (b == NULL)
        return;

    /* whole request was read */
    client->waitreq = 0;
    free(client->request);
    client->request = NULL;
    client->reqsize = 0;

    http_reply = malloc(sizeof(http_reply_fmt) + sizeof(client->boundary) * 2 + 1);
    if (http_reply == NULL) {
        fprintf(stderr, "cannot allocate memory\n");
        goto close;
    }

    snprintf(http_reply, sizeof(http_reply_fmt) + sizeof(client->boundary) * 2 + 1,
             http_reply_fmt, client->boundary, client->boundary);

    if (write(fd, http_reply, strlen(http_reply)) == -1) {
        free(http_reply);
        goto close;
    }

    free(http_reply);

    /* reschedule read event without read timeout */
    event_del(&client->ev);
    event_add(&client->ev, NULL);

    return;

    close:
    http_client_close(client);
}


static void on_http_accept(int fd, short ev, void *arg)
{
    struct http_client *client;
    struct sockaddr_storage addr;
    socklen_t len = sizeof(addr);
    struct timeval tv;
    int client_fd;
    int i;

    /* accept the new connection. */
    client_fd = accept4(fd, (struct sockaddr *)&addr, &len, SOCK_CLOEXEC | SOCK_NONBLOCK);
    if (client_fd == -1) {
        warn("http accept failed");
        return;
    }

    /* allocate client context */
    client = malloc(sizeof(struct http_client));
    if (client == NULL) {
        fprintf(stderr, "malloc failed\n");
        close(client_fd);
        return;
    }

    /* fill context fields */
    client->fd = client_fd;
    client->reqsize = 0;
    client->request = NULL;
    client->waitreq = 1;
    client->skip = 0;

    for (i = 0; i < sizeof(client->boundary) - 1; i++)
        client->boundary[i] = boundary_charset[rand() % (sizeof(boundary_charset) - 1)];
    client->boundary[i] = '\0';

    /* add http client to list */
    client->next = http_clients;
    http_clients = client;

    /* schedule read events */
    event_assign(&client->ev, eb, client_fd, EV_READ | EV_TIMEOUT | EV_PERSIST, on_http_read, client);
    tv.tv_sec = HTTP_READ_TIMEOUT;
    tv.tv_usec = 0;
    event_add(&client->ev, &tv);
}


static void usage(exit_code) {
    fprintf(stderr, "Usage: ffhttp [option]...\n"
            "\n"
            "Options:\n"
            " -h, --help            show this help\n"
            " -v, --verbose         enable verbose output\n"
            " -a, --addr=ADDRESS    listen address, default loopback\n"
            " -p, --port=PORT       listen port, default 8080\n"
            " -s, --skip=N          skip next N frames after each frame, default 0\n"
            " -b, --boundary        ffmpeg input boundary, default autodetect\n"
            "\n");
    exit(exit_code);
}


int main(int argc, char **argv)
{
    struct event httpd_ev;
    struct event stdin_ev;

    struct sockaddr_storage ss;
    size_t ss_size;
    int sock;

    char *addr = NULL;
    int port = HTTP_DEFAULT_PORT;
    int c;

    /* srand */
    srand(time(NULL));

    /* init libevent */
    eb = event_base_new();
    if (eb == NULL)
        err(EXIT_FAILURE, "event_base_new");

    /* init signals */
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN);

    /* parse arguments */
    while (1) {
        int option_index = 0;
        static struct option long_options[] = {
            {"help", no_argument, NULL, 'h'},
            {"addr", required_argument, NULL, 'a'},
            {"port", required_argument, NULL, 'p'},
            {"skip", required_argument, NULL, 's'},
            {"boundary", required_argument, NULL, 'b'},
            {"verbose", no_argument, NULL, 'v'},
            {NULL, 0, NULL, 0}
        };

        c = getopt_long(argc, argv, "ha:p:s:b:v", long_options, &option_index);

        if (c == -1)
            break;

        switch (c) {
            case 'h':
                usage(0);

            case 'a':
                addr = strdup(optarg);
                break;

            case 'p': {
                char *endptr;
                port = strtol(optarg, &endptr, 10);
                if (*endptr != '\0') {
                    fprintf(stderr, "Bad port: %s\n", endptr);
                    usage(EXIT_FAILURE);
                }
                if (port < 1 || port > 65535) {
                    fprintf(stderr, "Port out of range: %d\n", port);
                    usage(EXIT_FAILURE);
                }
                break;
            }

            case 's': {
                char *endptr;
                skip = strtol(optarg, &endptr, 10);
                if (*endptr != '\0') {
                    fprintf(stderr, "Bad skip: %s\n", endptr);
                    usage(EXIT_FAILURE);
                }
                if (skip < 1) {
                    fprintf(stderr, "Skip number too small: %d\n", skip);
                    usage(EXIT_FAILURE);
                }
                break;
            }

            case 'b':
                boundary_len = strlen(optarg) + 4;
                boundary = malloc(boundary_len + 1);
                if (boundary == NULL) {
                    fprintf(stderr, "cannot allocate memory\n");
                    return EXIT_FAILURE;
                }
                snprintf(boundary, boundary_len + 1, "--%s\r\n", optarg);
                break;

            case 'v':
                verbose++;
                break;

            case '?':
                /* getopt_long already printed an error message. */
                break;

            default:
                abort();
        }
    }

    if (optind < argc) {
        fprintf(stderr, "Unknown argument: %s\n", argv[optind]);
        usage(EXIT_FAILURE);
    }

    if (isatty(STDIN_FILENO))
        usage(EXIT_FAILURE);

    /* setup default values */
    if (addr == NULL)
        addr = HTTP_DEFAULT_ADDR;

    /* create sockaddr_storage from addr and port */
    if (inet_pton(AF_INET6, addr, &(*((struct sockaddr_in6 *)&ss)).sin6_addr) != 0) {
        ss.ss_family = AF_INET6;
        (*((struct sockaddr_in6 *)&ss)).sin6_port = htons(port);
        ss_size = sizeof(struct sockaddr_in6);
    } else if (inet_pton(AF_INET, addr, &(*((struct sockaddr_in *)&ss)).sin_addr) != 0) {
        (*((struct sockaddr_in *)&ss)).sin_port = htons(port);
        ss.ss_family = AF_INET;
        ss_size = sizeof(struct sockaddr_in);
    } else {
        fprintf(stderr, "Can't parse address: %s\n", addr);
        usage(EXIT_FAILURE);
    }

    /* create, bind and listen socket */
    sock = socket(ss.ss_family, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (sock < 0)
        err(EXIT_FAILURE, "listen failed");

    c = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &c, sizeof(c)) == -1)
        err(EXIT_FAILURE, "setsockopt failed");

    if (bind(sock, (struct sockaddr *)&ss, ss_size) < 0)
        err(EXIT_FAILURE, "bind failed");

    if (listen(sock, 5) < 0)
        err(EXIT_FAILURE, "listen failed");

    /* make stdin non-blocking */
    c = fcntl(STDIN_FILENO, F_GETFL, 0);
    if (c != -1)
        if (fcntl(STDIN_FILENO, F_SETFL, c | O_NONBLOCK) < 0)
            warn("failed to make stdin non-blocking");

    /* start stdin read loop */
    event_assign(&stdin_ev, eb, STDIN_FILENO, EV_READ | EV_PERSIST, on_stdin_read, NULL);
    event_add(&stdin_ev, NULL);

    /* start httpd loop */
    event_assign(&httpd_ev, eb, sock, EV_READ | EV_PERSIST, on_http_accept, NULL);
    event_add(&httpd_ev, NULL);

    /* event_base start */
    event_base_dispatch(eb);

    return 0;
}

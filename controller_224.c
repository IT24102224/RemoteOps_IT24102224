#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <poll.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define AGENT_PORT 9410
#define DEFAULT_UDP_PORT 9500
#define LINE_CAPACITY 1024
#define FILE_CHUNK 4096
#define FILE_LIMIT (10ULL * 1024ULL * 1024ULL)
#define SID_TAG "SID:4222"
#define DOWNLOAD_PATH "./downloads"

struct udp_receiver {
    int socket_fd;
    int stop_pipe[2];
    struct in_addr agent_ip;
    pthread_t thread;
};

static int send_all(int fd, const void *data, size_t length)
{
    const unsigned char *bytes = data;
    size_t sent = 0;

    while (sent < length) {
        ssize_t amount = send(fd, bytes + sent,
                              length - sent, MSG_NOSIGNAL);
        if (amount == -1 && errno == EINTR) {
            continue;
        }
        if (amount <= 0) {
            return -1;
        }
        sent += (size_t)amount;
    }
    return 0;
}

/* Read only through the newline, preserving following file bytes. */
static int read_line(int fd, char *line, size_t capacity)
{
    size_t used = 0;

    for (;;) {
        unsigned char byte;
        ssize_t amount = recv(fd, &byte, 1, 0);

        if (amount == -1 && errno == EINTR) {
            continue;
        }
        if (amount == -1) {
            return -1;
        }
        if (amount == 0) {
            return used == 0 ? 0 : -1;
        }
        if (byte == '\0' || used >= capacity - 1) {
            return -1;
        }
        if (byte == '\n') {
            line[used] = '\0';
            return 1;
        }
        line[used++] = (char)byte;
    }
}

static int valid_sid(const char *line)
{
    size_t length = strlen(line);
    size_t tag_length = strlen(SID_TAG);

    return length > tag_length &&
           line[length - tag_length - 1] == ' ' &&
           strcmp(line + length - tag_length, SID_TAG) == 0;
}

static int receive_response(int fd, char *response)
{
    int result = read_line(fd, response, LINE_CAPACITY);
    if (result != 1) {
        fprintf(stderr, "Agent disconnected or TCP response failed\n");
        return -1;
    }
    if (!valid_sid(response)) {
        fprintf(stderr, "Invalid response SID or format\n");
        return -1;
    }

    printf("%s\n", response);
    return 0;
}

static int valid_filename(const char *name)
{
    size_t length = strlen(name);
    if (length == 0 || length > 127 ||
        !isalnum((unsigned char)name[0])) {
        return 0;
    }

    for (size_t i = 0; i < length; i++) {
        unsigned char byte = (unsigned char)name[i];
        if (!isalnum(byte) && byte != '.' &&
            byte != '_' && byte != '-') {
            return 0;
        }
    }
    return 1;
}

static int parse_filename(const char *arguments, char *filename)
{
    int consumed = 0;

    return sscanf(arguments, "%127s %n",
                  filename, &consumed) == 1 &&
           arguments[consumed] == '\0' &&
           valid_filename(filename);
}

static int parse_port(const char *text, unsigned short *port)
{
    if (*text == '\0') {
        return -1;
    }
    for (size_t i = 0; text[i] != '\0'; i++) {
        if (!isdigit((unsigned char)text[i])) {
            return -1;
        }
    }

    errno = 0;
    unsigned long value = strtoul(text, NULL, 10);
    if (errno == ERANGE || value == 0 || value > 65535) {
        return -1;
    }

    *port = (unsigned short)value;
    return 0;
}

static void *udp_loop(void *argument)
{
    struct udp_receiver *receiver = argument;

    struct pollfd descriptors[2] = {
        { .fd = receiver->socket_fd, .events = POLLIN },
        { .fd = receiver->stop_pipe[0], .events = POLLIN }
    };

    for (;;) {
        int result = poll(descriptors, 2, -1);
        if (result == -1 && errno == EINTR) {
            continue;
        }
        if (result == -1) {
            perror("UDP poll");
            break;
        }

        if (descriptors[1].revents != 0) {
            break;
        }
        if (descriptors[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
            fprintf(stderr, "UDP receiver socket failed\n");
            break;
        }
        if (!(descriptors[0].revents & POLLIN)) {
            continue;
        }

        char datagram[LINE_CAPACITY];
        struct sockaddr_in source = {0};
        socklen_t source_length = sizeof(source);

        ssize_t amount = recvfrom(
            receiver->socket_fd, datagram, sizeof(datagram) - 1,
            MSG_TRUNC, (struct sockaddr *)&source, &source_length);

        if (amount == -1 && (errno == EINTR ||
                             errno == EAGAIN ||
                             errno == EWOULDBLOCK)) {
            continue;
        }
        if (amount == -1) {
            perror("recvfrom");
            break;
        }
        if (amount <= 0 || (size_t)amount >= sizeof(datagram)) {
            continue;
        }
        if (source.sin_addr.s_addr != receiver->agent_ip.s_addr) {
            continue;
        }
        if (memchr(datagram, '\0', (size_t)amount) != NULL) {
            continue;
        }

        datagram[amount] = '\0';
        if (datagram[amount - 1] != '\n') {
            continue;
        }
        datagram[amount - 1] = '\0';

        if (strncmp(datagram, "SYSINFO ", 8) != 0 ||
            !valid_sid(datagram) ||
            strchr(datagram, '\n') != NULL ||
            strchr(datagram, '\r') != NULL) {
            continue;
        }

        printf("\n[UDP] %s\n", datagram);
        fflush(stdout);
    }

    return NULL;
}

static int start_receiver(struct udp_receiver *receiver,
                          struct in_addr agent_ip,
                          unsigned short port)
{
    memset(receiver, 0, sizeof(*receiver));
    receiver->agent_ip = agent_ip;
    receiver->socket_fd = socket(
        AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);

    if (receiver->socket_fd == -1) {
        perror("UDP socket");
        return -1;
    }

    struct sockaddr_in local = {0};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = htons(port);

    if (bind(receiver->socket_fd,
             (struct sockaddr *)&local, sizeof(local)) == -1) {
        perror("UDP bind");
        close(receiver->socket_fd);
        return -1;
    }

    if (pipe2(receiver->stop_pipe, O_CLOEXEC) == -1) {
        perror("pipe2");
        close(receiver->socket_fd);
        return -1;
    }

    int result = pthread_create(
        &receiver->thread, NULL, udp_loop, receiver);
    if (result != 0) {
        fprintf(stderr, "UDP thread: %s\n", strerror(result));
        close(receiver->stop_pipe[0]);
        close(receiver->stop_pipe[1]);
        close(receiver->socket_fd);
        return -1;
    }

    return 0;
}

static void stop_receiver(struct udp_receiver *receiver)
{
    /* EOF on the pipe wakes the receiver without a shared stop flag. */
    close(receiver->stop_pipe[1]);
    pthread_join(receiver->thread, NULL);
    close(receiver->stop_pipe[0]);
    close(receiver->socket_fd);
}

static int upload_file(int socket_fd, const char *arguments)
{
    char filename[128];
    if (!parse_filename(arguments, filename)) {
        fprintf(stderr, "Usage: PUT <filename> (no directory path)\n");
        return 0;
    }

    int file_fd = open(filename,
                       O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (file_fd == -1) {
        perror("open upload");
        return 0;
    }

    struct stat info;
    if (fstat(file_fd, &info) == -1 ||
        !S_ISREG(info.st_mode) || info.st_size < 0 ||
        (unsigned long long)info.st_size > FILE_LIMIT) {
        fprintf(stderr, "Upload must be a regular file of at most 10 MiB\n");
        close(file_fd);
        return 0;
    }

    unsigned long long filesize = (unsigned long long)info.st_size;
    char header[256];
    int length = snprintf(header, sizeof(header),
                          "PUT %s %llu\n", filename, filesize);

    if (length < 0 || (size_t)length >= sizeof(header) ||
        send_all(socket_fd, header, (size_t)length) == -1) {
        close(file_fd);
        return -1;
    }

    unsigned char buffer[FILE_CHUNK];
    unsigned long long remaining = filesize;

    while (remaining > 0) {
        size_t wanted = remaining > sizeof(buffer)
                      ? sizeof(buffer) : (size_t)remaining;

        ssize_t amount;
        do {
            amount = read(file_fd, buffer, wanted);
        } while (amount == -1 && errno == EINTR);

        if (amount <= 0 ||
            send_all(socket_fd, buffer, (size_t)amount) == -1) {
            fprintf(stderr, "Upload failed; closing session\n");
            close(file_fd);
            return -1;
        }
        remaining -= (unsigned long long)amount;
    }

    close(file_fd);

    char response[LINE_CAPACITY];
    if (receive_response(socket_fd, response) == -1) {
        return -1;
    }

    char expected[256];
    snprintf(expected, sizeof(expected),
             "OK FILE_RECEIVED %s %s", filename, SID_TAG);

    if (strcmp(response, expected) != 0) {
        fprintf(stderr, "Upload rejected; closing session\n");
        return -1;
    }
    return 0;
}

static int ensure_download_directory(void)
{
    if (mkdir(DOWNLOAD_PATH, 0700) == -1 && errno != EEXIST) {
        perror("mkdir downloads");
        return -1;
    }

    struct stat info;
    if (lstat(DOWNLOAD_PATH, &info) == -1 ||
        !S_ISDIR(info.st_mode)) {
        fprintf(stderr, "Invalid downloads directory\n");
        return -1;
    }
    return 0;
}

static int download_file(int socket_fd, const char *arguments)
{
    char filename[128];
    if (!parse_filename(arguments, filename)) {
        fprintf(stderr, "Usage: GET <filename> (no directory path)\n");
        return 0;
    }
    if (ensure_download_directory() == -1) {
        return 0;
    }

    char request[256];
    int length = snprintf(request, sizeof(request),
                          "GET %s\n", filename);
    if (length < 0 || (size_t)length >= sizeof(request) ||
        send_all(socket_fd, request, (size_t)length) == -1) {
        return -1;
    }

    char response[LINE_CAPACITY];
    if (receive_response(socket_fd, response) == -1) {
        return -1;
    }
    if (strncmp(response, "ERR ", 4) == 0) {
        return 0;
    }

    char returned_name[128];
    char size_text[32];
    char tag[32];
    int consumed = 0;

    if (sscanf(response, "OK FILE_SEND %127s %31s %31s %n",
               returned_name, size_text, tag, &consumed) != 3 ||
        response[consumed] != '\0' ||
        strcmp(returned_name, filename) != 0 ||
        strcmp(tag, SID_TAG) != 0) {
        fprintf(stderr, "Invalid download header\n");
        return -1;
    }

    for (size_t i = 0; size_text[i] != '\0'; i++) {
        if (!isdigit((unsigned char)size_text[i])) {
            fprintf(stderr, "Invalid download size\n");
            return -1;
        }
    }

    errno = 0;
    unsigned long long filesize = strtoull(size_text, NULL, 10);
    if (errno == ERANGE || filesize > FILE_LIMIT) {
        fprintf(stderr, "Download exceeds size limit\n");
        return -1;
    }

    char path[256];
    snprintf(path, sizeof(path), "%s/%s", DOWNLOAD_PATH, filename);

    char temporary[] = DOWNLOAD_PATH "/.downloadXXXXXX";
    int file_fd = mkostemp(temporary, O_CLOEXEC);
    if (file_fd == -1) {
        perror("create download");
        return -1;
    }

    FILE *file = fdopen(file_fd, "wb");
    if (file == NULL) {
        close(file_fd);
        unlink(temporary);
        return -1;
    }

    unsigned char buffer[FILE_CHUNK];
    unsigned long long remaining = filesize;
    int failed = 0;

    while (remaining > 0) {
        size_t wanted = remaining > sizeof(buffer)
                      ? sizeof(buffer) : (size_t)remaining;

        ssize_t amount;
        do {
            amount = recv(socket_fd, buffer, wanted, 0);
        } while (amount == -1 && errno == EINTR);

        if (amount <= 0 ||
            fwrite(buffer, 1, (size_t)amount, file) != (size_t)amount) {
            failed = 1;
            break;
        }
        remaining -= (unsigned long long)amount;
    }

    if (fclose(file) == EOF) {
        failed = 1;
    }
    if (failed) {
        unlink(temporary);
        fprintf(stderr, "Download failed; partial file removed\n");
        return -1;
    }
    if (rename(temporary, path) == -1) {
        perror("rename download");
        unlink(temporary);
        return -1;
    }

    printf("Downloaded %llu bytes to %s\n", filesize, path);
    return 0;
}

static void show_commands(unsigned short udp_port)
{
    printf("\nCommands:\n");
    printf("  AUTH OPS-2224\n");
    printf("  SYSINFO\n");
    printf("  LISTPROC\n");
    printf("  EXEC DATE | UPTIME | DISKFREE | HOSTNAME | WHOAMI\n");
    printf("  PUT <filename>  (size calculated automatically)\n");
    printf("  GET <filename>  (saved under ./downloads/)\n");
    printf("  MONITOR START %u\n", (unsigned int)udp_port);
    printf("  MONITOR STOP\n");
    printf("  QUIT\n");
    printf("  HELP  (local command)\n\n");
}

int main(int argc, char *argv[])
{
    if (argc != 2 && argc != 3) {
        fprintf(stderr, "Usage: %s <agent-ip> [udp-port]\n", argv[0]);
        return EXIT_FAILURE;
    }

    unsigned short udp_port = DEFAULT_UDP_PORT;
    if (argc == 3 && parse_port(argv[2], &udp_port) == -1) {
        fprintf(stderr, "Invalid UDP port\n");
        return EXIT_FAILURE;
    }

    struct sockaddr_in agent_addr = {0};
    agent_addr.sin_family = AF_INET;
    agent_addr.sin_port = htons(AGENT_PORT);

    if (inet_pton(AF_INET, argv[1], &agent_addr.sin_addr) != 1) {
        fprintf(stderr, "Invalid IPv4 address: %s\n", argv[1]);
        return EXIT_FAILURE;
    }

    struct udp_receiver receiver;
    if (start_receiver(&receiver, agent_addr.sin_addr, udp_port) == -1) {
        return EXIT_FAILURE;
    }

    int socket_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (socket_fd == -1) {
        perror("TCP socket");
        stop_receiver(&receiver);
        return EXIT_FAILURE;
    }

    if (connect(socket_fd, (struct sockaddr *)&agent_addr,
                sizeof(agent_addr)) == -1) {
        perror("connect");
        close(socket_fd);
        stop_receiver(&receiver);
        return EXIT_FAILURE;
    }

    printf("Connected to Agent at %s:%d\n", argv[1], AGENT_PORT);
    printf("UDP receiver listening on port %u\n",
           (unsigned int)udp_port);
    show_commands(udp_port);

    int authenticated = 0;
    int exit_status = EXIT_SUCCESS;
    char line[LINE_CAPACITY];
    char response[LINE_CAPACITY];

    for (;;) {
        printf("RemoteOps> ");
        fflush(stdout);

        if (fgets(line, sizeof(line), stdin) == NULL) {
            printf("\nInput closed; closing connection\n");
            break;
        }

        char *newline = strchr(line, '\n');
        if (newline == NULL) {
            int byte;
            while ((byte = getchar()) != '\n' && byte != EOF) {
            }
            fprintf(stderr, "Input too long or missing newline\n");
            continue;
        }
        *newline = '\0';

        size_t length = strlen(line);
        if (length > 0 && line[length - 1] == '\r') {
            line[--length] = '\0';
        }
        if (length == 0) {
            continue;
        }

        if (strcmp(line, "HELP") == 0) {
            show_commands(udp_port);
            continue;
        }

        if (strcmp(line, "PUT") == 0 ||
            strncmp(line, "PUT ", 4) == 0) {
            if (!authenticated) {
                fprintf(stderr, "Authenticate before uploading\n");
                continue;
            }

            const char *arguments =
                strcmp(line, "PUT") == 0 ? "" : line + 4;
            if (upload_file(socket_fd, arguments) == -1) {
                exit_status = EXIT_FAILURE;
                break;
            }
            continue;
        }

        if (strcmp(line, "GET") == 0 ||
            strncmp(line, "GET ", 4) == 0) {
            if (!authenticated) {
                fprintf(stderr, "Authenticate before downloading\n");
                continue;
            }

            const char *arguments =
                strcmp(line, "GET") == 0 ? "" : line + 4;
            if (download_file(socket_fd, arguments) == -1) {
                exit_status = EXIT_FAILURE;
                break;
            }
            continue;
        }

        if (strncmp(line, "MONITOR START ", 14) == 0) {
            unsigned short requested;
            if (parse_port(line + 14, &requested) == -1 ||
                requested != udp_port) {
                fprintf(stderr,
                        "Use MONITOR START %u for this receiver\n",
                        (unsigned int)udp_port);
                continue;
            }
        }

        line[length] = '\n';
        if (send_all(socket_fd, line, length + 1) == -1) {
            perror("send command");
            exit_status = EXIT_FAILURE;
            break;
        }
        line[length] = '\0';

        if (receive_response(socket_fd, response) == -1) {
            exit_status = EXIT_FAILURE;
            break;
        }

        if (strcmp(response, "OK AUTHENTICATED " SID_TAG) == 0) {
            authenticated = 1;
        } else if (strcmp(response, "ERR 001 AUTH_FAILED " SID_TAG) == 0) {
            authenticated = 0;
        }

        if (strcmp(response, "OK BYE " SID_TAG) == 0) {
            break;
        }
    }

    close(socket_fd);
    stop_receiver(&receiver);
    printf("Controller connection closed\n");
    return exit_status;
}

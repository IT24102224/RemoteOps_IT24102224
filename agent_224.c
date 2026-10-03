#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define AGENT_PORT 9410
#define BACKLOG 10
#define RECEIVE_CAPACITY 4096
#define LINE_CAPACITY 1024
#define PROCESS_LIMIT 20
#define FILE_LIMIT (10ULL * 1024ULL * 1024ULL)
#define FILE_CHUNK 4096
#define AUTH_TOKEN "OPS-2224"
#define SID_TAG "SID:4222"
#define STORAGE_ROOT "./agentfiles"
#define STORAGE_PATH "./agentfiles/IT24102224"

struct socket_reader {
    unsigned char buffer[RECEIVE_CAPACITY];
    size_t next;
    size_t available;
};

/* Refill only when all buffered bytes have been consumed. */
static int refill_reader(int fd, struct socket_reader *reader)
{
    if (reader->next < reader->available) {
        return 1;
    }

    ssize_t received;

    do {
        received = recv(fd, reader->buffer,
                        sizeof(reader->buffer), 0);
    } while (received == -1 && errno == EINTR);

    if (received == -1) {
        return -1;
    }

    if (received == 0) {
        return 0;
    }

    reader->next = 0;
    reader->available = (size_t)received;
    return 1;
}

/*
 * Returns:
 *  1: complete line
 *  0: clean end of stream
 * -1: receive error
 * -2: line too long
 * -3: incomplete or invalid text line
 */
static int read_line(int fd, struct socket_reader *reader,
                     char *line, size_t capacity)
{
    size_t used = 0;

    for (;;) {
        int result = refill_reader(fd, reader);

        if (result == -1) {
            return -1;
        }

        if (result == 0) {
            return used == 0 ? 0 : -3;
        }

        unsigned char byte = reader->buffer[reader->next++];

        if (byte == '\n') {
            line[used] = '\0';
            return 1;
        }

        if (byte == '\0') {
            return -3;
        }

        if (used >= capacity - 1) {
            return -2;
        }

        line[used++] = (char)byte;
    }
}

/*
 * Read exactly length bytes, consuming buffered bytes first.
 * Bytes after the requested payload remain for the next command.
 */
static int read_exact(int fd, struct socket_reader *reader,
                      void *destination, size_t length)
{
    unsigned char *output = destination;
    size_t copied = 0;

    while (copied < length) {
        int result = refill_reader(fd, reader);

        if (result != 1) {
            return -1;
        }

        size_t amount = reader->available - reader->next;

        if (amount > length - copied) {
            amount = length - copied;
        }

        memcpy(output + copied, reader->buffer + reader->next,
               amount);

        reader->next += amount;
        copied += amount;
    }

    return 0;
}

static int send_all(int fd, const void *data, size_t length)
{
    const unsigned char *bytes = data;
    size_t sent = 0;

    while (sent < length) {
        ssize_t result = send(fd, bytes + sent,
                              length - sent, MSG_NOSIGNAL);

        if (result == -1) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }

        if (result == 0) {
            return -1;
        }

        sent += (size_t)result;
    }

    return 0;
}

static int send_response(int fd, const char *message)
{
    char response[LINE_CAPACITY];

    int length = snprintf(response, sizeof(response),
                          "%s %s\n", message, SID_TAG);

    if (length < 0 || (size_t)length >= sizeof(response)) {
        fprintf(stderr, "Response formatting failed\n");
        return -1;
    }

    if (send_all(fd, response, (size_t)length) == -1) {
        perror("send");
        return -1;
    }

    printf("Response sent: %s", response);
    fflush(stdout);
    return 0;
}

static int handle_sysinfo(int client_fd)
{
    struct sysinfo info;
    char message[256];

    if (sysinfo(&info) == -1) {
        perror("sysinfo");
        return send_response(client_fd, "ERR 007 SYSINFO_FAILED");
    }

    /* One-minute load average, not CPU utilisation percentage. */
    double cpu_load =
        (double)info.loads[0] / (double)(1UL << SI_LOAD_SHIFT);

    /* Non-free RAM, including buffers and cache. */
    double mem_used_mb =
        ((double)info.totalram - (double)info.freeram) *
        (double)info.mem_unit / (1024.0 * 1024.0);

    int length = snprintf(message, sizeof(message),
                          "OK SYSINFO %.2f %.2f %ld",
                          cpu_load, mem_used_mb, info.uptime);

    if (length < 0 || (size_t)length >= sizeof(message)) {
        return send_response(client_fd, "ERR 007 SYSINFO_FAILED");
    }

    return send_response(client_fd, message);
}

static int handle_listproc(int client_fd)
{
    char message[512] = "OK PROCS ";
    size_t used = strlen(message);
    int count = 0;
    int failed = 0;
    long pid;

    FILE *processes = popen("ps -e -o pid=", "r");

    if (processes == NULL) {
        perror("popen");
        return send_response(client_fd, "ERR 008 LISTPROC_FAILED");
    }

    int scan_result;

    while ((scan_result = fscanf(processes, "%ld", &pid)) == 1) {
        if (pid <= 0) {
            failed = 1;
            continue;
        }

        /* Drain remaining output before pclose(). */
        if (count >= PROCESS_LIMIT || failed) {
            continue;
        }

        int length = snprintf(message + used,
                              sizeof(message) - used,
                              "%s%ld", count == 0 ? "" : ",", pid);

        if (length < 0 ||
            (size_t)length >= sizeof(message) - used) {
            failed = 1;
            continue;
        }

        used += (size_t)length;
        count++;
    }

    if (scan_result != EOF || ferror(processes)) {
        failed = 1;
    }

    int status = pclose(processes);

    if (status != 0 || failed || count == 0) {
        return send_response(client_fd, "ERR 008 LISTPROC_FAILED");
    }

    return send_response(client_fd, message);
}

static int handle_exec(int client_fd, const char *name)
{
    const char *command = NULL;

    if (strcmp(name, "DATE") == 0) {
        command = "date";
    } else if (strcmp(name, "UPTIME") == 0) {
        command = "uptime";
    } else if (strcmp(name, "DISKFREE") == 0) {
        command = "df -h /";
    } else if (strcmp(name, "HOSTNAME") == 0) {
        command = "hostname";
    } else if (strcmp(name, "WHOAMI") == 0) {
        command = "whoami";
    } else {
        return send_response(client_fd,
                             "ERR 002 COMMAND_NOT_ALLOWED");
    }

    FILE *pipe = popen(command, "r");

    if (pipe == NULL) {
        perror("popen");
        return send_response(client_fd, "ERR 009 EXEC_FAILED");
    }

    char output[900];
    size_t used = 0;
    int too_long = 0;
    int invalid_output = 0;
    int byte;

    while ((byte = fgetc(pipe)) != EOF) {
        if (byte == '\n' || byte == '\r' || byte == '\t') {
            byte = ' ';
        }

        if (byte == '\0' || byte < 32 || byte == 127) {
            invalid_output = 1;
            continue;
        }

        if (byte == ' ' &&
            (used == 0 || output[used - 1] == ' ')) {
            continue;
        }

        if (used >= sizeof(output) - 1) {
            too_long = 1;
            continue;
        }

        output[used++] = (char)byte;
    }

    int read_failed = ferror(pipe);
    int status = pclose(pipe);

    if (read_failed || status != 0 || invalid_output) {
        return send_response(client_fd, "ERR 009 EXEC_FAILED");
    }

    if (too_long) {
        return send_response(client_fd,
                             "ERR 010 EXEC_OUTPUT_TOO_LONG");
    }

    while (used > 0 && output[used - 1] == ' ') {
        used--;
    }

    output[used] = '\0';

    if (used == 0) {
        return send_response(client_fd, "ERR 009 EXEC_FAILED");
    }

    char message[LINE_CAPACITY];

    int length = snprintf(message, sizeof(message),
                          "OK EXEC_RESULT %s", output);

    if (length < 0 || (size_t)length >= sizeof(message)) {
        return send_response(client_fd, "ERR 009 EXEC_FAILED");
    }

    return send_response(client_fd, message);
}

/*
 * Accept simple filenames only.
 * First character must be a letter or number.
 * Remaining characters may also include '.', '_' and '-'.
 */
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

static int ensure_directory(const char *path)
{
    if (mkdir(path, 0700) == -1 && errno != EEXIST) {
        perror("mkdir");
        return -1;
    }

    struct stat info;

    if (lstat(path, &info) == -1) {
        perror("lstat");
        return -1;
    }

    if (!S_ISDIR(info.st_mode)) {
        fprintf(stderr, "%s is not a directory\n", path);
        return -1;
    }

    return 0;
}

static int handle_put(int client_fd, struct socket_reader *reader,
                      const char *arguments)
{
    char filename[128];
    char size_text[32];
    int consumed = 0;

    if (sscanf(arguments, "%127s %31s %n",
               filename, size_text, &consumed) != 2 ||
        arguments[consumed] != '\0') {
        send_response(client_fd, "ERR 011 INVALID_PUT");
        return -1;
    }

    if (!valid_filename(filename)) {
        send_response(client_fd, "ERR 012 INVALID_FILENAME");
        return -1;
    }

    for (size_t i = 0; size_text[i] != '\0'; i++) {
        if (!isdigit((unsigned char)size_text[i])) {
            send_response(client_fd, "ERR 011 INVALID_PUT");
            return -1;
        }
    }

    errno = 0;
    unsigned long long filesize = strtoull(size_text, NULL, 10);

    if (errno == ERANGE || filesize > FILE_LIMIT) {
        /*
         * Close after rejection because raw bytes may already
         * follow the header. Do not parse them as commands.
         */
        send_response(client_fd, "ERR 004 FILE_TOO_LARGE");
        return -1;
    }

    char path[256];
    int length = snprintf(path, sizeof(path),
                          "%s/%s", STORAGE_PATH, filename);

    if (length < 0 || (size_t)length >= sizeof(path)) {
        send_response(client_fd, "ERR 012 INVALID_FILENAME");
        return -1;
    }

    /*
     * Receive into a temporary file. Publish the final filename
     * only after every byte has been written successfully.
     */
    char temporary[] = STORAGE_PATH "/.uploadXXXXXX";
    int file_fd = mkstemp(temporary);

    if (file_fd == -1) {
        perror("mkstemp");
        send_response(client_fd, "ERR 013 FILE_WRITE_FAILED");
        return -1;
    }

    FILE *file = fdopen(file_fd, "wb");

    if (file == NULL) {
        perror("fdopen");
        close(file_fd);
        unlink(temporary);
        send_response(client_fd, "ERR 013 FILE_WRITE_FAILED");
        return -1;
    }

    unsigned char buffer[FILE_CHUNK];
    unsigned long long remaining = filesize;
    int transfer_failed = 0;

    while (remaining > 0) {
        size_t amount = remaining > sizeof(buffer)
                      ? sizeof(buffer) : (size_t)remaining;

        if (read_exact(client_fd, reader, buffer, amount) == -1) {
            fprintf(stderr, "Upload interrupted: %s\n", filename);
            transfer_failed = 1;
            break;
        }

        if (fwrite(buffer, 1, amount, file) != amount) {
            fprintf(stderr, "Upload write failed: %s\n", filename);
            transfer_failed = 1;
            break;
        }

        remaining -= amount;
    }

    if (fclose(file) == EOF) {
        transfer_failed = 1;
    }

    if (transfer_failed) {
        unlink(temporary);
        send_response(client_fd, "ERR 013 FILE_WRITE_FAILED");
        return -1;
    }

    if (rename(temporary, path) == -1) {
        perror("rename");
        unlink(temporary);
        send_response(client_fd, "ERR 013 FILE_WRITE_FAILED");
        return -1;
    }

    printf("Upload stored: %s (%llu bytes)\n", path, filesize);
    fflush(stdout);

    char message[256];
    snprintf(message, sizeof(message),
             "OK FILE_RECEIVED %s", filename);

    return send_response(client_fd, message);
}

static int handle_get(int client_fd, const char *arguments)
{
    char filename[128];
    int consumed = 0;

    if (sscanf(arguments, "%127s %n",
               filename, &consumed) != 1 ||
        arguments[consumed] != '\0') {
        return send_response(client_fd, "ERR 014 INVALID_GET");
    }

    if (!valid_filename(filename)) {
        return send_response(client_fd, "ERR 012 INVALID_FILENAME");
    }

    char path[256];
    int length = snprintf(path, sizeof(path),
                          "%s/%s", STORAGE_PATH, filename);

    if (length < 0 || (size_t)length >= sizeof(path)) {
        return send_response(client_fd, "ERR 012 INVALID_FILENAME");
    }

    int file_fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);

    if (file_fd == -1) {
        if (errno == ENOENT) {
            return send_response(client_fd,
                                 "ERR 005 FILE_NOT_FOUND");
        }

        return send_response(client_fd, "ERR 015 FILE_READ_FAILED");
    }

    struct stat info;

    if (fstat(file_fd, &info) == -1 ||
        !S_ISREG(info.st_mode) || info.st_size < 0) {
        close(file_fd);
        return send_response(client_fd, "ERR 015 FILE_READ_FAILED");
    }

    unsigned long long filesize = (unsigned long long)info.st_size;

    if (filesize > FILE_LIMIT) {
        close(file_fd);
        return send_response(client_fd, "ERR 004 FILE_TOO_LARGE");
    }

    char message[256];
    snprintf(message, sizeof(message),
             "OK FILE_SEND %s %llu", filename, filesize);

    if (send_response(client_fd, message) == -1) {
        close(file_fd);
        return -1;
    }

    unsigned char buffer[FILE_CHUNK];
    unsigned long long remaining = filesize;

    while (remaining > 0) {
        size_t amount = remaining > sizeof(buffer)
                      ? sizeof(buffer) : (size_t)remaining;

        ssize_t received;

        do {
            received = read(file_fd, buffer, amount);
        } while (received == -1 && errno == EINTR);

        if (received <= 0) {
            /*
             * Header already sent: close instead of inserting an
             * error response inside the announced raw payload.
             */
            fprintf(stderr, "Download read failed: %s\n", filename);
            close(file_fd);
            return -1;
        }

        if (send_all(client_fd, buffer, (size_t)received) == -1) {
            perror("send file");
            close(file_fd);
            return -1;
        }

        remaining -= (unsigned long long)received;
    }

    close(file_fd);

    printf("Download sent: %s (%llu bytes)\n", path, filesize);
    fflush(stdout);
    return 0;
}

static void handle_connection(int client_fd)
{
    struct socket_reader reader = {0};
    char line[LINE_CAPACITY];
    int authenticated = 0;

    for (;;) {
        int result = read_line(client_fd, &reader,
                               line, sizeof(line));

        if (result != 1) {
            if (result == 0) {
                printf("Client disconnected\n");
            } else if (result == -1) {
                perror("recv");
            } else if (result == -2) {
                send_response(client_fd, "ERR 006 LINE_TOO_LONG");
            } else {
                send_response(client_fd, "ERR 006 INVALID_LINE");
            }

            fflush(stdout);
            break;
        }

        printf("Complete command line: [%s]\n", line);
        fflush(stdout);

        if (!authenticated) {
            if (strcmp(line, "AUTH " AUTH_TOKEN) == 0) {
                authenticated = 1;

                if (send_response(client_fd,
                                  "OK AUTHENTICATED") == -1) {
                    break;
                }
            } else {
                if (send_response(client_fd,
                                  "ERR 001 AUTH_FAILED") == -1) {
                    break;
                }

                /* A rejected PUT may have raw bytes following it. */
                if (strcmp(line, "PUT") == 0 ||
                    strncmp(line, "PUT ", 4) == 0) {
                    break;
                }
            }

            continue;
        }

        if (strcmp(line, "AUTH") == 0 ||
            strncmp(line, "AUTH ", 5) == 0) {
            if (strcmp(line, "AUTH " AUTH_TOKEN) == 0) {
                if (send_response(client_fd,
                                  "OK AUTHENTICATED") == -1) {
                    break;
                }
            } else {
                authenticated = 0;

                if (send_response(client_fd,
                                  "ERR 001 AUTH_FAILED") == -1) {
                    break;
                }
            }

            continue;
        }

        if (strcmp(line, "SYSINFO") == 0) {
            if (handle_sysinfo(client_fd) == -1) {
                break;
            }
            continue;
        }

        if (strcmp(line, "LISTPROC") == 0) {
            if (handle_listproc(client_fd) == -1) {
                break;
            }
            continue;
        }

        if (strcmp(line, "EXEC") == 0 ||
            strncmp(line, "EXEC ", 5) == 0) {
            const char *name =
                strcmp(line, "EXEC") == 0 ? "" : line + 5;

            if (handle_exec(client_fd, name) == -1) {
                break;
            }
            continue;
        }

        if (strcmp(line, "PUT") == 0 ||
            strncmp(line, "PUT ", 4) == 0) {
            const char *arguments =
                strcmp(line, "PUT") == 0 ? "" : line + 4;

            if (handle_put(client_fd, &reader, arguments) == -1) {
                break;
            }
            continue;
        }

        if (strcmp(line, "GET") == 0 ||
            strncmp(line, "GET ", 4) == 0) {
            const char *arguments =
                strcmp(line, "GET") == 0 ? "" : line + 4;

            if (handle_get(client_fd, arguments) == -1) {
                break;
            }
            continue;
        }

        if (strcmp(line, "QUIT") == 0) {
            send_response(client_fd, "OK BYE");
            break;
        }

        if (send_response(client_fd,
                          "ERR 003 UNKNOWN_COMMAND") == -1) {
            break;
        }
    }
}

int main(void)
{
    if (ensure_directory(STORAGE_ROOT) == -1 ||
        ensure_directory(STORAGE_PATH) == -1) {
        return EXIT_FAILURE;
    }

    int listen_fd;
    int reuse = 1;
    struct sockaddr_in server_addr = {0};

    listen_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (listen_fd == -1) {
        perror("socket");
        return EXIT_FAILURE;
    }

    if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR,
                   &reuse, sizeof(reuse)) == -1) {
        perror("setsockopt");
        close(listen_fd);
        return EXIT_FAILURE;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(AGENT_PORT);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(listen_fd, (struct sockaddr *)&server_addr,
             sizeof(server_addr)) == -1) {
        perror("bind");
        close(listen_fd);
        return EXIT_FAILURE;
    }

    if (listen(listen_fd, BACKLOG) == -1) {
        perror("listen");
        close(listen_fd);
        return EXIT_FAILURE;
    }

    printf("Agent listening on TCP port %d\n", AGENT_PORT);
    printf("File storage: %s\n", STORAGE_PATH);
    fflush(stdout);

    for (;;) {
        struct sockaddr_in client_addr = {0};
        socklen_t client_len = sizeof(client_addr);

        int client_fd = accept(listen_fd,
                               (struct sockaddr *)&client_addr,
                               &client_len);

        if (client_fd == -1) {
            if (errno == EINTR) {
                continue;
            }
            perror("accept");
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];

        if (inet_ntop(AF_INET, &client_addr.sin_addr,
                      client_ip, sizeof(client_ip)) != NULL) {
            printf("Connection accepted from %s:%u\n",
                   client_ip,
                   (unsigned int)ntohs(client_addr.sin_port));
        } else {
            perror("inet_ntop");
            printf("Connection accepted\n");
        }

        fflush(stdout);

        handle_connection(client_fd);
        close(client_fd);

        printf("Connection closed\n");
        fflush(stdout);
    }
}

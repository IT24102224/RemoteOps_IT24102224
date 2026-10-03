#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define AGENT_PORT 9410
#define BACKLOG 10
#define RECEIVE_CAPACITY 4096
#define LINE_CAPACITY 1024

struct socket_reader {
    unsigned char buffer[RECEIVE_CAPACITY];
    size_t next;
    size_t available;
};


static int read_line(int fd, struct socket_reader *reader,
                     char *line, size_t capacity)
{
    size_t used = 0;

    for (;;) {
        if (reader->next == reader->available) {
            ssize_t received;

            do {
                received = recv(fd, reader->buffer,
                                sizeof(reader->buffer), 0);
            } while (received == -1 && errno == EINTR);

            if (received == -1) {
                return -1;
            }

            if (received == 0) {
                return used == 0 ? 0 : -3;
            }

            reader->next = 0;
            reader->available = (size_t)received;
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

static void handle_connection(int client_fd)
{
    struct socket_reader reader = {0};
    char line[LINE_CAPACITY];

    for (;;) {
        int result = read_line(client_fd, &reader,
                               line, sizeof(line));

        if (result == 1) {
            printf("Complete command line: [%s]\n", line);
            fflush(stdout);
            continue;
        }

        if (result == 0) {
            printf("Client disconnected\n");
        } else if (result == -1) {
            perror("recv");
        } else if (result == -2) {
            printf("Connection closed: command line too long\n");
        } else {
            printf("Connection closed: incomplete or invalid text line\n");
        }

        fflush(stdout);
        break;
    }
}

int main(void)
{
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

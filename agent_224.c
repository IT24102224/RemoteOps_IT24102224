#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define AGENT_PORT 9410
#define BACKLOG 10

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
                   client_ip, (unsigned int)ntohs(client_addr.sin_port));
        } else {
            perror("inet_ntop");
            printf("Connection accepted\n");
        }

        close(client_fd);
        printf("Connection closed: command handling is not implemented yet\n");
        fflush(stdout);
    }
}

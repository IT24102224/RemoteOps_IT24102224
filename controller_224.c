#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define AGENT_PORT 9410

int main(int argc, char *argv[])
{
    int socket_fd;
    struct sockaddr_in agent_addr = {0};

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <agent-ip>\n", argv[0]);
        return EXIT_FAILURE;
    }

    agent_addr.sin_family = AF_INET;
    agent_addr.sin_port = htons(AGENT_PORT);

    if (inet_pton(AF_INET, argv[1], &agent_addr.sin_addr) != 1) {
        fprintf(stderr, "Invalid IPv4 address: %s\n", argv[1]);
        return EXIT_FAILURE;
    }

    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd == -1) {
        perror("socket");
        return EXIT_FAILURE;
    }

    if (connect(socket_fd, (struct sockaddr *)&agent_addr,
                sizeof(agent_addr)) == -1) {
        perror("connect");
        close(socket_fd);
        return EXIT_FAILURE;
    }

    printf("Connected to Agent at %s:%d\n", argv[1], AGENT_PORT);

    close(socket_fd);
    printf("Controller connection closed\n");

    return EXIT_SUCCESS;
}

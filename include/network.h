#ifndef NETWORK_H
#define NETWORK_H

//#include <cstddef>
//#include <cstdint>
#include "../include/protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <sys/time.h>
#include <netinet/tcp.h>

#define DEFAULT_TOR_PROXY_HOST "127.0.0.1"
#define DEFAULT_TOR_PROXY_PORT 9050
#define MAX_HOSTNAME_LEN 256
#define RECV_BUFFER_SIZE 8192
#define SEND_TIMEOUT_SEC 10
#define RECV_TIMEOUT_SEC 30

// structs

// == tor connection == //

typedef struct{
    int sockfd;
    char proxyHost[MAX_HOSTNAME_LEN];
    uint16_t proxyPort;
    char targetHost[MAX_HOSTNAME_LEN];
    uint16_t targetPort;
    uint8_t connected;
    uint8_t isOnion;
} TorConnection;

typedef struct{
    int sockfd;
    uint16_t port;
    struct sockaddr_in addr;
    uint8_t listening;
} ServerSocket;

typedef struct{
    uint64_t bytesSent;
    uint64_t bytesReceived;
    uint64_t messagesSent;
    uint64_t messagesReceived;
    uint64_t connectionErrors;
} NetworkStats;

// ======= //

TorConnection* networkConnectTor(
        const char *onionAddr,
        uint16_t port,
        const char *proxyHost,
        uint16_t proxyPort
);



// ============= //

void networkCloseTor(TorConnection *conn);

int netwokReconnectTor(TorConnection *conn);

ServerSocket* networkCreateServer(uint16_t port, int backlog);

int networkAcceptClient(ServerSocket *server, struct sockaddr_in *clientAddr);

void networkCloseServer(ServerSocket *server);

ssize_t networkSendAll(int sockfd, const uint8_t *data, size_t len);

ssize_t networkRecvExact(int sockfd, uint8_t *buffer, size_t len);

int networkSendMessage(int sockfd, const uint8_t *message, size_t msgLen);

int networkRecvMessage(int sockfd, uint8_t **messageCut, size_t *msgLenOut);

int networkSetRecvTimeout(int sockfd, int seconds);

int networkSetSendTimeout(int sockfd, int seconds);

int networkSetKeepalive(int sockfd, int idleSec, int interlavSec, int count);

int networkSetNodelay(int sockfd);


// diagnostic & utilities

int networkIsConnected(int sockfd);

int networkGetPeerAddress(int sockfd, char *ipOut, uint16_t *portOut);

int networkValidateOnionAddress(const char *addr);

void networkGetStats(NetworkStats *stats);

void networkResetStats(void);

void networkPrintConnectionInfo(const TorConnection *conn);


// gestor errors //

const char* networkGetLastError(void);

void networkClearError(void);

#endif

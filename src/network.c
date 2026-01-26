#include "../include/network.h"
#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>

static char lastError[256] = {0};
static NetworkStats globalStats = {0};

static void setError(const char *err){
    strncpy(lastError, err, 255);
}

TorConnection* networkConnectTor(const char *onionAddr, uint16_t port,
                                  const char *proxyHost, uint16_t proxyPort){
    TorConnection *conn = malloc(sizeof(TorConnection));
    if(!conn){
        setError("malloc failed");
        return NULL;
    }

    memset(conn, 0, sizeof(TorConnection));

    if(!proxyHost) proxyHost = DEFAULT_TOR_PROXY_HOST;
    if(!proxyPort) proxyPort = DEFAULT_TOR_PROXY_PORT;

    strncpy(conn->proxyHost, proxyHost, MAX_HOSTNAME_LEN - 1);
    strncpy(conn->targetHost, onionAddr, MAX_HOSTNAME_LEN - 1);
    conn->proxyPort = proxyPort;
    conn->targetPort = port;
    conn->isOnion = strstr(onionAddr, ".onion") != NULL;

    conn->sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(conn->sockfd < 0){
        setError("socket creation failed");
        free(conn);
        return NULL;
    }

    struct sockaddr_in proxyAddr;
    memset(&proxyAddr, 0, sizeof(proxyAddr));
    proxyAddr.sin_family = AF_INET;
    proxyAddr.sin_port = htons(proxyPort);
    inet_pton(AF_INET, proxyHost, &proxyAddr.sin_addr);

    if(connect(conn->sockfd, (struct sockaddr*)&proxyAddr, sizeof(proxyAddr)) < 0){
        setError("connect to proxy failed");
        close(conn->sockfd);
        free(conn);
        return NULL;
    }

    uint8_t greeting[3] = {0x05, 0x01, 0x00};
    if(send(conn->sockfd, greeting, 3, 0) != 3){
        setError("SOCKS5 greeting failed");
        close(conn->sockfd);
        free(conn);
        return NULL;
    }

    uint8_t response[2];
    if(recv(conn->sockfd, response, 2, 0) != 2 || response[0] != 0x05 || response[1] != 0x00){
        setError("SOCKS5 greeting response invalid");
        close(conn->sockfd);
        free(conn);
        return NULL;
    }

    size_t addrLen = strlen(onionAddr);
    uint8_t request[256];
    request[0] = 0x05;
    request[1] = 0x01;
    request[2] = 0x00;
    request[3] = 0x03;
    request[4] = (uint8_t)addrLen;
    memcpy(request + 5, onionAddr, addrLen);
    request[5 + addrLen] = (port >> 8) & 0xFF;
    request[6 + addrLen] = port & 0xFF;

    if(send(conn->sockfd, request, 7 + addrLen, 0) != (ssize_t)(7 + addrLen)){
        setError("SOCKS5 connect request failed");
        close(conn->sockfd);
        free(conn);
        return NULL;
    }

    uint8_t reply[10];
    if(recv(conn->sockfd, reply, 10, 0) < 10 || reply[1] != 0x00){
        setError("SOCKS5 connect failed");
        close(conn->sockfd);
        free(conn);
        return NULL;
    }

    conn->connected = 1;
    return conn;
}

void networkCloseTor(TorConnection *conn){
    if(!conn) return;
    if(conn->sockfd >= 0) close(conn->sockfd);
    free(conn);
}

int networkReconnectTor(TorConnection *conn){
    if(!conn) return -1;

    if(conn->sockfd >= 0) close(conn->sockfd);

    TorConnection *newConn = networkConnectTor(conn->targetHost, conn->targetPort,
                                                conn->proxyHost, conn->proxyPort);
    if(!newConn) return -1;

    conn->sockfd = newConn->sockfd;
    conn->connected = newConn->connected;
    free(newConn);

    return 0;
}

ServerSocket* networkCreateServer(uint16_t port, int backlog){
    ServerSocket *server = malloc(sizeof(ServerSocket));
    if(!server){
        setError("malloc failed");
        return NULL;
    }

    server->port = port;
    server->sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(server->sockfd < 0){
        setError("socket creation failed");
        free(server);
        return NULL;
    }

    int opt = 1;
    setsockopt(server->sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&server->addr, 0, sizeof(server->addr));
    server->addr.sin_family = AF_INET;
    server->addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    server->addr.sin_port = htons(port);

    if(bind(server->sockfd, (struct sockaddr*)&server->addr, sizeof(server->addr)) < 0){
        setError("bind failed");
        close(server->sockfd);
        free(server);
        return NULL;
    }

    if(listen(server->sockfd, backlog) < 0){
        setError("listen failed");
        close(server->sockfd);
        free(server);
        return NULL;
    }

    server->listening = 1;
    return server;
}

int networkAcceptClient(ServerSocket *server, struct sockaddr_in *clientAddr){
    if(!server) return -1;

    socklen_t addrLen = sizeof(*clientAddr);
    int clientFd = accept(server->sockfd, (struct sockaddr*)clientAddr, &addrLen);

    if(clientFd < 0){
        setError("accept failed");
        return -1;
    }

    return clientFd;
}

void networkCloseServer(ServerSocket *server){
    if(!server) return;
    if(server->sockfd >= 0) close(server->sockfd);
    free(server);
}

ssize_t networkSendAll(int sockfd, const uint8_t *data, size_t len){
    size_t sent = 0;
    while(sent < len){
        ssize_t n = send(sockfd, data + sent, len - sent, 0);
        if(n <= 0) return -1;
        sent += n;
    }
    globalStats.bytesSent += sent;
    return sent;
}

ssize_t networkRecvExact(int sockfd, uint8_t *buffer, size_t len){
    size_t received = 0;
    while(received < len){
        ssize_t n = recv(sockfd, buffer + received, len - received, 0);
        if(n <= 0) return -1;
        received += n;
    }
    globalStats.bytesReceived += received;
    return received;
}

int networkSendMessage(int sockfd, const uint8_t *message, size_t msgLen){
    uint32_t netLen = htonl(msgLen);
    if(networkSendAll(sockfd, (uint8_t*)&netLen, 4) < 0) return -1;
    if(networkSendAll(sockfd, message, msgLen) < 0) return -1;
    globalStats.messagesSent++;
    return 0;
}

int networkRecvMessage(int sockfd, uint8_t **messageOut, size_t *msgLenOut){
    uint32_t netLen;
    if(networkRecvExact(sockfd, (uint8_t*)&netLen, 4) < 0) return -1;

    *msgLenOut = ntohl(netLen);
    if(*msgLenOut > MAX_MESSAGE_SIZE){
        setError("message too large");
        return -1;
    }

    *messageOut = malloc(*msgLenOut);
    if(!*messageOut) return -1;

    if(networkRecvExact(sockfd, *messageOut, *msgLenOut) < 0){
        free(*messageOut);
        *messageOut = NULL;
        return -1;
    }

    globalStats.messagesReceived++;
    return 0;
}

int networkSetRecvTimeout(int sockfd, int seconds){
    struct timeval tv;
    tv.tv_sec = seconds;
    tv.tv_usec = 0;
    return setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

int networkSetSendTimeout(int sockfd, int seconds){
    struct timeval tv;
    tv.tv_sec = seconds;
    tv.tv_usec = 0;
    return setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

int networkSetKeepalive(int sockfd, int idleSec, int intervalSec, int count){
    int opt = 1;
    if(setsockopt(sockfd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt)) < 0) return -1;

    #ifdef __linux__
    setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPIDLE, &idleSec, sizeof(idleSec));
    setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPINTVL, &intervalSec, sizeof(intervalSec));
    setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPCNT, &count, sizeof(count));
    #endif

    return 0;
}

int networkSetNodelay(int sockfd){
    int opt = 1;
    return setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
}

int networkIsConnected(int sockfd){
    char buf;
    int result = recv(sockfd, &buf, 1, MSG_PEEK | MSG_DONTWAIT);
    if(result == 0) return 0;
    if(result < 0 && errno != EAGAIN && errno != EWOULDBLOCK) return 0;
    return 1;
}

int networkGetPeerAddress(int sockfd, char *ipOut, uint16_t *portOut){
    struct sockaddr_in addr;
    socklen_t addrLen = sizeof(addr);

    if(getpeername(sockfd, (struct sockaddr*)&addr, &addrLen) < 0) return -1;

    inet_ntop(AF_INET, &addr.sin_addr, ipOut, INET_ADDRSTRLEN);
    *portOut = ntohs(addr.sin_port);

    return 0;
}

int networkValidateOnionAddress(const char *addr){
    if(!addr) return 0;

    size_t len = strlen(addr);
    if(len < 22) return 0;

    if(strcmp(addr + len - 6, ".onion") != 0) return 0;

    size_t baseLen = len - 6;
    if(baseLen != 16 && baseLen != 56) return 0;

    for(size_t i = 0; i < baseLen; i++){
        char c = tolower(addr[i]);
        if(!((c >= 'a' && c <= 'z') || (c >= '2' && c <= '7'))){
            return 0;
        }
    }

    return 1;
}

void networkGetStats(NetworkStats *stats){
    if(stats) memcpy(stats, &globalStats, sizeof(NetworkStats));
}

void networkResetStats(void){
    memset(&globalStats, 0, sizeof(NetworkStats));
}

void networkPrintConnectionInfo(const TorConnection *conn){
    if(!conn) return;
    printf("[CONN] Target: %s:%u via %s:%u\n",
           conn->targetHost, conn->targetPort,
           conn->proxyHost, conn->proxyPort);
    printf("[CONN] Status: %s, Type: %s\n",
           conn->connected ? "Connected" : "Disconnected",
           conn->isOnion ? "Onion" : "Direct");
}

const char* networkGetLastError(void){
    return lastError;
}

void networkClearError(void){
    memset(lastError, 0, sizeof(lastError));
}

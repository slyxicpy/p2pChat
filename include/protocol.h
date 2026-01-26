#ifndef PROTOCOL_H
#define PROTOCOL_H

//#include <cstddef>
//#include <cstdint>
#include <stdint.h>
#include <stddef.h>
#include <time.h>

// == Types msg == //
/*
 * - 0x00-0x0F: Auth y control
 * - 0x10-0x1F: Mensajes de chat
 * - 0x20-0x2F: Gestion de usuarios
 * - 0x30-0x3F: Transferencia de files */

typedef enum{
    /* === AUTH === */
    MSG_AUTH_REQUEST    = 0x01,  /* Cliente -> Servidor: solicita auth */
    MSG_AUTH_RESPONSE   = 0x02,  /* Servidor -> Cliente: resultado auth */
    MSG_AUTH_CHALLENGE  = 0x03,  /* Servidor -> Cliente: challenge crypto */

    /* === CHAT === */
    MSG_CHAT_TEXT       = 0x10,  /* Mensaje de texto */
    MSG_CHAT_TYPING     = 0x11,  /* Usuario esta escribiendo */
    MSG_CHAT_ACK        = 0x12,  /* Confirmacion de recepción */

    /* === G USUARIOS === */
    MSG_USER_JOIN       = 0x20,  /* Usuario se unio */
    MSG_USER_LEAVE      = 0x21,  /* Usuario se fue */
    MSG_USER_LIST       = 0x22,  /* Lista de usuarios conectados */
    MSG_USER_STATUS     = 0x23,  /* Cambio de estado (disponible/ausente) */

    /* === CONTROL === */
    MSG_PING            = 0x30,  /* Keep-alive */
    MSG_PONG            = 0x31,  /* Respuesta a ping */
    MSG_ERROR           = 0x3F,  /* Mensaje de error */

    /* === Archivos === */
    MSG_FILE_OFFER      = 0x40,  /* Ofrecer archivo */
    MSG_FILE_ACCEPT     = 0x41,  /* Aceptar archivo */
    MSG_FILE_CHUNK      = 0x42,  /* Chunk de archivo */
    MSG_FILE_COMPLETE   = 0x43,  /* Transferencia completa */

    /* == p2p == */
    MSG_PEER_LIST       = 0x50,
    MSG_PEER_REQUEST    = 0x51,
    MSG_GOSSIP          = 0x52,
    MSG_HEARTBEAT       = 0x53,
    MSG_PEER_ANNOUNCE   = 0x54,

} MessageType;


// == auth request == //

typedef struct{
    char username[32];
    uint8_t pwdHash[32];
    uint32_t protocolVersion;
} AuthRequest;

// == auth response == //

typedef struct{
    uint8_t success;
    char message[128];
    uint32_t sessionId;
} AuthResponse;

// == chat message == //

typedef struct{
    char sender[32];
    char message[1024];
    uint64_t timestamp;
    uint8_t encrypted;
} ChatMessage;

// == user info == //

typedef struct{
    char username[32];
    uint8_t status;
    uint64_t joinedTime;
} UserInfo;

// == User List Payload == //

typedef struct{
    uint32_t count;
    UserInfo *users;
} UserListPayload;

// == err payload == //

typedef struct{
    uint16_t errorCode;
    char description[256];
} ErrorPayload;

// == message == //

typedef struct{
    uint32_t length;
    MessageType type;
    void *payload;
    uint8_t encrypted;
} Message;

// =================== //

int protocolSerializer(const Message *msg, uint8_t **bufferOut, size_t *bufferLen);

int protocolDeserealizer(const uint8_t *buffer, size_t bufferLen, Message *msgOut);


// construct message

Message* protocolCreateAuthRequest(const char *username, const uint8_t *pwdHash);
Message* protocolCreateChatMessage(const char *sender, const char *text);
Message* protocolCreateUserList(UserInfo *user, uint32_t count);
Message* protocolCreateError(uint16_t code, const char *description);
Message* protocolCreatePing(void);

// == Gestor memory == //
void protocolFreeMessage(Message *msg);

// == utilities == //
const char* protocolMessageTypeName(MessageType type);

int protocolValidateMessage(const Message *msg);

void protocolPrintMessage(const Message *msg);


// errs code
#define ERR_INVALID_AUTH        1001  /* Autenticación invalid */
#define ERR_USERNAME_TAKEN      1002  /* Username ya en uso */
#define ERR_SERVER_FULL         1003  /* Servidor lleno */
#define ERR_PROTOCOL_VERSION    1004  /* Version incompatible */
#define ERR_INVALID_MESSAGE     2001  /* Mensaje mal formado */
#define ERR_PERMISSION_DENIED   2002  /* Sin permisos */
#define ERR_RATE_LIMIT          2003  /* Demasiados mensajes */
#define ERR_INTERNAL_SERVER     5000  /* Error interno */

// config protocol
#define PROTOCOL_VERSION        1      /* Version */
#define MAX_MESSAGE_SIZE        65536  /* 64KB max por mensaje */
#define MAX_USERNAME_LEN        32     /* Longitud max de username */
#define MAX_CHAT_MSG_LEN        1024   /* Longitud max de mensaje */
#define PING_INTERVAL           30     /* Segundos entre pings */
#define TIMEOUT_SECONDS         90     /* Timeout de conexion */





#endif

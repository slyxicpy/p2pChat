#include "../include/protocol.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>

int protocolSerialize(const Message *msg, uint8_t **bufferOut, size_t *bufferLen){
    if(!msg || !bufferOut || !bufferLen) return -1;

    size_t payloadSize = 0;

    switch(msg->type){
        case MSG_AUTH_REQUEST:
            payloadSize = sizeof(AuthRequest);
            break;
        case MSG_AUTH_RESPONSE:
            payloadSize = sizeof(AuthResponse);
            break;
        case MSG_CHAT_TEXT:
            payloadSize = sizeof(ChatMessage);
            break;
        case MSG_USER_JOIN:
        case MSG_USER_LEAVE:
            payloadSize = 32;
            break;
        case MSG_USER_LIST:
            payloadSize = sizeof(uint32_t) + ((UserListPayload*)msg->payload)->count * sizeof(UserInfo);
            break;
        case MSG_ERROR:
            payloadSize = sizeof(ErrorPayload);
            break;
        case MSG_PING:
        case MSG_PONG:
            payloadSize = 0;
            break;
        default:
            return -1;
    }

    *bufferLen = 4 + 1 + payloadSize;
    *bufferOut = malloc(*bufferLen);
    if(!*bufferOut) return -1;

    uint32_t netLen = htonl(*bufferLen);
    memcpy(*bufferOut, &netLen, 4);
    (*bufferOut)[4] = (uint8_t)msg->type;

    if(payloadSize > 0){
        memcpy(*bufferOut + 5, msg->payload, payloadSize);
    }

    return 0;
}

int protocolDeserialize(const uint8_t *buffer, size_t bufferLen, Message *msgOut){
    if(!buffer || bufferLen < 5 || !msgOut) return -1;

    uint32_t netLen;
    memcpy(&netLen, buffer, 4);
    msgOut->length = ntohl(netLen);

    if(msgOut->length != bufferLen) return -1;

    msgOut->type = (MessageType)buffer[4];

    size_t payloadSize = bufferLen - 5;

    if(payloadSize > 0){
        msgOut->payload = malloc(payloadSize);
        if(!msgOut->payload) return -1;
        memcpy(msgOut->payload, buffer + 5, payloadSize);
    } else {
        msgOut->payload = NULL;
    }

    msgOut->encrypted = 0;
    return 0;
}

Message* protocolCreateAuthRequest(const char *username, const uint8_t *pwdHash){
    Message *msg = malloc(sizeof(Message));
    if(!msg) return NULL;

    AuthRequest *auth = malloc(sizeof(AuthRequest));
    if(!auth){
        free(msg);
        return NULL;
    }

    memset(auth->username, 0, 32);
    strncpy(auth->username, username, 31);
    auth->username[31] = '\0';
    memcpy(auth->pwdHash, pwdHash, 32);
    auth->protocolVersion = PROTOCOL_VERSION;

    msg->type = MSG_AUTH_REQUEST;
    msg->payload = auth;
    msg->encrypted = 0;

    return msg;
}

Message* protocolCreateChatMessage(const char *sender, const char *text){
    Message *msg = malloc(sizeof(Message));
    if(!msg) return NULL;

    ChatMessage *chat = malloc(sizeof(ChatMessage));
    if(!chat){
        free(msg);
        return NULL;
    }

    memset(chat->sender, 0, 32);
    memset(chat->message, 0, 1024);
    strncpy(chat->sender, sender, 31);
    chat->sender[31] = '\0';
    strncpy(chat->message, text, 1023);
    chat->message[1023] = '\0';
    chat->timestamp = time(NULL);
    chat->encrypted = 0;

    msg->type = MSG_CHAT_TEXT;
    msg->payload = chat;
    msg->encrypted = 0;

    return msg;
}

Message* protocolCreateUserList(UserInfo *users, uint32_t count){
    Message *msg = malloc(sizeof(Message));
    if(!msg) return NULL;

    UserListPayload *list = malloc(sizeof(UserListPayload));
    if(!list){
        free(msg);
        return NULL;
    }

    list->count = count;
    list->users = malloc(count * sizeof(UserInfo));
    if(!list->users){
        free(list);
        free(msg);
        return NULL;
    }

    memcpy(list->users, users, count * sizeof(UserInfo));

    msg->type = MSG_USER_LIST;
    msg->payload = list;
    msg->encrypted = 0;

    return msg;
}

Message* protocolCreateError(uint16_t code, const char *description){
    Message *msg = malloc(sizeof(Message));
    if(!msg) return NULL;

    ErrorPayload *err = malloc(sizeof(ErrorPayload));
    if(!err){
        free(msg);
        return NULL;
    }

    err->errorCode = code;
    memset(err->description, 0, 256);
    strncpy(err->description, description, 255);

    msg->type = MSG_ERROR;
    msg->payload = err;
    msg->encrypted = 0;

    return msg;
}

Message* protocolCreatePing(void){
    Message *msg = malloc(sizeof(Message));
    if(!msg) return NULL;

    msg->type = MSG_PING;
    msg->payload = NULL;
    msg->encrypted = 0;

    return msg;
}

void protocolFreeMessage(Message *msg){
    if(!msg) return;

    if(msg->payload){
        if(msg->type == MSG_USER_LIST){
            UserListPayload *list = (UserListPayload*)msg->payload;
            if(list->users) free(list->users);
        }
        free(msg->payload);
    }
    free(msg);
}

const char* protocolMessageTypeName(MessageType type){
    switch(type){
        case MSG_AUTH_REQUEST: return "AUTH_REQUEST";
        case MSG_AUTH_RESPONSE: return "AUTH_RESPONSE";
        case MSG_CHAT_TEXT: return "CHAT_TEXT";
        case MSG_USER_JOIN: return "USER_JOIN";
        case MSG_USER_LEAVE: return "USER_LEAVE";
        case MSG_USER_LIST: return "USER_LIST";
        case MSG_PING: return "PING";
        case MSG_PONG: return "PONG";
        case MSG_ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

int protocolValidateMessage(const Message *msg){
    if(!msg) return 0;
    if(msg->length > MAX_MESSAGE_SIZE) return 0;
    return 1;
}

void protocolPrintMessage(const Message *msg){
    if(!msg) return;
    printf("[MSG] Type: %s, Length: %u\n",
           protocolMessageTypeName(msg->type), msg->length);
}

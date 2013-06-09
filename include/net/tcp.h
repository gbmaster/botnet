#ifndef TCP_H_INCLUDED
#define TCP_H_INCLUDED

#ifdef __linux__

#include <netinet/tcp.h>

#elif defined _WIN32

#include <windows.h>

#else
#error OS not supported
#endif

#include "net/ip.h"

SOCKET tcp_connect(char *address, uint16_t port);
SOCKET tcp_listen(uint16_t port);
SOCKET tcp_accept(SOCKET s, uint32_t *ip_address, uint16_t *port);
int tcp_send(SOCKET s, const unsigned char* data, unsigned int length);
int tcp_recv(SOCKET s, unsigned char** buffer, unsigned int* length, time_t seconds_timeout = 0);

#endif // TCP_H_INCLUDED

#ifndef UDP_H_INCLUDED
#define UDP_H_INCLUDED

#ifdef __linux__

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>

#elif defined _WIN32

#include <windows.h>

#else
#error OS not supported
#endif

#include "net/ip.h"

SOCKET udp_socket(const uint16_t binding_port = 0);
int udp_recv(SOCKET s, unsigned char* &buffer, unsigned int &length, struct sockaddr_in &saddr);
int udp_send(SOCKET s, char *address, const uint16_t port, const unsigned char* data, const unsigned int length);

#endif // UDP_H_INCLUDED

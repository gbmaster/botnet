#ifndef IP_H_INCLUDED
#define IP_H_INCLUDED

#ifdef __linux__

#include <arpa/inet.h>
#include <netdb.h>

#endif

#include "lib/libs.h"

unsigned long resolve_hostname(char *hostname);

#ifdef __linux__

int closesocket(SOCKET s);

#endif

bool net_initialize();

#endif

#ifdef __linux__

#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <linux/if.h>

#endif

#include <string.h>
#include "net/ip.h"
#include "log/log.h"

unsigned long resolve_hostname(char *hostname)
{
    struct hostent *he = gethostbyname(hostname);
    if(he == NULL)
        return 0;

    return *(unsigned long *)(he->h_addr_list[0]);
}

#ifdef __linux__

int closesocket(SOCKET s)
{
    return close(s);
}

#endif

bool net_initialize()
{
#ifdef WIN32
    WORD wVersion;
    WSADATA wsaData;

    wVersion = MAKEWORD(2, 2);

    if(WSAStartup(wVersion, &wsaData))
        return false;

    if(LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2)
    {
        WSACleanup();
        return false;
    }
#endif

    return true;
}

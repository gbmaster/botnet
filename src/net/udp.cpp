#ifdef __linux__

#include <arpa/inet.h>
#include <fcntl.h>

#endif

#include <string.h>
#include "net/udp.h"
#include "lib/libs.h"
#include "log/log.h"

SOCKET udp_socket(const uint16_t binding_port)
{
    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if(s == INVALID_SOCKET)
        WriteErrLog("Error creating the socket...");

    if(binding_port != 0)
    {
        struct sockaddr_in saddr;
        memset(&saddr, 0, sizeof(struct sockaddr_in));
        saddr.sin_family = AF_INET;
        saddr.sin_port = htons(binding_port);
        saddr.sin_addr.s_addr = INADDR_ANY;

        int flag = 1;
        if(setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *)&flag, sizeof(flag)))
        {
            WriteErrLog("Error setting SO_REUSEADDR for the socket: " << strerror(errno));
            closesocket(s);
            return INVALID_SOCKET;
        }

        if(bind(s, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in)) == SOCKET_ERROR)
        {
            WriteErrLog("Error binding the bind socket: " << strerror(errno));
            closesocket(s);
            return INVALID_SOCKET;
        }
    }

    unsigned long flag = 1;
#ifdef __linux__
    if(fcntl(s, F_SETFL, O_NONBLOCK, flag) == -1)
#elif defined _WIN32
    if(ioctlsocket(s, FIONBIO, &flag) != 0)
#else
#error OS not supported
#endif
    {
        WriteLog("Error setting the socket as non-blocking: " << strerror(errno));
        closesocket(s);
        return INVALID_SOCKET;
    }

    return s;
}

int udp_recv(SOCKET s, unsigned char* &buffer, unsigned int &length, struct sockaddr_in &saddr)
{
    buffer = new unsigned char[2048];
    unsigned int buffer_size = 2048;

    memset(&saddr, 0, sizeof(struct sockaddr_in));
#ifdef __linux
    unsigned int sockaddrin_size = sizeof(saddr);
#elif defined _WIN32
    int sockaddrin_size = sizeof(saddr);
#else
#error OS not supported
#endif

    int ret = recvfrom(s, (char *)buffer, buffer_size, 0, (struct sockaddr *)&saddr, &sockaddrin_size);
    if(ret > 0)
    {
        length = ret;
    }
    else
    {
        delete [] buffer;
        buffer = NULL;
        length = 0;

        return SOCKET_ERROR;
    }

    return 0;
}

int udp_send(SOCKET s, char *address, const uint16_t port, const unsigned char* data, const unsigned int length)
{
    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(struct sockaddr_in));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(port);

    saddr.sin_addr.s_addr = inet_addr(address);
    if(saddr.sin_addr.s_addr == INADDR_NONE)
        saddr.sin_addr.s_addr = resolve_hostname(address);

    if(sendto(s, (const char *)data, length, 0, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in)) == SOCKET_ERROR)
        return SOCKET_ERROR;
    else
        return 0;
}

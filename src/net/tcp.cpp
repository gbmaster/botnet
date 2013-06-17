#ifdef __linux__

#include <arpa/inet.h>
#include <fcntl.h>

#endif

#include <string.h>
#include "net/tcp.h"
#include "lib/libs.h"
#include "log/log.h"

SOCKET tcp_socket()
{
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);

    char flag = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag));

    // Like a SO_DONTLINGER
    struct linger ling;
	ling.l_onoff = 0;
	ling.l_linger = 0;
    setsockopt(s, SOL_SOCKET, SO_LINGER, (char *)&ling, sizeof(ling));

    return s;
}

SOCKET tcp_connect(char *address, uint16_t port)
{
    SOCKET s = tcp_socket();

    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(struct sockaddr_in));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(port);

    saddr.sin_addr.s_addr = inet_addr(address);
    if(saddr.sin_addr.s_addr == INADDR_NONE)
        saddr.sin_addr.s_addr = resolve_hostname(address);

    connect(s, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in));

    return s;
}

SOCKET tcp_listen(uint16_t port)
{
    SOCKET s = tcp_socket();

    struct sockaddr_in saddr;
    memset(&saddr, 0, sizeof(struct sockaddr_in));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(port);
    saddr.sin_addr.s_addr = htonl(INADDR_ANY);

    if(bind(s, (struct sockaddr *)&saddr, sizeof(struct sockaddr_in)) == SOCKET_ERROR)
    {
        closesocket(s);
        return INVALID_SOCKET;
    }

    if(listen(s, SOMAXCONN))
    {
        closesocket(s);
        return INVALID_SOCKET;
    }

    return s;
}

int tcp_send(SOCKET s, const unsigned char* data, unsigned int length)
{
    timeval tm;
    fd_set fd;
    int ret;
    FD_ZERO(&fd);
    FD_SET(s, &fd);
    tm.tv_sec = 5;
    tm.tv_usec = 0;

    if((ret = select(s + 1, NULL, &fd, NULL, &tm)) > 0)
    {
        int data_to_send = length;
        char *pdata = (char *)data;

        do
        {
            ret = send(s, pdata, data_to_send, 0);
#ifdef __linux__
            if(ret < 0)
#elif defined _WIN32
            if(ret == SOCKET_ERROR)
#else
#error OS not supported
#endif
                return SOCKET_ERROR;
            pdata += ret;
            data_to_send -= ret;
        } while(data_to_send > 0);
    }

    return 0;
}

int tcp_recv(SOCKET s, unsigned char** buffer, unsigned int* length, time_t seconds_timeout)
{
    timeval tm;
    fd_set fd;
    int ret = 1;
    FD_ZERO(&fd);
    FD_SET(s, &fd);
    tm.tv_sec = seconds_timeout;
    tm.tv_usec = 0;

    *length = 0;

    if((ret = select(s + 1, &fd, NULL, NULL, &tm)) > 0)
    {
        *buffer = new unsigned char[2048];
        unsigned int buffer_size = 2048;

        unsigned char tmp_buf[2048];
        do
        {
            ret = recv(s, (char *)tmp_buf, sizeof(tmp_buf), 0);
#ifdef __linux__
            if(ret < 0)
#elif defined _WIN32
            if(ret == SOCKET_ERROR)
#else
#error OS not supported
#endif
            {
                if(*length != 0)
                {
                    break;
                }
                else
                {
                    delete [] *buffer;
                    return -1;
                }
            }

            if(ret == 0 && *length == 0)
            {
                delete [] *buffer;
                return 0;
            }

            if(*length + ret >= buffer_size)
            {
                // RESIZE PLEASE
                // Really painful
                unsigned char *new_buffer = new unsigned char[buffer_size + 2048];
                memcpy(new_buffer, *buffer, buffer_size);
                buffer_size += 2048;

                delete [] *buffer;
                *buffer = new_buffer;
            }

            memcpy(*buffer + *length, tmp_buf, ret);
            *length += ret;
        } while(ret > 0);

        return 1;
    }
    else if(ret == 0)
    {
        return 0;
    }
    else
    {
        return -1;
    }
}

SOCKET tcp_accept(SOCKET s, uint32_t *ip_address, uint16_t *port)
{
    fd_set readset;
    struct timeval tm;

    FD_ZERO(&readset);
    FD_SET(s, &readset);
    tm.tv_sec = tm.tv_usec = 0;

    if(select(s + 1, &readset, NULL, NULL, &tm) <=0)
        return INVALID_SOCKET;

    struct sockaddr_in saddr;
    socklen_t len = sizeof(saddr);

    SOCKET accept_s = accept(s, (struct sockaddr *)&saddr, &len);
    if(accept_s == INVALID_SOCKET)
        return INVALID_SOCKET;

    char flag = 1;
    setsockopt(accept_s, IPPROTO_TCP, TCP_NODELAY, (char *)&flag, sizeof(flag));

    // Like a SO_DONTLINGER
    struct linger ling;
	ling.l_onoff = 0;
	ling.l_linger = 0;
    setsockopt(accept_s, SOL_SOCKET, SO_LINGER, (char *)&ling, sizeof(ling));

#ifdef __linux__
    if(fcntl(accept_s, F_SETFL, O_NONBLOCK, flag) == -1)
#elif defined _WIN32
    if(ioctlsocket(accept_s, FIONBIO, (u_long *)&flag) != 0)
#else
#error OS not supported
#endif
    {
        WriteLog("Error setting the socket as non-blocking: " << strerror(errno));
        closesocket(s);
        return INVALID_SOCKET;
    }

    *ip_address = *(uint32_t *)&(saddr.sin_addr);
    *port = ntohs(saddr.sin_port);

    return accept_s;
}

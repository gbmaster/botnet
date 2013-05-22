#include <sstream>
#include <vector>
#include <string.h>
#include "net/http.h"
#include "net/tcp.h"
#include "net/ip.h"
#include "lib/libs.h"
#include "kad/nodes_dat.h"
#include "log/log.h"

struct NODES_DAT_URL
{
    char host[1024];    // 1024 *should* be enough
    unsigned short int port;
    char path[1024];
} nodes_hosts[] =
{
    {
        "server-met.emulefuture.de", 80, "download.php?file=nodes.dat"
    }
/*
    ,
    {
        "www.alldivx.de", 80, "nodes/nodes.dat"
    }
*/
};

std::vector<std::string> http_split(const unsigned char *str, const unsigned int &str_length, unsigned char *&payload, unsigned int &payload_length)
{
    const unsigned char *s = str, *next_hit = str;
    std::vector<std::string> items;

    payload = NULL;
    payload_length = 0;

    for(unsigned int i = 0; i < str_length - 1; i++, s++)
    {
        if(str[i] == '\r' && str[i + 1] == '\n')
        {
            // Is this an empty item?
            if(next_hit == s)
            {
                next_hit = s + 2;
                break;
            }
            else
            {
                items.push_back(std::string((const char *)next_hit, s - next_hit));
                next_hit = s + 2;
            }
        }
    }

    // Payload?
    if(next_hit < str + str_length)
    {
        payload = new unsigned char[str + str_length - next_hit];
        memcpy(payload, next_hit, str + str_length - next_hit);
        payload_length = str + str_length - next_hit;
    }

    return items;
}

void download_nodes_list(std::list<Contact *>& peer_list, std::list<Contact *>& bootstrap_list)
{
    // Loop on all the nodes.dat sources hardcoded in the vector
    for(unsigned char i = 0; i < (sizeof(nodes_hosts) / sizeof(nodes_hosts[0])); i++)
    {
        WriteLog("Downloading nodes file from " << nodes_hosts[i].host << ":" << nodes_hosts[i].port << "/" << nodes_hosts[i].path);

        SOCKET s = tcp_connect(nodes_hosts[i].host, nodes_hosts[i].port);
        if(s == INVALID_SOCKET)
        {
            WriteLog("Unable to connect to " << nodes_hosts[i].host << ":" << nodes_hosts[i].port << "... Skipped");
            continue;
        }

        std::stringstream get_request;
        get_request << "GET /" << nodes_hosts[i].path << " HTTP/1.1\r\n";
        get_request << "Host: " << nodes_hosts[i].host << "\r\n";
        get_request << "User-Agent: FakeAgent\r\n\r\n";

        tcp_send(s, (unsigned char *)(get_request.str().c_str()), get_request.str().length());

        unsigned char *response;
        unsigned int response_size;
        tcp_recv(s, &response, &response_size, 5);

        // The connection is not needed anymore
        closesocket(s);

        // OK, we have an HTTP response: it's parsing time!
        std::vector<std::string> http_elements;
        unsigned char *payload;
        unsigned int payload_length;
        http_elements = http_split(response, response_size, payload, payload_length);
        // response has been allocated into tcp_recv: not needed anymore, as it's been splitted
        delete [] response;

        if((http_elements.size() == 0) ||
           (http_elements.size() > 0 && strncmp(http_elements[0].c_str(), "HTTP/1.1 200 OK", strlen("HTTP/1.1 200 OK"))))
           // Woops: something went bad
           continue;

        extract_peers_from_nodes_dat(payload, peer_list, bootstrap_list);

        delete [] payload;
    }

    return;
}

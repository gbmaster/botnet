#ifndef TCPSERVER_H_INCLUDED
#define TCPSERVER_H_INCLUDED

#include <vector>
#include "lib/libs.h"

#define OP_EMULEPROT             0xC5
#define OP_EDONKEYHEADER         0xE3

#define OP_HELLO                 0x01
#define OP_HELLOANSWER           0x4C
#define OP_KAD_FWTCPCHECK_ACK    0xA8

#define MAX_TCP_CONNECTIONS      500

class TCPServer
{
    public:
        static TCPServer& get_instance()
        {
            static TCPServer instance;
            return instance;
        }

        const unsigned char * get_user_hash() const { return _user_hash; };
        std::string& get_user_name() { return _username; }
        uint32_t get_version() const { return _version; }
        uint16_t get_tcp_port() const { return _tcp_port; }


        bool send_tcp_packet(SOCKET s, const unsigned char protocol, const unsigned char opcode, const unsigned char *payload, const uint32_t length);
        void close_connection(SOCKET s)
        {
            closesocket(s);
            _num_connections--;
        }

        void retrieve_and_dispatch_potential_packet();

    private:
        TCPServer();
        TCPServer(const TCPServer &);
        TCPServer& operator = (const TCPServer&);

        void process_emuleprot_packet(uint32_t ip_address, const unsigned char *buffer, uint32_t buffer_size);
        void process_kad_fwtcpcheck_ack(uint32_t ip_address);

        uint16_t _tcp_port;

        std::vector<std::pair<uint32_t, SOCKET> > _pending_connections;
        SOCKET _sock;
        unsigned int _num_connections;

        unsigned char _user_hash[16];
        std::string _username;
        uint32_t _version;
};

#endif

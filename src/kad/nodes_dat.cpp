#include <string.h>
#include "kad/nodes_dat.h"
#include "lib/libs.h"
#include "log/log.h"
#include "net/ip.h"

void extract_peers_from_bootstrap_nodes_dat(const unsigned char *buffer, std::list<Contact *>& bootstrap_list)
{
    /*
        The header is so composed:
          uint32_t reserved0          set to zero
          uint32_t reserved1          set to 0x00000003
          uint32_t bootstrap_edition  nodes.dat bootstrap version
          uint32_t num_entries        number of entries in the file
    */

    if(!bootstrap_list.empty())
        return;

    uint32_t reserved0 = *(uint32_t *)&(buffer[0]);
    uint32_t reserved1 = *(uint32_t *)&(buffer[4]);
    uint32_t num_entries = *(uint32_t *)&(buffer[12]);

    if(reserved0 != 0 || reserved1 != 3)
        // wow: this bootstrap nodes.dat is invalid
        return;

    unsigned char *peer = (unsigned char *)&(buffer[16]);

    /*
        The peer is so composed:
          uint64_t low_peer_id        128-bit peer identifier (MD4 of node ID)
          uint64_t high_peer_id
          uint32_t peer_ip            IP address of the peer
          uint16_t udp_port           peer UDP port number
          uint16_t tcp_port           peer TCP port number
          unsigned char version       peer contact version
    */

    for(unsigned int i = 0; i < num_entries; i++, peer += 25)
    {
        uint32_t peer_ip = ntohl(*(uint32_t *)&(peer[16]));
        uint16_t udp_port = *(uint16_t *)&(peer[20]);
        uint16_t tcp_port = *(uint16_t *)&(peer[22]);
        unsigned char version = peer[24];

        if(version > 7)
        {
            // Only the 50 closest nodes, please
            uint128_t distance(Kad::get_instance().get_client_id());
            uint128_t peer_id = uint128_t::get_from_buffer(peer);
            distance ^= peer_id;

            if(bootstrap_list.size() < 50 || bootstrap_list.back()->get_distance() > distance)
            {
                Contact *new_peer = new Contact(uint128_t::get_from_buffer(peer),
                                                peer_ip,
                                                udp_port,
                                                tcp_port,
                                                version,
                                                0,
                                                false);

                bool peer_added = false;
                for(std::list<Contact *>::iterator peerIt = bootstrap_list.begin();
                    peerIt != bootstrap_list.end();
                    peerIt++)
                {
                    if((*peerIt)->get_distance() > distance)
                    {
                        bootstrap_list.insert(peerIt, new_peer);
                        peer_added = true;
                        break;
                    }
                }

                if(!peer_added)
                {
                    bootstrap_list.push_back(new_peer);
                }
                else if(bootstrap_list.size() > 50)
                {
                    delete bootstrap_list.back();
                    bootstrap_list.pop_back();
                }
            }
        }
    }
}

void extract_peers_from_nodes_dat(const unsigned char *buffer, std::list<Contact *>& peer_list, std::list<Contact *>& bootstrap_list)
{
    /*
        The header is so composed:
          uint32_t reserved0          set to zero
          uint32_t reserved1          set to 0x00000002
          uint32_t num_entries        number of entries in the file
    */

    uint32_t reserved0 = *(uint32_t *)&(buffer[0]);
    uint32_t reserved1 = *(uint32_t *)&(buffer[4]);
    uint32_t num_entries = *(uint32_t *)&(buffer[8]);

    if(reserved0 != 0 || reserved1 < 2)
        // wow: this nodes.dat is invalid
        return;

    if(reserved1 == 3)
    {
        uint32_t bootstrap_edition = *(uint32_t *)&(buffer[8]);
        if(bootstrap_edition == 1)
        {
            extract_peers_from_bootstrap_nodes_dat(buffer, bootstrap_list);
            return;
        }
    }

    unsigned char *peer = (unsigned char *)&(buffer[12]);

    /*
        The peer is so composed:
          uint64_t low_peer_id        128-bit peer identifier (MD4 of node ID)
          uint64_t high_peer_id
          uint32_t peer_ip            IP address of the peer
          uint16_t udp_port           peer UDP port number
          uint16_t tcp_port           peer TCP port number
          uint8_t version             peer contact version
          uint32_t kad_key            peer Kad UDP key
          uint32_t kad_ip
          unsigned char verified
    */

    for(unsigned int i = 0; i < num_entries; i++, peer += 34)
    {
        uint32_t peer_ip = ntohl(*(uint32_t *)&(peer[16]));
        uint16_t udp_port = *(uint16_t *)&(peer[20]);
        uint16_t tcp_port = *(uint16_t *)&(peer[22]);
        unsigned char version = peer[24];
        uint32_t kad_key = *(uint32_t *)&(peer[25]);
        uint32_t kad_ip = ntohl(*(uint32_t *)&(peer[29]));
        bool verified = peer[33] != 0;

        if(version < 7)
            continue;

        KadUDPKey udp_key(kad_key, kad_ip);

        Contact *new_peer = new Contact(uint128_t::get_from_buffer(peer),
                                        peer_ip,
                                        udp_port,
                                        tcp_port,
                                        version,
                                        udp_key,
                                        verified);

        peer_list.push_back(new_peer);
    }

    return;
}

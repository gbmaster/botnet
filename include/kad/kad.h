#ifndef KAD_H_INCLUDED
#define KAD_H_INCLUDED

#include "lib/libs.h"
#include "kad/firewall.h"
#include "kad/routingtable.h"
#include "kad/search.h"
#include "lib/tag.h"

#define KAD_VERSION 9

#define LAST_PACKET_SEC_TIMEOUT 1200

#define MAGICVALUE_UDP_SYNC_CLIENT  0x395F2EC1
#define CRYPT_HEADER_WITHOUTPADDING 8



#define KADEMLIA_PACKET          0xE4

#define KADEMLIA2_BOOTSTRAP_REQ  0x01
#define KADEMLIA2_BOOTSTRAP_RES  0x09
#define KADEMLIA2_HELLO_REQ      0x11
#define KADEMLIA2_HELLO_RES      0x19
#define KADEMLIA2_REQ            0x21
#define KADEMLIA2_HELLO_RES_ACK  0x22
#define KADEMLIA2_RES            0x29
#define KADEMLIA_FIREWALLED2_REQ 0x53
#define KADEMLIA_FIREWALLED_RES  0x58
#define KADEMLIA2_PING           0x60
#define KADEMLIA2_PONG           0x61

class Kad
{
    public:
        static Kad& get_instance()
        {
            static Kad instance;
            return instance;
        }

        bool is_connected() { return get_current_time() - _last_contact < LAST_PACKET_SEC_TIMEOUT; }

        void bootstrap();

        /*
         * Sends a generic KAD packet to ip_address:port contact_id encrypted with udp_key (or the contact_id)
         */
        bool send_kad_packet(uint32_t ip_address,
                             uint16_t port,
                             const uint128_t& contact_id,
                             const KadUDPKey udp_key,
                             unsigned char type,
                             const unsigned char *payload,
                             uint32_t length);

        /*
         * Sends a KADEMLIA2_HELLO_REQ to contact
         */
        bool send_hello_request(const Contact* contact, bool is_ack_requested);

        /*
         * Sends a KADEMLIA2_REQ to contact
         */
        bool send_request(const Contact* contact, uint8_t max_responses, const uint128_t& target);

        /*
         * Checks if there is an incoming packet and dispatches it
         */
        void retrieve_and_dispatch_potential_packet();

        unsigned char get_connect_options(bool encryption, bool callback)
        {
            // Encryption is always supported
            return encryption ? (1 << 3) | (1 << 2) | (1 << 1) : 0;
        }

        /*
         * These ones retrieve the information about the local Kad contact
         */
        const uint128_t& get_client_id() const { return _kad_client_id; }
        uint32_t get_public_ip() const { return _public_ip_address; }
        uint16_t get_udp_port() const { return _kad_udp_port; }

        uint32_t get_udp_verify_key(uint32_t ip_address)
        {
            uint64_t buffer = (uint64_t)_kad_udp_key << 32 | ip_address;

            unsigned char digest[16];
            md5sum((unsigned char *)&buffer, 8, digest);

            return ((*(uint32_t *)digest) ^ (*(uint32_t *)(digest + 4)) ^ (*(uint32_t *)(digest + 8)) ^ (*(uint32_t *)(digest + 12))) % 0xFFFFFFFE + 1;
        }

        /*
         * The UDP socket used for communications
         */
        SOCKET get_socket() { return _sock; }

        /*
         * The list containing all the peers used to bootstrap the network
         */
        std::list<Contact *>& get_bootstrap_peers() { return _bootstrap_peers; }

    private:
        Kad();
        Kad(const Kad &);
        Kad& operator = (const Kad&);

        void set_last_contact() { _last_contact = get_current_time(); }

        /*
         * Sends a KADEMLIA2_BOOTSTRAP_REQ to contact
         */
        bool send_bootstrap_request(const Contact *contact);
        /*
         * Processes a KADEMLIA2_BOOTSTRAP_RES message
         */
        bool process_bootstrap_response(const unsigned char *buffer, uint32_t length, uint32_t ip_address);

        /*
         * Processes a KADEMLIA2_HELLO_REQ message
         */
        bool process_hello_response(const unsigned char *buffer,
                                    uint32_t length,
                                    uint32_t ip_address,
                                    uint16_t port,
                                    KadUDPKey& udp_key,
                                    bool is_recv_key_valid);

        /*
         * Processes a KADEMLIA_FIREWALLED_RES message
         */
        bool process_firewalled_response(const unsigned char *buffer,
                                         uint32_t length,
                                         uint32_t ip_address,
                                         uint16_t udp_port);

        /*
         * Processes a KADEMLIA2_PING message
         */
        bool process_ping(const unsigned char *buffer,
                          uint32_t length,
                          uint32_t ip_address,
                          uint16_t udp_port,
                          KadUDPKey& udp_key);
        /*
         * Sends a KADEMLIA2_PING to contact
         */
        bool send_ping(const Contact *contact);
        /*
         * Processes a KADEMLIA2_PONG message
         */
        bool process_pong(const unsigned char *buffer,
                          uint32_t length,
                          uint32_t ip_address,
                          uint16_t udp_port);

        /*
         * Processes a KADEMLIA2_RES message
         */
        bool process_response(const unsigned char *buffer,
                              uint32_t length,
                              uint32_t ip_address,
                              uint16_t udp_port);

        /*
         * Functions used to (de)obfuscate a packet
         */
        void deobfuscate_packet(unsigned char *in_buffer,
                                uint32_t in_buffer_length,
                                unsigned char** out_buffer,
                                uint32_t* out_buffer_length,
                                uint32_t ip_address,
                                uint32_t* receiver_key,
                                uint32_t* sender_key);
        void obfuscate_packet(unsigned char* in_buffer,
                              uint32_t in_buffer_length,
                              unsigned char* out_buffer,
                              uint32_t* out_buffer_length,
                              unsigned char *client_id_data,
                              uint32_t receiver_key,
                              uint32_t sender_key);

        uint128_t _kad_client_id;
        uint32_t _kad_udp_key;
        uint16_t _kad_udp_port;
        uint32_t _public_ip_address;

        SOCKET _sock;

        std::list<Contact *> _bootstrap_peers;

        time_t _last_contact;
};

#endif

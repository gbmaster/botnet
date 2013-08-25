#ifndef FIREWALL_H_INCLUDED
#define FIREWALL_H_INCLUDED

#include <vector>
#include <list>
#include <map>
#include "lib/libs.h"
#include "kad/contact.h"
#include "kad/kadudpkey.h"
#include "kad/uint128.h"

#define MAXIMUM_KAD_TCP_FW_CHECKS 3
#define MAXIMUM_KAD_UDP_FW_RESPONSES 2

class Firewall
{
    public:
        static Firewall& get_instance()
        {
            static Firewall instance;
            return instance;
        }

        /*
         * Do we really need a TCP firewall check?
         */
        bool tcp_firewall_check_needed() { return _num_tcp_fw_checks < MAXIMUM_KAD_TCP_FW_CHECKS; }
        void inc_fw_check() { _num_tcp_fw_checks++; }

        /*
         * Requests a TCP firewall check
         */
        bool tcp_firewall_check(uint32_t ip_address, uint16_t udp_port, KadUDPKey& udp_key);

        bool is_udp_verified() { return _is_udp_verified; }

        /*
         * Is TCP firewalled?
         */
        bool is_tcp_firewalled()
        {
            if(_tcp_fw_responses < 2)
                return true;
            else
                return false;
        }

        /*
         * Do we really need an UDP firewall check?
         */
        bool udp_firewall_check_needed() { return _udp_fw_responses < MAXIMUM_KAD_UDP_FW_RESPONSES; }

        /*
         * Sends an UDP firewall check request to the next candidate
         */
        void udp_firewall_check();

        bool is_udp_firewalled() { return _is_udp_firewalled; }

        /*
         * Info about the external TCP port
         */
        void add_new_external_port(uint32_t ip_address, uint16_t port);
        bool external_port_needed();
        bool external_port_used();
        void reset_external_ports() { _externIPs.clear(); _externPorts.clear(); }

        /*
         * Info about the external UDP port
         */
        uint16_t get_external_udp_port() const { return _ext_udp_port; }
        void set_external_udp_port_used(bool value) { _ext_udp_port_used = value; }
        bool external_udp_port_port_used() const { return _ext_udp_port_used; }
        bool external_udp_port_verified() const { return _ext_udp_verified; }

        /*
         * Was a TCP firewall request sent to ip_address?
         */
        bool is_firewall_req_ip_address(uint32_t ip_address) const;
        /*
         * Remove the TCP firewall request sent to ip_address
         */
        void remove_firewall_req_ip_address(uint32_t ip_address);

        void increase_tcp_fw_res() { _tcp_fw_responses++; };

        /*
         * Add a new possible contact to send the UDP firewall check request to
         */
        void add_possible_udp_test_contact(const uint128_t& contact_id, uint32_t ip_address, uint16_t udp_port, uint16_t tcp_port, unsigned char version, const KadUDPKey& udp_key, bool is_verified);

    private:
        Firewall();
        Firewall(const Firewall &);
        Firewall& operator = (const Firewall&);

        std::list<uint32_t> _firewall_requests;

        unsigned int _num_tcp_fw_checks;
        uint32_t _tcp_fw_responses;
        bool _is_udp_firewalled;

        bool _is_udp_verified;
        uint32_t _udp_fw_responses;
        uint16_t _ext_udp_port;
        bool _ext_udp_port_used;
        bool _ext_udp_verified;

        std::vector<uint32_t> _externIPs;       // The IPs we received the responses from
        std::vector<uint16_t> _externPorts;     // The port they told us we have

        std::list<Contact> _potential_clients;  // The list of clients we'll contact for UDP firewall check
        std::map<uint32_t, bool> _used_clients; // The IPs already used and the boolean saying if they answered or not

        SOCKET _sock;
};

#endif

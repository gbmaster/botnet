#ifndef FIREWALL_H_INCLUDED
#define FIREWALL_H_INCLUDED

#include <vector>
#include <list>
#include "lib/libs.h"
#include "kad/kadudpkey.h"

#define MAXIMUM_KAD_FW_CHECKS 3

class Firewall
{
    public:
        static Firewall& get_instance()
        {
            static Firewall instance;
            return instance;
        }

        bool firewall_check_needed() { return _num_fw_checks < MAXIMUM_KAD_FW_CHECKS; }
        void inc_fw_check() { _num_fw_checks++; }

        bool firewall_check(uint32_t ip_address, uint16_t udp_port, KadUDPKey& udp_key);
        bool send_firewall_check_udp_request(uint32_t ip_address, uint16_t port);

        bool is_verified() { return _is_verified; }

        bool is_tcp_firewalled()
        {
            if(_tcp_fw_responses < 2)
                return true;
            else
                return false;
        }
        bool is_udp_firewalled() { return _is_udp_firewalled; }

        void add_new_external_port(uint32_t ip_address, uint16_t port);
        bool external_port_needed();
        bool external_port_used();
        void reset_external_ports() { _externIPs.clear(); _externPorts.clear(); }

        uint16_t get_external_udp_port() const { return _ext_udp_port; }
        void set_external_udp_port_used(bool value) { _ext_udp_port_used = value; }
        bool external_udp_port_port_used() const { return _ext_udp_port_used; }
        bool external_udp_port_verified() const { return _ext_udp_verified; }

        bool is_firewall_req_ip_address(uint32_t ip_address) const;
        void remove_firewall_req_ip_address(uint32_t ip_address);
        void increase_tcp_fw_res() { _tcp_fw_responses++; };

    private:
        Firewall();
        Firewall(const Firewall &);
        Firewall& operator = (const Firewall&);

        std::list<uint32_t> _firewall_requests;

        unsigned int _num_fw_checks;
        bool _is_verified;
        uint32_t _tcp_fw_responses;
        bool _is_udp_firewalled;

        uint16_t _ext_udp_port;
        bool _ext_udp_port_used;
        bool _ext_udp_verified;

        std::vector<uint32_t> _externIPs;
        std::vector<uint16_t> _externPorts;

        SOCKET _sock;
};

#endif

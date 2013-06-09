#include "kad/firewall.h"
#include "kad/kad.h"
#include "net/udp.h"

Firewall::Firewall()
{
    _num_fw_checks = 0;
    _is_verified = false;
    _tcp_fw_responses = 0;
    _is_udp_firewalled = true;

    _ext_udp_port = 0;
    _ext_udp_port_used = false;
    _ext_udp_verified = false;
}

void Firewall::add_new_external_port(uint32_t ip_address, uint16_t port)
{
    // Did we receive already an external Kad port from this address?
    for(unsigned int i = 0; i < _externIPs.size(); i++)
        if(_externIPs[i] == ip_address)
            return;

    _externIPs.push_back(ip_address);
    WriteLog("A new potential external Kad port (" << port << ") has been received from " <<
              ip_to_str(ip_address));

    for(unsigned int i = 0; i < _externPorts.size(); i++)
        if(_externPorts[i] == port)
        {
            // We need at least 2 equal external Kad ports in order
            // to declare it as definitive.
            // Well, one is already here...
            _ext_udp_port = port;

            WriteLog("External Kad port set to " << _ext_udp_port);

            // Our research is over: fill the IP vector with empty entries
            while(_externIPs.size() < 3)
                _externIPs.push_back(0);

            return;
        }

    _externPorts.push_back(port);

    if(!external_port_needed())
    {
        // We are not sure yet about the external Kad port, huh?
        _ext_udp_port = 0;
    }
}

bool Firewall::external_port_needed()
{
    return _externIPs.size() < 3;
}

bool Firewall::firewall_check(uint32_t ip_address, uint16_t udp_port, KadUDPKey& udp_key)
{
    unsigned int packet_size = 19;

    unsigned char *packet = new unsigned char[packet_size];

    uint16_t kad_tcp_port = TCPServer::get_instance().get_tcp_port();
    unsigned char client_id_buffer[16];
    Kad::get_instance().get_client_id().to_buffer(client_id_buffer);

    memcpy(packet, &kad_tcp_port, 2);
    memcpy(&(packet[2]), client_id_buffer, 16);

    unsigned char connect_options = Kad::get_instance().get_connect_options(true, false);
    memcpy(&(packet[18]), &connect_options, 1);

    uint128_t null_id(0);

    WriteLog("Sending KADEMLIA_FIREWALLED2_REQ to " << ip_to_str(ip_address) << ":" << udp_port);
    bool ret = Kad::get_instance().send_kad_packet(ip_address, udp_port, null_id, udp_key, KADEMLIA_FIREWALLED2_REQ, packet, packet_size);

    // We need to add the IP address to check that we don't receive any
    // unwanted firewall confirmation
    _firewall_requests.push_back(ip_address);

    delete [] packet;

    return ret;
}

bool Firewall::send_firewall_check_udp_request(uint32_t ip_address, uint16_t port)
{
    if(!Kad::get_instance().is_connected())
        return false;

    uint16_t internal_port = Kad::get_instance().get_udp_port();
    uint16_t external_port = get_external_udp_port();
    uint32_t udp_key = Kad::get_instance().get_udp_verify_key(ip_address);

    // OK, this is an ed2k packet. It will be forged differently
    unsigned char packet[14];
    uint32_t length = 14;

    packet[0] = 0xC5; // eMule protocol
    memcpy(packet + 1, &length, 4); // packet length
    packet[5] = 0xA7; // firewall UDP check

    memcpy(packet + 6, &internal_port, 2);
    memcpy(packet + 8, &external_port, 2);
    memcpy(packet + 10, &udp_key, 4);

    return udp_send(Kad::get_instance().get_socket(), ip_to_str(ip_address), port, packet, length);
}

bool Firewall::is_firewall_req_ip_address(uint32_t ip_address) const
{
    for(std::list<uint32_t>::const_iterator ipIt = _firewall_requests.begin();
        ipIt != _firewall_requests.end();
        ipIt++)
    {
        if(*ipIt == ip_address)
            return true;
    }

    return false;
}

void Firewall::remove_firewall_req_ip_address(uint32_t ip_address)
{
    for(std::list<uint32_t>::iterator ipIt = _firewall_requests.begin();
        ipIt != _firewall_requests.end();
        ipIt++)
    {
        if(*ipIt == ip_address)
        {
            _firewall_requests.erase(ipIt);
            return;
        }
    }
}

#ifndef CONTACT_H_INCLUDED
#define CONTACT_H_INCLUDED

#include "kad/uint128.h"
#include "kad/kadudpkey.h"
#include "lib/libs.h"
#include "net/ip.h"
#include "tcp/tcpserver.h"

enum KadContactType
{
    ACTIVE_LONGER_THAN_TWO_HOURS = 0,
    ACTIVE_ONE_TWO_HOURS,
    ACTIVE_LESS_THAN_ONE_HOUR,
    JUST_CREATED,
    PROMPTED_FOR_DELETION
};

inline KadContactType operator++(KadContactType &type, int)
{
    if(type == PROMPTED_FOR_DELETION)
        return type;
    else
    {
        int int_type = static_cast<int>(type);
        type = static_cast<KadContactType>(++int_type);
        return type;
    }
}

class Contact
{
    public:
        Contact(uint128_t contact_id,
                uint32_t ip_address,
                uint16_t udp_port,
                uint16_t tcp_port,
                unsigned char version,
                const KadUDPKey& udp_key,
                bool is_verified);

        ~Contact()
        {
            if(_tcp_socket != INVALID_SOCKET)
                TCPServer::get_instance().close_connection(_tcp_socket);
        }

        const uint128_t& get_contact_id() const { return _contact_id; }
        uint128_t& get_contact_id() { return _contact_id; }

        const uint128_t& get_distance() const { return _distance; }
        uint128_t& get_distance() { return _distance; }

        uint32_t get_ip_address() const { return _ip_address; }
        void set_ip_address(uint32_t ip_address) { _ip_address = ip_address; }

        uint16_t get_udp_port() const { return _udp_port; }
        void set_udp_port(uint16_t udp_port) { _udp_port = udp_port; }

        uint16_t get_tcp_port() const { return _tcp_port; }
        void set_tcp_port(uint16_t tcp_port) { _tcp_port = tcp_port; }

        KadUDPKey get_udp_key() const { return _udp_key; }
        void set_udp_key(KadUDPKey udp_key) { _udp_key = udp_key; }

        unsigned char get_version() const { return _version; }
        void set_version(unsigned char version) { _version = version; }

        KadContactType get_type() const { return _type; }
        void update_type();
        void fast_aging() { _type++; _expiration = get_current_time() + 120; }

        time_t get_expiration() const { return _expiration; }
        void set_expiration(time_t time) { _expiration = time; }

        bool is_verified() const { return _verified; }
        void set_verified(bool verified) { _verified = verified; }

        SOCKET get_tcp_socket() const { return _tcp_socket; }
        void set_tcp_socket(SOCKET s) { _tcp_socket = s; }

        void process_tcp_hello_packet(unsigned char *buffer);
        void send_tcp_hello_answer();

    private:
        unsigned int fill_with_hello_data(unsigned char *buffer);

        uint128_t _contact_id;
        uint128_t _distance;
        uint32_t _ip_address;
        uint16_t _udp_port;
        uint16_t _tcp_port;
        KadContactType _type;
        time_t _last_type_set;
        time_t _creation;
        time_t _expiration;
        KadUDPKey _udp_key;
        unsigned char _version;
        bool _verified;

        SOCKET _tcp_socket;
};

inline std::ostream& operator << (std::ostream &stream, const Contact &contact)
{
    std::stringstream ret;

    uint32_t ip_address = contact.get_ip_address();
    ret << "ip_address=" << ip_to_str(ip_address) << ":" << contact.get_udp_port() << " (" << contact.get_tcp_port() << "), ";
    ret << "contact_id=" << contact.get_contact_id() << ", ";
    ret << "version=" << (uint16_t)(contact.get_version()) << ";";

    stream << ret.str();
    return stream;
}

#endif

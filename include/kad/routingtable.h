#ifndef ROUTINGTABLE_H_INCLUDED
#define ROUTINGTABLE_H_INCLUDED

#include <list>
#include "kad/contact.h"
#include "kad/zone.h"

class RoutingTable
{
    public:
        static RoutingTable& get_instance()
        {
            static RoutingTable instance;
            return instance;
        }

        bool add(Contact *contact);
        bool add(uint128_t contact_id, uint32_t ip_address, uint16_t udp_port, uint16_t tcp_port, unsigned char version, const KadUDPKey& udp_key, bool is_verified);

        const Contact *get_random_contact();

        Contact *get_contact(const uint128_t& contact_id)
        {
            return _root->get_contact(contact_id);
        }
        Contact *get_contact_by_ip(uint32_t ip_address, uint16_t port, bool is_tcp = false)
        {
            return _root->get_contact_by_ip(ip_address, port, is_tcp);
        }
        void get_nearest_contacts(KadContactType maxType, const uint128_t& target, const uint128_t& distance, uint32_t max_required, std::list<const Contact *>& results)
        {
            return _root->get_nearest_contacts(maxType, target, distance, max_required, results);
        }

        void update_type_for_ip(uint32_t ip_address, uint16_t port, bool is_tcp = false)
        {
            _root->update_type_for_ip(ip_address, port, is_tcp);
        }

        bool is_ip_present(uint32_t ip_address)
        {
            return _root->is_ip_present(ip_address);
        }

        unsigned int get_num_contacts() { return _root->get_num_contacts(); }

        void get_all_zones(std::list<Zone *>& zones_list, Zone *starting_zone = NULL);
        void get_all_kBuckets(std::list<KBucket *>& kBuckets_list, Zone *starting_zone = NULL);

        void maintain_table();
        void process_big_timer();

    private:
        RoutingTable();
        RoutingTable(const RoutingTable &);
        RoutingTable& operator = (const RoutingTable&);

        Zone *_root;

        time_t _last_leaves_merge;
};

#endif

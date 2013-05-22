#ifndef ZONE_H_INCLUDED
#define ZONE_H_INCLUDED

#include "kad/kbucket.h"
#include "kad/uint128.h"

class Zone
{
    public:
        Zone(Zone *parent, uint128_t index, unsigned int level);
        Zone(Zone *parent, uint128_t index, unsigned int level, KBucket *kBucket);

        ~Zone()
        {
            if(_subnet != NULL)
            {
                delete _subnet;
            }
            else
            {
                delete _left_child;
                delete _right_child;
            }
        }

        bool add(Contact *contact);
        const Contact *get_random_contact();
        Contact *get_contact(const uint128_t& contact_id);
        Contact *get_contact_by_ip(uint32_t ip_address, uint16_t port, bool is_tcp = false)
        {
            return get_contact_by_ip_ref(ip_address, port, is_tcp);
        }
        void update_type_for_ip(uint32_t ip_address, uint16_t port, bool is_tcp = false)
        {
            Contact *contact = get_contact_by_ip_ref(ip_address, port, is_tcp);
            if(contact != NULL)
                contact->update_type();
        }
        bool is_ip_present(uint32_t ip_address);

        void merge_leaves();
        bool split_me();

        bool is_leaf() const { return _subnet != NULL; }
        unsigned int get_level() const { return _level; }
        uint128_t& get_index() { return _index; }
        unsigned int get_num_contacts();

        KBucket *get_subnet() const { return _subnet; }
        Zone *get_left_child() const { return _left_child; }
        Zone *get_right_child() const { return _right_child; }

    private:
        uint128_t _index;
        unsigned int _level;

        Zone *_parent;
        Zone *_left_child;
        Zone *_right_child;
        KBucket *_subnet;

        Contact *get_contact_by_ip_ref(uint32_t ip_address, uint16_t port, bool is_tcp = false);
};

#endif

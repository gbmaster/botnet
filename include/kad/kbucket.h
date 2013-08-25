#ifndef KBUCKET_H_INCLUDED
#define KBUCKET_H_INCLUDED

#include <list>
#include "kad/contact.h"
#include "log/log.h"

#define K 10

class KBucket
{
    public:
        KBucket() {};

        ~KBucket()
        {
            for (std::list<Contact *>::const_iterator contIt = _contact_list.begin();
                 contIt != _contact_list.end();
                 contIt++)
            {
                delete *contIt;
            }
        }

        Contact* get_contact(const uint128_t& contact_id);
        Contact* get_contact_by_ip(uint32_t ip_address, uint16_t port, bool is_tcp = false);
        Contact* get_random_contact();
        void get_nearest_contacts(KadContactType maxType, const uint128_t& target, const uint128_t& distance, uint32_t max_required, std::list<const Contact *>& results);
        Contact* get_oldest_contact();
        bool is_ip_present(uint32_t ip_address);
        void make_youngest(Contact *contact);

        void update_contact(Contact *contact);
        void add(Contact *contact);
        void remove(const Contact *contact, bool delete_contact = true);

        bool is_full() { return _contact_list.size() == K; }
        unsigned int get_num_contacts() { return _contact_list.size(); }
        void get_contact_list(std::list<Contact *>& contact_list);

    private:
        std::list<Contact *> _contact_list;
};

#endif

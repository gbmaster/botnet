#ifndef SEARCHTASK_H_INCLUDED
#define SEARCHTASK_H_INCLUDED

#include <list>
#include "kad/uint128.h"
#include "kad/contact.h"

#define KADEMLIA_FIND_NODE 0x0B

#define SEARCHNODE_LIFETIME 45

#define ALPHA 3
#define TOLERANCE 16777216

enum SearchType
{
	FIND_NODE
};

class SearchTask
{
    public:
        SearchTask(const uint128_t& id, SearchType type);
        void start();

        time_t get_creation_time() const { return _creation_time; }
        uint16_t get_timeout() const;

        // This one tries to repeat the search with the other contacts
        void push_search();

        SearchType get_type() const { return _type; }

        // Process the results
        void process_response(uint32_t ip_address, uint16_t udp_port, std::list<Contact*>& results);

    private:
        // The number of contacts to send the requests to each time
        uint32_t get_req_count() const;
        // The number of responses to be received
        uint32_t get_res_count() const;

        // Does this contact fall in the tolerance zone?
        bool in_tolerance_zone(const uint128_t& target, const uint128_t& source, uint32_t tolerance_zone);

        const uint128_t _id;

        std::list<const Contact *> _possible_contacts;
        std::list<const Contact *> _used_contacts;

        SearchType _type;

        time_t _creation_time;
};

#endif

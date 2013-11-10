#ifndef SEARCH_H_INCLUDED
#define SEARCH_H_INCLUDED

#include <map>
#include "kad/uint128.h"
#include "kad/searchtask.h"

class Search
{
    public:
        static Search& get_instance()
        {
            static Search instance;
            return instance;
        }

        // This one checks for timeouts and pushes the searches on and on
        void wake_up_searches();

        // Is there already a search for this ID?
        bool already_searching_for(const uint128_t& id);

        // Add a new task to the set
        void add_new_task(const uint128_t& target, SearchTask *task) { _tasks[target] = task; }

        // Is the search for ID a firewall check?
        bool is_firewall_check(const uint128_t& id);

        void stop_search(const uint128_t& id);

        // Start a new search for the node target
        bool find_node(const uint128_t& target);

        // Process the results
        void process_response(const uint128_t& target, uint32_t ip_address, uint16_t udp_port, std::list<Contact*>& results);

    private:
        Search() {};
        Search(const Search &);
        Search& operator = (const Search&);

        std::map<const uint128_t, SearchTask*> _tasks;
};

#endif


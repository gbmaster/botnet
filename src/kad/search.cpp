#include "kad/search.h"
#include "log/log.h"

void Search::wake_up_searches()
{
    time_t now = get_current_time();

    // Loop on all searches
    std::map<const uint128_t, SearchTask*>::iterator itTask = _tasks.begin();
    while(itTask != _tasks.end())
    {
        std::map<const uint128_t, SearchTask*>::iterator itCurrentTask = itTask;
        itTask++;

        const uint128_t& target = itCurrentTask->first;
        SearchTask* task = itCurrentTask->second;

        if(task->get_creation_time() + task->get_timeout() <= now)
        {
            // Timeout-ed: please terminate this
            WriteLog("The search for ID #" << target << " died. Deleting it...");
            _tasks.erase(itCurrentTask);
            delete task;
        }
        else
        {
            // Try to look for more results by pushing the search
            task->push_search();
        }
    }
}

bool Search::already_searching_for(const uint128_t& id)
{
    return _tasks.find(id) != _tasks.end();
}

void Search::stop_search(const uint128_t& id)
{
    std::map<const uint128_t, SearchTask*>::iterator itTask = _tasks.find(id);

    // Do we really have a search with the ID?
    if (itTask != _tasks.end())
    {
        WriteLog("Stopping search with ID #" << id);

        SearchTask *task = itTask->second;
        delete task;
        _tasks.erase(itTask);
    }
}

bool Search::find_node(const uint128_t& target)
{
    WriteLog("FIND_NODE for #" << target);

    // Is there already a search going on on this?
    if(already_searching_for(target))
    {
        WriteLog("There's already a search using ID #" << target);
        return false;
    }

    // Start a new one
    SearchTask* search_task = new SearchTask(target, FIND_NODE);
    add_new_task(target, search_task);

    search_task->start();
    return true;
}

void Search::process_response(const uint128_t& target, uint32_t ip_address, uint16_t udp_port, std::list<Contact*>& results)
{
    std::map<const uint128_t, SearchTask*>::const_iterator itTask = _tasks.find(target);

    if(itTask != _tasks.end())
    {
        SearchTask *search_task = itTask->second;

        // Process the results
        search_task->process_response(ip_address, udp_port, results);
    }
    else
    {
        WriteWarnLog("The search results for " << target << " arrived too late or were unexpected.");
    }
}

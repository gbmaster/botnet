#include "kad/searchtask.h"
#include "kad/kad.h"

SearchTask::SearchTask(const uint128_t& id, SearchType type) : _id(id)
{
    _creation_time = get_current_time();
    _type = type;
}

void SearchTask::start()
{
    WriteLog(LOG_SECTION("Start search task ID #" << _id));

    if (_possible_contacts.empty())
    {
        const uint128_t distance = _id ^ Kad::get_instance().get_client_id();
        RoutingTable::get_instance().get_nearest_contacts(JUST_CREATED, _id, distance, 50, _possible_contacts);
    }

    // If we have some contacts to send the request to, let's do it
    if (!_possible_contacts.empty())
    {
        std::list<const Contact *>::iterator contIt = _possible_contacts.begin();
        for (uint32_t i = 0; i < get_req_count(); i++)
        {
            const Contact *contact = *contIt++;

            // Move the contact to the used ones
            _possible_contacts.pop_front();
            _used_contacts.push_back(contact);

            Kad::get_instance().send_request(contact, get_res_count(), _id);
        }
    }
    else
    {
        WriteLog("We have no contacts to send the request to");
    }

    WriteLog(LOG_SECTION("Start search task is over"));
}

void SearchTask::push_search()
{
    WriteLog(LOG_SECTION("Pushing search task ID #" << _id));

    if(!_possible_contacts.empty())
    {
        const Contact* contact = *(_possible_contacts.begin());

        _possible_contacts.erase(_possible_contacts.begin());
        _used_contacts.push_back(contact);

        Kad::get_instance().send_request(contact, get_res_count(), _id);
    }
    else
    {
        // By changing the creation time, we'll cheat in order to get deleted
        WriteLog("We have no contacts to send the request to");
        _creation_time = get_current_time() - get_timeout();
    }

    WriteLog(LOG_SECTION("End pushing search task ID #" << _id));
}

uint32_t SearchTask::get_req_count() const
{
    if (_type == FIND_NODE)
        return 1;
    else
        // The minimum
        return ALPHA < _possible_contacts.size() ? ALPHA : _possible_contacts.size();
}

uint32_t SearchTask::get_res_count() const
{
    if (_type == FIND_NODE)
        return KADEMLIA_FIND_NODE;
    else
        assert(false);
}

uint16_t SearchTask::get_timeout() const
{
    if (_type == FIND_NODE)
        return SEARCHNODE_LIFETIME;
    else
        assert(false);
}

bool SearchTask::in_tolerance_zone(const uint128_t& target, const uint128_t& source, uint32_t tolerance_zone)
{
    uint128_t xor_value = source ^ target;
    uint32_t lowest_bytes = xor_value.low() & 0xFFFFFFFF;

    return lowest_bytes < tolerance_zone;
}

void SearchTask::process_response(uint32_t ip_address, uint16_t udp_port, std::list<Contact*>& results)
{
    WriteLog(LOG_SECTION("Start processing search ID #" << _id));

    uint128_t distance;
    const Contact *from_contact = NULL;

    for(std::list<const Contact*>::const_iterator contIt = _used_contacts.begin();
        contIt != _used_contacts.end();
        contIt++)
    {
        const Contact *contact = *contIt;
        if(contact->get_ip_address() == ip_address && contact->get_udp_port() == udp_port)
        {
            distance = contact->get_distance();
            from_contact = contact;
            break;
        }
    }

    // As the results have been already inserted by the Kad process, we're not interested in results (here)
    if(_type == FIND_NODE)
    {
        _possible_contacts.clear();
        return;
    }

    if(from_contact == NULL || from_contact != NULL)
        assert(false);
/*
    std::list<const Contact*> alpha;

    for(std::list<Contact*>::const_iterator contIt = results.begin();
        contIt != results.end();
        contIt++)
    {
        const Contact* contact = *contIt;
        bool should_be_skipped = false;

        for(std::list<const Contact*>::const_iterator usedContIt = _used_contacts.begin();
            usedContIt != _used_contacts.end();
            usedContIt++)
        {
            if((*usedContIt)->get_contact_id() == contact->get_contact_id())
                should_be_skipped = true;
        }

        // If this one should be skipped, then skip it
        if(should_be_skipped)
            continue;

        for(std::list<const Contact*>::const_iterator possContIt = _possible_contacts.begin();
            possContIt != _possible_contacts.end();
            possContIt++)
        {
            if((*possContIt)->get_contact_id() == contact->get_contact_id())
                should_be_skipped = true;
        }

        // If this one should be skipped, then skip it
        if(should_be_skipped)
            continue;

        if(in_tolerance_zone(contact->get_contact_id() ^ Kad::get_instance().get_client_id(),
                             _id ^ Kad::get_instance().get_client_id(),
                             TOLERANCE))
        {
            alpha.push_back(contact);
        }
        else
        {
            WriteLog("Adding " << *contact << " to the contactable ones list");
            _possible_contacts.push_back(contact);
        }
    }

    // Send again the request to these guys
    if(alpha.size() > 0)
    {
        for(std::list<const Contact*>::const_iterator contIt = alpha.begin();
            contIt != alpha.end();
            contIt++)
        {
            _used_contacts.push_back(*contIt);
            Kad::get_instance().send_request(*contIt, get_res_count(), _id);
        }
    }
*/
    WriteLog(LOG_SECTION("End processing search ID #" << _id));
}

#include "kad/kbucket.h"
#include "kad/uint128.h"
#include "net/ip.h"

bool compare_distance(const Contact* first, const Contact* second)
{
    if (first->get_distance() < second->get_distance())
        return true;
    else
        return false;
}

Contact* KBucket::get_contact(const uint128_t& contact_id)
{
    for(std::list<Contact *>::const_iterator contIt = _contact_list.begin();
        contIt != _contact_list.end();
        contIt++)
    {
        if((*contIt)->get_contact_id() == contact_id)
            return *contIt;
    }

    return NULL;
}

/*
 * How contact_list works:
 *    FRESHER CONTACTS ARE ALWAYS AT THE BOTTOM OF THE LIST
 *    * the new contacts are always added in the back
 *    * if a contact sent us a packet, we update it putting it in the back
 */

Contact* KBucket::get_oldest_contact()
{
    if(_contact_list.size() == 0)
        return NULL;
    else
        return _contact_list.front();
}

void KBucket::add(Contact *contact)
{
    _contact_list.push_back(contact);
}

void KBucket::update_contact(Contact *contact)
{
    for(std::list<Contact *>::iterator contIt = _contact_list.begin();
        contIt != _contact_list.end();
        contIt++)
    {
        if((*contIt)->get_contact_id() == contact->get_contact_id())
        {
            Contact *contact = *contIt;

            _contact_list.erase(contIt);
            _contact_list.push_back(contact);

            return;
        }
    }
}

void KBucket::remove(const Contact *contact, bool delete_contact)
{
    for(std::list<Contact *>::iterator contIt = _contact_list.begin();
        contIt != _contact_list.end();
        contIt++)
    {
        if((*contIt)->get_ip_address() == contact->get_ip_address())
        {
            Contact *to_be_erased = *contIt;

            _contact_list.erase(contIt);
            if(delete_contact) delete to_be_erased;
            return;
        }
    }
}

Contact* KBucket::get_random_contact()
{
    if(_contact_list.size() == 0)
        return NULL;

    unsigned int rand_stop = rand() % _contact_list.size();
    unsigned int i = 0;
    Contact *contact;

    for(std::list<Contact *>::const_iterator contIt = _contact_list.begin();
        contIt != _contact_list.end();
        contIt++, i++)
    {
        if(i == rand_stop)
            contact = *contIt;
    }

    return contact;
}

void KBucket::get_nearest_contacts(KadContactType maxType, const uint128_t& target, const uint128_t& distance, uint32_t max_required, std::list<const Contact *>& results)
{
    if(_contact_list.size() == 0)
        return;

    for(std::list<Contact *>::const_iterator contIt = _contact_list.begin();
        contIt != _contact_list.end();
        contIt++)
    {
        // Is it the one we're looking for?
        if((*contIt)->get_type() <= maxType && (*contIt)->is_verified())
        {
            results.push_back(*contIt);
        }
    }

    // We need to sort' em, now, as we'll check if there are too many results
    results.sort(compare_distance);

    while(results.size() > max_required)
    {
        results.erase(--results.end());
    }
}

void KBucket::get_contact_list(std::list<Contact *>& contact_list)
{
    for(std::list<Contact *>::iterator contIt = _contact_list.begin();
        contIt != _contact_list.end();
        contIt++)
    {
        contact_list.push_back(*contIt);
    }
}

Contact* KBucket::get_contact_by_ip(uint32_t ip_address, uint16_t port, bool is_tcp)
{
    for(std::list<Contact *>::iterator contIt = _contact_list.begin();
        contIt != _contact_list.end();
        contIt++)
    {
        if((*contIt)->get_ip_address() == ip_address)
        {
            if(is_tcp)
            {
                if((*contIt)->get_tcp_port() == port)
                    return *contIt;
            }
            else
            {
                if((*contIt)->get_udp_port() == port)
                    return *contIt;
            }
        }
    }

    return NULL;
}

bool KBucket::is_ip_present(uint32_t ip_address)
{
    for(std::list<Contact *>::iterator contIt = _contact_list.begin();
        contIt != _contact_list.end();
        contIt++)
        if((*contIt)->get_ip_address() == ip_address)
            return true;

    return false;
}

void KBucket::make_youngest(Contact *contact)
{
    remove(contact, false);
    add(contact);
}

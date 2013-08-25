#include "kad/routingtable.h"
#include "kad/kad.h"
#include "log/log.h"

RoutingTable::RoutingTable()
{
    _root = new Zone(NULL, uint128_t(), 0, new KBucket());
    _last_leaves_merge = get_current_time();
}

bool RoutingTable::add(Contact* contact)
{
    // We don't add ourselves of old version contact
    if(contact->get_contact_id() == Kad::get_instance().get_client_id() || contact->get_version() < 7)
        return false;

    return _root->add(contact);
}

bool RoutingTable::add(uint128_t contact_id, uint32_t ip_address, uint16_t udp_port, uint16_t tcp_port, unsigned char version, const KadUDPKey& udp_key, bool is_verified)
{
    Contact* contact = new Contact(contact_id, ip_address, udp_port, tcp_port, version, udp_key, is_verified);

    if(!add(contact))
    {
        delete contact;
        return false;
    }

    return true;
}

const Contact* RoutingTable::get_random_contact()
{
    return _root->get_random_contact();
}

void RoutingTable::get_all_kBuckets(std::list<KBucket *>& kBuckets_list, Zone *starting_zone)
{
    if(starting_zone == NULL)
        starting_zone = _root;

    if(starting_zone->is_leaf())
    {
        kBuckets_list.push_back(starting_zone->get_subnet());
    }
    else
    {
        get_all_kBuckets(kBuckets_list, starting_zone->get_left_child());
        get_all_kBuckets(kBuckets_list, starting_zone->get_right_child());
    }
}

void RoutingTable::maintain_table()
{
    time_t now = get_current_time();

    std::list<KBucket *> kBuckets_list;
    RoutingTable::get_instance().get_all_kBuckets(kBuckets_list);

    /*
     * Remove all the expired contacts
     */

    for(std::list<KBucket *>::iterator kIt = kBuckets_list.begin();
        kIt != kBuckets_list.end();
        kIt++)
    {
        KBucket *kBucket = *kIt;

        std::list<Contact *> contact_list;
        kBucket->get_contact_list(contact_list);
        for(std::list<Contact *>::const_iterator contIt = contact_list.begin(); contIt != contact_list.end(); contIt++)
        {
            // Perfect, we have a contact: is it still alive?
            const Contact *contact = *contIt;

            // Is this contact doomed to deletion? Is the expiration date already gone?
            if((contact->get_type() == PROMPTED_FOR_DELETION) &&
               ((contact->get_expiration() > 0) && (contact->get_expiration() <= now)))
            {
                WriteLog(*contact << " expired. Removing! " << get_num_contacts() << " contacts in the RT.");
                // It was: delete it
                kBucket->remove(contact);

                continue;
            }
        }

        // Looking for the oldest one: maybe it's time to refresh it
        Contact *contact = kBucket->get_oldest_contact();
        // Maybe we already sent a request to this one or, anyway, it has an expiration date
        if(contact != NULL && (contact->get_expiration() >= now || contact->get_type() == PROMPTED_FOR_DELETION))
        {
            // "Promote" it in order to not catch it again at the next step
            kBucket->make_youngest(contact);
            contact = NULL;
        }

        if(contact != NULL)
        {
            Kad::get_instance().send_hello_request(contact, false);
            // It has 2 minutes to reply, otherwise there's the accelerated aging
            contact->fast_aging();
        }
    }

    /*
     * Try to merge leaves every 45 minutes
     */

    if(now - _last_leaves_merge >= 45 * 60)
    {
        _last_leaves_merge = now;
        _root->merge_leaves();
    }
}

void RoutingTable::process_big_timer()
{
    _root->process_big_timer();
}

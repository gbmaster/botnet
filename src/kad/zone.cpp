#include "kad/kad.h"
#include "kad/zone.h"
#include "log/log.h"

Zone::Zone(Zone *parent, uint128_t index, unsigned int level)
{
    _parent = parent;
    _index = index;
    _level = level;

    _left_child = NULL;
    _right_child = NULL;
}

Zone::Zone(Zone *parent, uint128_t index, unsigned int level, KBucket *kBucket)
{
    _parent = parent;
    _index = index;
    _level = level;

    _left_child = NULL;
    _right_child = NULL;

    _subnet = kBucket;
}

bool Zone::add(Contact *contact)
{
    if(!is_leaf())
    {
        // If it's not a leaf, the the research must be continued
        // recursively through the child, until a leaf is found
        if(contact->get_distance().get_bit(_level))
            return _right_child->add(contact);
        else
            return _left_child->add(contact);
    }
    else
    {
        // Good, a leaf: add the contact in the bucket
        // Is this contact already present in it?
        Contact *old_contact = _subnet->get_contact(contact->get_contact_id());

        if(old_contact != NULL)
        {
            // An old contact with the same ID was already present in the bucket
            // Update contact information

            if(old_contact->get_udp_key().get_key(Kad::get_instance().get_public_ip()) != 0 &&
               old_contact->get_udp_key().get_key(Kad::get_instance().get_public_ip()) != contact->get_udp_key().get_key(Kad::get_instance().get_public_ip()))
            {
                // Mmm... the Kad UDP key has changed. NOT UPDATING
                WriteWarnLog(ip_to_str(contact->get_ip_address()) <<
                             " tried to update itself in the routing table, but the Kad UDP key provided (0x" <<
                             std::hex << contact->get_udp_key().get_key(Kad::get_instance().get_public_ip()) <<
                             ") is different from the old one (" <<
                             old_contact->get_udp_key().get_key(Kad::get_instance().get_public_ip()) <<
                             std::dec << ")");
                return false;
            }

            // Update the information about the contact
            old_contact->set_ip_address(contact->get_ip_address());
            old_contact->set_udp_port(contact->get_udp_port());
            old_contact->set_tcp_port(contact->get_tcp_port());
            old_contact->set_version(contact->get_version());
            old_contact->set_udp_key(contact->get_udp_key());
            old_contact->set_verified(contact->is_verified());
            old_contact->update_type();

            // Put the contact on the top of the list
            _subnet->make_youngest(old_contact);

            return false;
        }
        else
        {
            // If the bucket is not full, then add the client to the bucket
            if(!_subnet->is_full())
            {
                WriteLog("Adding in the routing table " << *contact);
                _subnet->add(contact);
                return true;
            }
            else
            {
                // Not enough space: the zone will be split in two childs
                if(!split_me())
                    return false;

                if(contact->get_distance().get_bit(_level))
                    return _right_child->add(contact);
                else
                    return _left_child->add(contact);
            }
        }
    }
}

bool Zone::split_me()
{
    // Are we already at the maximum level? Do we really need to split?
    if(_level >= 127 || !_subnet->is_full())
        return false;

    // Only the first five zones can split if the level is greater than 4
    if(_index < 5 || _level < 4)
    {
        // Create two childs and assign the contacts to them
        uint128_t left_index(_index);
        left_index <<= 1;

        uint128_t right_index(left_index);
        right_index += 1;

        WriteLog("kBucket " << _index << " is full. Splitting in " << left_index << " and " << right_index);

        KBucket *left_subnet = new KBucket();
        KBucket *right_subnet = new KBucket();
        std::list<Contact *> contact_list;
        _subnet->get_contact_list(contact_list);

        for(std::list<Contact *>::iterator contIt = contact_list.begin(); contIt != contact_list.end(); contIt++)
        {
            Contact *contact = *contIt;
            _subnet->remove(contact, false);

            if(contact->get_distance().get_bit(_level))
                right_subnet->add(contact);
            else
                left_subnet->add(contact);
        }

        _left_child = new Zone(this, left_index, _level + 1, left_subnet);
        _right_child = new Zone(this, right_index, _level + 1, right_subnet);

        delete _subnet;
        _subnet = NULL;

        return true;
    }
    else
        return false;
}

const Contact *Zone::get_random_contact()
{
    if(is_leaf())
    {
        return _subnet->get_random_contact();
    }
    else
    {
        const Contact *contact;
        unsigned char random_child = rand() & 1;

        if(random_child)
        {
            contact = _left_child->get_random_contact();
            if(contact == NULL) contact = _right_child->get_random_contact();
        }
        else
        {
            contact = _right_child->get_random_contact();
            if(contact == NULL) contact = _left_child->get_random_contact();
        }

        return contact;
    }
}

unsigned int Zone::get_num_contacts()
{
    if(is_leaf())
        return _subnet->get_num_contacts();
    else
        return _left_child->get_num_contacts() + _right_child->get_num_contacts();
}

void Zone::merge_leaves()
{
    // If it's already a leaf, there's nothing to merge
    if(is_leaf())
        return;

    if(!_left_child->is_leaf())
        _left_child->merge_leaves();
    if(!_right_child->is_leaf())
        _right_child->merge_leaves();

    // Less than K/2 contacts in the whole zone?
    if(_left_child->is_leaf() && _right_child->is_leaf() && get_num_contacts() < K/2)
    {
        _subnet = new KBucket();

        WriteLog("Merging zones " << _left_child->_index << " and " << _right_child->_index);

        std::list<Contact *> left_contacts, right_contacts;
        _left_child->_subnet->get_contact_list(left_contacts);
        _right_child->_subnet->get_contact_list(right_contacts);

        for(std::list<Contact *>::iterator contIt = left_contacts.begin(); contIt != left_contacts.end(); contIt++)
        {
            Contact *contact = *contIt;
            _left_child->_subnet->remove(contact, false);

            _subnet->add(contact);
        }

        delete _left_child;
        _left_child = NULL;

        for(std::list<Contact *>::iterator contIt = right_contacts.begin(); contIt != right_contacts.end(); contIt++)
        {
            Contact *contact = *contIt;
            _right_child->_subnet->remove(contact, false);

            _subnet->add(contact);
        }

        delete _right_child;
        _right_child = NULL;
    }
}

Contact* Zone::get_contact_by_ip_ref(uint32_t ip_address, uint16_t port, bool is_tcp)
{
    if(is_leaf())
        return _subnet->get_contact_by_ip(ip_address, port, is_tcp);

    Contact *contact = _left_child->get_contact_by_ip_ref(ip_address, port, is_tcp);
    if(contact == NULL)
        contact = _right_child->get_contact_by_ip_ref(ip_address, port, is_tcp);

    return contact;
}

Contact* Zone::get_contact(const uint128_t& contact_id)
{
    if(is_leaf())
        return _subnet->get_contact(contact_id);

    Contact *contact = _left_child->get_contact(contact_id);
    if(contact == NULL)
        contact = _right_child->get_contact(contact_id);

    return contact;
}

bool Zone::is_ip_present(uint32_t ip_address)
{
    if(is_leaf())
        return _subnet->is_ip_present(ip_address);

    bool ret = _left_child->is_ip_present(ip_address);
    if(!ret)
        ret = _right_child->is_ip_present(ip_address);

    return ret;
}

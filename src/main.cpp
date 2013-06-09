#ifdef __linux__

#include <unistd.h>

#endif

#include <string.h>
#include "net/ip.h"
#include "net/http.h"
#include "tcp/tcpserver.h"
#include "log/log.h"
#include "lib/libs.h"

int main()
{
	/*
	 * Network initialization (actually needed only Windows)
	 */
    if(!net_initialize())
    {
	WriteLog("Unable to initialize the network");
	return -1;
    }

    std::list<Contact *> peer_list;
    std::list<Contact *>& bootstrap_list = Kad::get_instance().get_bootstrap_peers();
    bool active = true;

    // Try to download the nodes from nodes.dat files from the www
    download_nodes_list(peer_list, bootstrap_list);
    // unsigned char id[16] = { 0xC0, 0x18, 0xE8, 0xFF, 0x42, 0x8F, 0x1A, 0xAA, 0x88, 0x45, 0x06, 0x0E, 0xAF, 0x88, 0x92, 0x52};
    // Contact *tmp_contact = new Contact(uint128_t::get_from_buffer(id), 0xB501A8C0, 9734, 123, 9, 0, false);
    // peer_list.push_back(tmp_contact);

    enter_critical_section(&(RoutingTable::get_instance().get_contactlist_mutex()));
    for(std::list<Contact *>::const_iterator contIt = peer_list.begin();
        contIt != peer_list.end();
        contIt++)
    {
        RoutingTable::get_instance().add(*contIt);
    }
    leave_critical_section(&(RoutingTable::get_instance().get_contactlist_mutex()));
    WriteLog("Added " << peer_list.size() << " nodes and " << bootstrap_list.size() << " bootstrap nodes");

    while(active)
    {
        millisec_sleep(20);

        enter_critical_section(&(RoutingTable::get_instance().get_contactlist_mutex()));
        Kad::get_instance().retrieve_and_dispatch_potential_packet();
        TCPServer::get_instance().retrieve_and_dispatch_potential_packet();

        // Should we bootstrap?
        if(!Kad::get_instance().is_connected() && RoutingTable::get_instance().get_num_contacts() == 0)
        {
            Kad::get_instance().bootstrap();
            millisec_sleep(1980);
        }
        leave_critical_section(&(RoutingTable::get_instance().get_contactlist_mutex()));
	}

    return 0;
}

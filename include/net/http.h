#ifndef HTTP_H_INCLUDED
#define HTTP_H_INCLUDED

#include <list>
#include "kad/kad.h"
#include "net/ip.h"

void download_nodes_list(std::list<Contact *>& peer_list, std::list<Contact *>& bootstrap_list);

#endif

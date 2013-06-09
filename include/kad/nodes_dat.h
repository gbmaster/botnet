#ifndef NODES_DAT_H_INCLUDED
#define NODES_DAT_H_INCLUDED

#include <list>
#include "kad/kad.h"

void extract_peers_from_nodes_dat(const unsigned char *buffer,
                                  std::list<Contact *>& peer_list,
                                  std::list<Contact *>& bootstrap_list);

#endif

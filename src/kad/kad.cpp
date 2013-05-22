#ifdef __linux__
#include <time.h>
#endif

#include <string.h>
#include <stdlib.h>
#include "kad/kad.h"
#include "kad/firewall.h"
#include "net/udp.h"
#include "log/log.h"
#include "lib/libs.h"

Kad::Kad()
{
    srand(get_current_time());

    _kad_udp_key = 0x842A1683;

    WriteWarnLog("REMEMBER TO GENERATE A VALID CLIENT_ID");
    _kad_client_id = uint128_t(0xE01691E42A6B7281, 0x73ECB6A5B35BBDF7);

    _public_ip_address = 0;
    _kad_udp_port = 9735;

    WriteLog("KAD INITIALIZED: client_id = " << _kad_client_id <<
                             " UDP key " << std::hex << _kad_udp_key << std::dec <<
                             " UDP " << _kad_udp_port);

    _sock = udp_socket(_kad_udp_port);
}

void Kad::bootstrap()
{
    const Contact *kad_peer;

    if(_bootstrap_peers.size())
        kad_peer = _bootstrap_peers.front();
    else
        return;

    if(Kad::get_instance().send_bootstrap_request(kad_peer))
    {
        if(_bootstrap_peers.size() > 0)
        {
            _bootstrap_peers.pop_front();
            delete kad_peer;
        }
    }
}

bool Kad::send_kad_packet(uint32_t ip_address, uint16_t port, const uint128_t& contact_id, const KadUDPKey udp_key, const unsigned char type, const unsigned char *payload, const uint32_t length)
{
    /*
     * Kad packets are like this:
     *
     * |----------------------------|
     * | Kad ID | OP code | Payload |
     * |----------------------------|
     *    1B       1B       lengthB
     */
    unsigned char *final_payload = new unsigned char[2 + length];
    uint32_t final_length = length + 2;

    final_payload[0] = KADEMLIA_PACKET;
    final_payload[1] = type;
    if(payload != NULL)
        memcpy(&(final_payload[2]), payload, length);

    // Perform encryption
    // Allocate a pretty big array of chars
    unsigned char *enc_payload = new unsigned char[CRYPT_HEADER_WITHOUTPADDING + 8 + 2 * final_length];
    uint32_t enc_payload_length;

    if(contact_id == 0)
        obfuscate_packet(final_payload, final_length, enc_payload, &enc_payload_length, NULL, udp_key.get_key(_public_ip_address), get_udp_verify_key(ip_address));
    else
    {
        unsigned char client_id_buffer[16];
        contact_id.to_buffer(client_id_buffer);
        obfuscate_packet(final_payload, final_length, enc_payload, &enc_payload_length, client_id_buffer, udp_key.get_key(_public_ip_address), get_udp_verify_key(ip_address));
    }

    // Original buffer not needed anymore
    delete [] final_payload;

    if(udp_send(_sock, ip_to_str(ip_address), port, enc_payload, enc_payload_length) == SOCKET_ERROR)
    {
        delete [] enc_payload;
        return false;
    }

    delete [] enc_payload;

    return true;
}

bool Kad::send_bootstrap_request(const Contact *contact)
{
    WriteLog("Sending KADEMLIA2_BOOTSTRAP_REQ to " << *contact);

    return send_kad_packet(contact->get_ip_address(),
                           contact->get_udp_port(),
                           contact->get_contact_id(),
                           contact->get_udp_key(),
                           KADEMLIA2_BOOTSTRAP_REQ,
                           NULL,
                           0);
}

bool Kad::process_bootstrap_response(const unsigned char *buffer, const uint32_t length)
{
    /*
     * This packet MUST be at least 21 bytes long:
     *  16B contact_id
     *   2B tcp_port
     *   1B version
     *   2B num_contacts
     *  ...
     */

    if(length < 21)
        return false;

    // If there are no contacts, all the contacts will be considered as verified
    bool verified = RoutingTable::get_instance().get_num_contacts() == 0;

    uint16_t num_contacts = *(uint16_t *)&(buffer[19]);
    // Every contact is 25B long; the header is 21B
    if(length - 21 != num_contacts * 25)
    {
        WriteLog("Malformed bootstrap request packet: length is " << length << " bytes, but" << 21 + num_contacts * 25 << " was expected");
        return false;
    }

    unsigned char *contact_entry = (unsigned char *)&(buffer[21]);
    // Put the contacts in the routing table
    for(uint16_t i = 0; i < num_contacts; i++, contact_entry += 25)
    {
        uint128_t contact_id = uint128_t::get_from_buffer(contact_entry);
        uint32_t ip_address = ntohl(*(uint32_t *)&(contact_entry[16]));
        uint16_t udp_port = *(uint16_t *)&(contact_entry[20]);
        uint16_t tcp_port = *(uint16_t *)&(contact_entry[22]);
        unsigned char version = contact_entry[24];

        RoutingTable::get_instance().add(contact_id, ip_address, udp_port, tcp_port, version, 0, verified);
    }

    return true;
}

bool Kad::send_hello_request(const Contact* contact, bool is_ack_requested)
{
    /*
     * This packet MUST be at least 20 bytes long:
     *  16B contact_id
     *   2B tcp_port
     *   1B Kad version
     *   1B tag list size
     *  ... (every tag size)
     */

    unsigned int packet_size = 20;      // packet size without any tag
    unsigned char tag_list_size = 0;

    Tag *source_udp_port_tag = NULL, *kad_options_tag = NULL;

    if(!Firewall::get_instance().external_udp_port_port_used())
    {
        tag_list_size++;

        source_udp_port_tag = new Int16Tag(TAG_SOURCEUPORT, _kad_udp_port);
        packet_size += source_udp_port_tag->get_size();
    }

    if(contact->get_version() >= 8 &&
       (Firewall::get_instance().is_udp_firewalled() || Firewall::get_instance().is_tcp_firewalled()))
    {
        tag_list_size++;
        uint8_t kad_options = ((is_ack_requested ? 1 : 0) << 2 |
			                   (Firewall::get_instance().is_tcp_firewalled() ? 1 : 0) << 1 |
                               (Firewall::get_instance().is_udp_firewalled() ? 1 : 0));

        kad_options_tag = new Int8Tag(TAG_KADMISCOPTIONS, kad_options);
        packet_size += kad_options_tag->get_size();
    }

    unsigned char *packet = new unsigned char[packet_size];

    unsigned char client_id_buffer[16];
    _kad_client_id.to_buffer(client_id_buffer);
    memcpy(&(packet[0]), client_id_buffer, 16);

    uint16_t tcp_port = TCPServer::get_instance().get_tcp_port();
    memcpy(&(packet[16]), (unsigned char *)&tcp_port, sizeof(uint16_t));
    packet[18] = KAD_VERSION;
    packet[19] = tag_list_size;

    // Where the tags start
    unsigned char *ppacket = packet + 20;
    if(source_udp_port_tag != NULL)
    {
        source_udp_port_tag->dump(ppacket);
        ppacket += source_udp_port_tag->get_size();
        delete source_udp_port_tag;
    }

    if(kad_options_tag != NULL)
    {
        kad_options_tag->dump(ppacket);
        delete kad_options_tag;
    }

    WriteLog("Sending KADEMLIA2_HELLO_REQ to " << *contact);
    bool ret = send_kad_packet(contact->get_ip_address(),
                               contact->get_udp_port(),
                               contact->get_contact_id(),
                               contact->get_udp_key(),
                               KADEMLIA2_HELLO_REQ,
                               packet,
                               packet_size);

    delete [] packet;

    return ret;
}

bool Kad::process_hello_response(const unsigned char *buffer, const uint32_t length, uint32_t ip_address, uint16_t port, KadUDPKey& udp_key, bool is_recv_key_valid)
{
    /*
     * This packet MUST be at least 20 bytes long:
     *  16B contact_id
     *   2B tcp_port
     *   1B version
     *   1B tag list size
     *  ...
     */

    if(length < 20)
        return false;

    uint128_t contact_id = uint128_t::get_from_buffer(buffer);
    uint16_t tcp_port = *(uint16_t *)&(buffer[16]);
    unsigned char version = buffer[18];
    unsigned char tag_list_size = buffer[19];

    unsigned char *tag_ptr = NULL;
    if(tag_list_size > 0)
         tag_ptr = (unsigned char *)&(buffer[20]);
    else
        return false;

    // Analyse the tags included
    bool is_udp_firewalled = false;
    uint16_t udp_port = port;
    bool is_ack_requested = false;
    for(unsigned char i = 0; i < tag_list_size; i++)
    {
        unsigned int bytes_processed;

        Tag *tag = extract_tag(tag_ptr, bytes_processed);
        if(tag == NULL)
            break;

        const std::string& name = tag->get_name();
        if(tag->get_type() == TAGTYPE_UINT16 && name.compare(TAG_SOURCEUPORT))
        {
            udp_port = ((Int16Tag *)tag)->get_value();
        }
        else if(tag->get_type() == TAGTYPE_UINT8 && name.compare(TAG_KADMISCOPTIONS))
        {
            uint8_t value = ((Int8Tag *)tag)->get_value();
            is_udp_firewalled = (value & 0x01) > 0;

            if((value & 0x04) > 0 && version >= 8)
                is_ack_requested = true;
        }

        delete tag;
    }

    Contact *contact = new Contact(contact_id, ip_address, udp_port, tcp_port, version, udp_key, is_recv_key_valid);
    if(!is_udp_firewalled)
    {
        RoutingTable::get_instance().add(contact_id, ip_address, udp_port, tcp_port, version, udp_key, is_recv_key_valid);
    }
    else
    {
        WriteLog(ip_to_str(ip_address) << " not added/updated, as the UDP port is firewalled");
        delete contact;
        // we return true, as the processing went fine, isn't it?
        return true;
    }

    if(is_ack_requested)
    {
        WriteLog(ip_to_str(ip_address) << " requested to send an ACK packet");

        if(!udp_key.is_valid())
        {
            WriteErrLog("Unable to send the ACK request, as the UDP key is not valid");
        }
        else
        {
            assert(false);
        }
    }

    if(Firewall::get_instance().external_port_needed())
        send_ping(contact);

    if(Firewall::get_instance().firewall_check_needed())
        Firewall::get_instance().firewall_check(ip_address, udp_port, udp_key);

    delete contact;

    return true;
}

bool Kad::process_firewalled_response(const unsigned char *buffer, const uint32_t length, uint32_t ip_address, uint16_t udp_port)
{
    // The KADEMLIA_FIREWALLED_RES message brings us the information about the external IP
    // that we use. Not even the space for that? In this case, sorry, it's a misforged packet
    if(length < 4)
    {
        WriteErrLog("KADEMLIA_FIREWALLED_RES from " << ip_to_str(ip_address) <<
                    " received with wrong length (" << length << "B). Discarding...");
        return false;
    }

    if(RoutingTable::get_instance().get_contact_by_ip(ip_address, udp_port) == NULL)
    {
        WriteErrLog(ip_to_str(ip_address) << "is not in the routing table. Discarding...");
        return false;
    }

    uint32_t external_ip = ntohl(*(uint32_t *)buffer);
    if(_public_ip_address != external_ip)
    {
        _public_ip_address = external_ip;
        WriteLog("External IP set to " << ip_to_str(_public_ip_address));
    }
    else
        WriteLog("Nothing new...");

    Firewall::get_instance().inc_fw_check();

    return true;
}

bool Kad::send_ping(const Contact *contact)
{
    WriteLog("Sending KADEMLIA2_PING to " << ip_to_str(contact->get_ip_address()) << ":" << contact->get_udp_port());

    return send_kad_packet(contact->get_ip_address(),
                           contact->get_udp_port(),
                           contact->get_contact_id(),
                           contact->get_udp_key(),
                           KADEMLIA2_PING,
                           NULL,
                           0);
}

bool Kad::process_pong(const unsigned char *buffer, const uint32_t length, uint32_t ip_address, uint16_t udp_port)
{
    // The KADEMLIA2_PONG message brings us the information about the external port
    // that we use. Not even the space for that? In this case, sorry, it's
    // a misforged packet
    if(length < 2)
    {
        WriteErrLog("KADEMLIA2_PONG from " << ip_to_str(ip_address) <<
                    " received with wrong length (" << length << "B). Discarding...");
        return false;
    }

    if(RoutingTable::get_instance().get_contact_by_ip(ip_address, udp_port) == NULL)
    {
        WriteErrLog(ip_to_str(ip_address) << "is not in the routing table. Discarding...");
        return false;
    }

    if(Firewall::get_instance().external_port_needed())
    {
        Firewall::get_instance().add_new_external_port(ip_address, *(uint16_t *)buffer);
    }

    return true;
}

void Kad::retrieve_and_dispatch_potential_packet()
{
    unsigned char *buffer;
    unsigned int length;
    struct sockaddr_in saddr;

    if(udp_recv(_sock, buffer, length, saddr) != SOCKET_ERROR)
    {
        WriteLog("Received an UDP packet of " << length << "B from " << ip_to_str(saddr.sin_addr.s_addr));

        if(length > 0)
        {
            if(length < 2)
            {
                WriteErrLog("Invalid Kad packet");
                delete [] buffer;
                return;
            }

            unsigned char *decrypted_buffer;
            unsigned int decrypted_length;
            uint32_t receiver_key, sender_key;
            deobfuscate_packet(buffer, length, &decrypted_buffer, &decrypted_length, saddr.sin_addr.s_addr, &receiver_key, &sender_key);

            if(decrypted_length == 0)
            {
                delete [] buffer;
                return;
            }

            KadUDPKey udp_key(sender_key, get_public_ip());
            bool valid_recv_key = receiver_key == get_udp_verify_key(saddr.sin_addr.s_addr);
            if(!valid_recv_key)
                WriteWarnLog("Invalid receiver key");

            if(decrypted_buffer[0] != 0xE4)
            {
                WriteErrLog("Kad packet magic number not present");
                delete [] buffer;
                return;
            }

            unsigned char type = decrypted_buffer[1];

            // Set the last packet receiving time
            set_last_contact();

            RoutingTable::get_instance().update_type_for_ip(saddr.sin_addr.s_addr, ntohs(saddr.sin_port));

            switch (type)
            {
                case KADEMLIA2_BOOTSTRAP_RES:
                {
                    WriteLog("It's a KADEMLIA2_BOOTSTRAP_RES");
                    process_bootstrap_response(decrypted_buffer + 2, decrypted_length - 2);
                    break;
                }
                case KADEMLIA2_HELLO_RES:
                {
                    WriteLog("It's a KADEMLIA2_HELLO_RES");
                    process_hello_response(decrypted_buffer + 2, decrypted_length - 2, saddr.sin_addr.s_addr, ntohs(saddr.sin_port), udp_key, valid_recv_key);
                    break;
                }
                case KADEMLIA_FIREWALLED_RES:
                {
                    WriteLog("It's a KADEMLIA_FIREWALLED_RES");
                    process_firewalled_response(decrypted_buffer + 2, decrypted_length - 2, saddr.sin_addr.s_addr, ntohs(saddr.sin_port));
                    break;
                }
                case KADEMLIA2_PONG:
                {
                    WriteLog("It's a KADEMLIA2_PONG");
                    process_pong(decrypted_buffer + 2, decrypted_length - 2, saddr.sin_addr.s_addr, ntohs(saddr.sin_port));
                    break;
                }
                default:
                    WriteErrLog("Kad packet with opcode 0x" << std::hex << (uint16_t)decrypted_buffer[1] << std::dec);
                    assert(false);
            }
        }

        delete [] buffer;
    }
}

void Kad::deobfuscate_packet(unsigned char* in_buffer, const uint32_t in_buffer_length, unsigned char** out_buffer, uint32_t* out_buffer_length, uint32_t ip_address, uint32_t* receiver_key, uint32_t* sender_key)
{
    *receiver_key = *sender_key = 0;
    *out_buffer = in_buffer;
    *out_buffer_length = in_buffer_length;

    // Not even the space for the crypt header? Is it an encrypted packet?
    if(in_buffer_length < CRYPT_HEADER_WITHOUTPADDING || in_buffer[0] == KADEMLIA_PACKET)
    {
        WriteLog("Not encrypted packet.");
        assert(false);
        return;
    }

    // A clue about if it has been encrypted with the client ID or with the Kad UDP key
	unsigned char marker_bit = (in_buffer[0] & 0x03);
	if(marker_bit != 0 && marker_bit != 2) marker_bit = 0;

    bool last_check = false;
    unsigned char md5hash[16];
    rc4key receiver_rc4_key;
    uint32_t value = 0;

    do
    {
        if(marker_bit == 0)
        {
            // Client ID is the key
            unsigned char key_data[18];
            _kad_client_id.to_buffer(key_data);
            memcpy(key_data + 16, in_buffer + 1, 2);
            md5sum(key_data, sizeof(key_data), md5hash);

            if(!last_check)
                marker_bit = 2;
        }
        else if(marker_bit == 2)
        {
            // Kad UDP key
            unsigned char key_data[6];
            uint32_t udp_verify_key = get_udp_verify_key(ip_address);
            memcpy(key_data, (unsigned char *)&udp_verify_key, 4);
            memcpy(key_data + 4, in_buffer + 1, 2);
            md5sum(key_data, sizeof(key_data), md5hash);

            if(!last_check)
                marker_bit = 0;
        }

        // Create the key and try to decrypt the magic value
        rc4_createkey(md5hash, 16, &receiver_rc4_key);
        rc4_process(in_buffer + 3, (unsigned char *)&value, 4, &receiver_rc4_key);

        if(last_check) break;
        else last_check = true;
    } while(value != MAGICVALUE_UDP_SYNC_CLIENT);

    if(value != MAGICVALUE_UDP_SYNC_CLIENT)
    {
        WriteErrLog("Unable to deobfuscate the packet");
        *out_buffer = NULL;
        *out_buffer_length = 0;
        return;
    }

    // Process padding
    unsigned char padding_length;
    rc4_process(in_buffer + 7, (unsigned char *)&padding_length, 1, &receiver_rc4_key);

    *out_buffer_length -= CRYPT_HEADER_WITHOUTPADDING;
    if(*out_buffer_length <= padding_length)
    {
        WriteErrLog("Padding length specified (" << (uint16_t)padding_length << "B) longer than the packet (" << *out_buffer_length << "B)");
        *out_buffer = NULL;
        *out_buffer_length = 0;
        return;
    }

    if(padding_length > 0)
        rc4_process(NULL, NULL, padding_length, &receiver_rc4_key);
    *out_buffer_length -= padding_length;

    // Decrypt the receiver and the sender key
    rc4_process(in_buffer + CRYPT_HEADER_WITHOUTPADDING + padding_length, (unsigned char *)receiver_key, sizeof(uint32_t), &receiver_rc4_key);
    rc4_process(in_buffer + CRYPT_HEADER_WITHOUTPADDING + padding_length + 4, (unsigned char *)sender_key, sizeof(uint32_t), &receiver_rc4_key);
    *out_buffer_length -= 8;

    // Decrypt the payload
    *out_buffer = in_buffer + (in_buffer_length - *out_buffer_length);
    rc4_process(*out_buffer, *out_buffer, *out_buffer_length, &receiver_rc4_key);
}

void Kad::obfuscate_packet(unsigned char* in_buffer, const uint32_t in_buffer_length, unsigned char* out_buffer, uint32_t* out_buffer_length, unsigned char *client_id_data, uint32_t receiver_key, uint32_t sender_key)
{
    /*
       The crypto header is composed like this:
       1B semi random marker byte
       2B random key bytes
       4B MAGICVALUE_UDP_SYNC_CLIENT
       1B number of bytes used for padding
       POTENTIAL PADDING BYTES
       4B receiver key
       4B sender key
     */

    const uint32_t crypt_header_size = CRYPT_HEADER_WITHOUTPADDING + 8;
    *out_buffer_length = in_buffer_length + crypt_header_size;

    // Time to generate the two random bytes used for the encryption
    uint16_t two_random_bytes = rand();

    unsigned char md5hash[16];
    bool is_client_id_used_for_key = true;
    if(client_id_data != NULL)
    {
        // We can use the destination client ID as key for encryption
        unsigned char key_data[18];
        memcpy(key_data, client_id_data, 16);
        memcpy(key_data + 16, &two_random_bytes, 2);
        md5sum(key_data, 18, md5hash);
    }
    else if(receiver_key != 0)
    {
        // We can use the destination UDP key
        unsigned char key_data[6];
        memcpy(key_data, &receiver_key, 4);
        memcpy(key_data + 4, &two_random_bytes, 2);
        md5sum(key_data, 6, md5hash);
        is_client_id_used_for_key = false;
    }
    else
        assert(false);

    /*
       The semi random marker byte is now generated: if the client ID has
       been used for the encryption, then it ends with the bits ...10, otherwise
       it ends with ...00
       This is going to be the first byte in the packet, the one used to
       identify the type of packet,  so it really can't be one of the following
       values:
           0xA3
           0xB2
           0xC5     eMule packet
           0xD4     eMule packet packet
           0xE4     Kad packet
           0xE5     Kad packed packet
       The only possible chance is to try to get a new random byte until
       it satisfies all the above criteria
     */

    unsigned char marker_byte;
    while(1)
    {
        // We want it to end with a 0 bit anyway...
        marker_byte = rand() & 0xFE;
        if(is_client_id_used_for_key) marker_byte &= 0xFC;
        else marker_byte |= 0x02;

        if(marker_byte != 0xA3 &&
           marker_byte != 0xB2 &&
           marker_byte != 0xC5 &&
           marker_byte != 0xD4 &&
           marker_byte != 0xE4 &&
           marker_byte != 0xE5)
           break;
    }

    rc4key sender_rc4_key;
    rc4_createkey(md5hash, 16, &sender_rc4_key);

    // Fill the header
    out_buffer[0] = marker_byte;
    memcpy(out_buffer + 1, &two_random_bytes, 2);
    uint32_t magic_value = MAGICVALUE_UDP_SYNC_CLIENT;
    unsigned char padding_length = 0;
    rc4_process((unsigned char *)&magic_value, out_buffer + 3, 4, &sender_rc4_key);
    rc4_process(&padding_length, out_buffer + 7, 1, &sender_rc4_key);

    // Add the keys
    rc4_process((unsigned char *)&receiver_key, out_buffer + CRYPT_HEADER_WITHOUTPADDING, 4, &sender_rc4_key);
    rc4_process((unsigned char *)&sender_key, out_buffer + CRYPT_HEADER_WITHOUTPADDING + 4, 4, &sender_rc4_key);

    // Encrypt the payload
    rc4_process(in_buffer, out_buffer + crypt_header_size, in_buffer_length, &sender_rc4_key);
}

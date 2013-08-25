#include "kad/contact.h"
#include "kad/kad.h"

Contact::Contact(const uint128_t& contact_id, uint32_t ip_address, uint16_t udp_port, uint16_t tcp_port,
                 uint8_t version, const KadUDPKey& udp_key, bool is_verified)
{
    _contact_id = contact_id;
    _distance = contact_id ^ Kad::get_instance().get_client_id();
    _ip_address = ip_address;
    _udp_port = udp_port;
    _tcp_port = tcp_port;
    _type = JUST_CREATED;
    _version = version;
    _udp_key = udp_key;
    _verified = is_verified;

    _creation = time(NULL);
    _expiration = 0;
    _last_type_set = _creation;

    _tcp_socket = INVALID_SOCKET;
}

void Contact::update_type()
{
    time_t now = get_current_time();
    uint32_t hours = (now - _creation) / 3600;

    if(hours == 0 && _type != ACTIVE_LESS_THAN_ONE_HOUR)
    {
        // Less than one hour: next potential upgrade will happen in 1h
        _type = ACTIVE_LESS_THAN_ONE_HOUR;
        _expiration = 3600;
    }
    else if(hours == 1 && _type != ACTIVE_ONE_TWO_HOURS)
    {
        // Between 1 and 2 hours: next potential upgrade will happen in 1h
        _type = ACTIVE_ONE_TWO_HOURS;
        _expiration = 3600;
    }
}

unsigned int Contact::fill_with_hello_data(unsigned char *buffer)
{
    unsigned int length = 0;
    // Fill with hash
    const unsigned char* user_hash = TCPServer::get_instance().get_user_hash();
    memcpy(buffer, user_hash, 16);
    buffer += 16; length += 16;

    // Fill with a dummy ID
    uint32_t theID = 1;
    memcpy(buffer, &theID, 4);
    buffer += 4; length += 4;

    // Fill with the TCP port
    uint16_t tcp_port = TCPServer::get_instance().get_tcp_port();
    memcpy(buffer, &tcp_port, 2);
    buffer += 2; length += 2;

    // Fill with the number of tags to be included (6)
    uint32_t number_of_tags = 6;
    memcpy(buffer, &number_of_tags, 4);
    buffer += 4; length += 4;

    // Fill the 1st tag: user name
    StringTag tag_username(CT_NAME, TCPServer::get_instance().get_user_name());
    tag_username.dump(buffer);
    buffer += tag_username.get_size(); length += tag_username.get_size();

    // Fill the 2nd tag: eMule version
    Int32Tag tag_version(CT_VERSION, TCPServer::get_instance().get_version());
    tag_version.dump(buffer);
    buffer += tag_version.get_size(); length += tag_version.get_size();

    // Fill the 3rd tag: Kad udp port
    uint32_t udp_port;
    if(Firewall::get_instance().get_external_udp_port() != 0 &&
       Firewall::get_instance().external_udp_port_port_used() &&
       Firewall::get_instance().external_udp_port_verified())
        udp_port = Firewall::get_instance().get_external_udp_port();
    else
        udp_port = Kad::get_instance().get_udp_port();
    // Here the information is sent twice because the eMule implementations checks
    // if UDP is really enabled (we are in TCP part of this stuff, so...): the
    // low part of the value would be 0 if so.
    Int32Tag tag_udpports(CT_EMULE_UDPPORTS, (uint32_t)udp_port << 16 | udp_port);
    tag_udpports.dump(buffer);
    buffer += tag_udpports.get_size(); length += tag_udpports.get_size();

    // Fill the 4th tag: eMule misc options
    // The most of these settings won't be even useful to us, as there won't
    // be any file exchange, but, duh, the protocol needs this stuff
    const uint32_t udp_ver = 4;
	const uint32_t data_comp_ver = 1;
	const uint32_t support_sec_ident = 0;
	const uint32_t source_exc_ver = 4;
	const uint32_t extended_req_ver = 2;
	const uint32_t accept_comment_ver = 1;
	const uint32_t no_view_shared_files = 0;
	const uint32_t multi_packet = 1;
	const uint32_t support_preview = 1;
	const uint32_t peer_cache = 1;
	const uint32_t unicode_support = 1;
	const uint32_t aich_ver = 1;
	Int32Tag tag_misc_opt1(CT_EMULE_MISCOPTIONS1, (aich_ver << 29) |
                                                  (unicode_support << 28) |
                                                  (udp_ver << 24) |
                                                  (data_comp_ver << 20) |
                                                  (support_sec_ident << 16) |
                                                  (source_exc_ver << 12) |
                                                  (extended_req_ver <<  8) |
                                                  (accept_comment_ver << 4) |
                                                  (peer_cache << 3) |
                                                  (no_view_shared_files << 2) |
                                                  (multi_packet << 1) |
                                                  (support_preview << 0));
    tag_misc_opt1.dump(buffer);
    buffer += tag_misc_opt1.get_size(); length += tag_misc_opt1.get_size();

    // Fill the 5th tag: eMule misc options (Kad)
    const uint32_t kad_version = KAD_VERSION;
    const uint32_t support_large_files = 1;
    const uint32_t ext_multi_packet = 1;
    const uint32_t reserved = 0;
    const uint32_t support_crypt_layer = 1;
    const uint32_t request_crypt_layer = 1;
    const uint32_t requires_crypt_layer = 1;
    const uint32_t support_source_ex2 = 1;
    const uint32_t support_captcha = 1;
    const uint32_t direct_udp_callback = Firewall::get_instance().is_tcp_firewalled() &&
                                         Firewall::get_instance().is_udp_firewalled() &&
                                         Firewall::get_instance().external_udp_port_verified();
    const uint32_t file_id = 1;
    Int32Tag tag_misc_opt2(CT_EMULE_MISCOPTIONS2,
                           ((file_id << 13) |
                            (direct_udp_callback << 12) |
                            (support_captcha << 11) |
                            (support_source_ex2 << 10) |
                            (requires_crypt_layer << 9) |
                            (request_crypt_layer << 8) |
                            (support_crypt_layer << 7) |
                            (reserved << 6) |
                            (ext_multi_packet << 5) |
                            (support_large_files << 4) |
                            (kad_version << 0)));
    tag_misc_opt2.dump(buffer);
    buffer += tag_misc_opt2.get_size(); length += tag_misc_opt2.get_size();

    // Fill the 6th and last tag: eMule version info
    const uint32_t maj = 1, min = 0, upd = 0;
    Int32Tag emule_version(CT_EMULE_VERSION,
                           ((maj << 17) |
                            (min << 10) |
                            (upd << 7)));
    emule_version.dump(buffer);
    buffer += emule_version.get_size(); length += emule_version.get_size();

    // Fill with null TCP server connection info
    uint32_t ip_addr = 0, port = 0;
    memcpy(buffer, &ip_addr, 4);
    buffer += 4; length += 4;
    memcpy(buffer, &port, 4);
    buffer += 4; length += 4;

    return length;
}

void Contact::send_tcp_hello_answer()
{
    WriteLog("Sending OP_HELLOANSWER to " << ip_to_str(_ip_address));

    unsigned char* buffer = new unsigned char[2048];

    unsigned int length = fill_with_hello_data(buffer);

    if(!TCPServer::get_instance().send_tcp_packet(_tcp_socket, OP_EDONKEYHEADER, OP_HELLOANSWER, buffer, length))
        TCPServer::get_instance().close_connection(_tcp_socket);

    delete [] buffer;
}

void Contact::process_tcp_hello_packet(unsigned char *buffer)
{
    uint32_t ip_address = *(uint32_t *)(buffer + 18);

    if(ip_address != _ip_address)
    {
        WriteErrLog("The IP address communicated (" << ip_to_str(ip_address) << ") is different from the stored one. Closing connection...");
        closesocket(_tcp_socket);

        return;
    }

    // Actually we don't care about all the information carried into the tags...

    send_tcp_hello_answer();
}

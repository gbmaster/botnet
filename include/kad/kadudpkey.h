#ifndef KADUDPKEY_H_INCLUDED
#define KADUDPKEY_H_INCLUDED

#include <assert.h>

class KadUDPKey
{
    public:
        KadUDPKey(uint32_t zero = 0)
        {
            assert(zero == 0);
            _key = 0;
            _ip_address = 0;
        }

        KadUDPKey(uint32_t key, uint32_t ip_address)
        {
            _key = key;
            _ip_address = ip_address;
        }

        KadUDPKey& operator = (const KadUDPKey& key)
        {
            _key = key._key;
            _ip_address = key._ip_address;
            return *this;
        }

		KadUDPKey& operator = (const uint32_t zero)
		{
            assert(zero == 0);
            _key = 0;
            _ip_address = 0;
            return *this;
        }

        void set_key(uint32_t key) { _key = key; }
        uint32_t get_key(uint32_t ip_address) const
        {
            if(ip_address == _ip_address)
                return _key;
            else
                return 0;
        }

        bool is_valid() { return _key != 0 && _ip_address != 0; }

    private:
        uint32_t _key;
        uint32_t _ip_address;
};

#endif

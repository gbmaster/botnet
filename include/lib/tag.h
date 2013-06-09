#ifndef TAG_H_INCLUDED
#define TAG_H_INCLUDED

#include <string>
#include <string.h>
#include <stdint.h>

#define CT_NAME               "\x01"
#define CT_VERSION            "\x11"
#define CT_EMULE_UDPPORTS     "\xF9"
#define CT_EMULE_MISCOPTIONS1 "\xFA"
#define CT_EMULE_VERSION      "\xFB"
#define CT_EMULE_MISCOPTIONS2 "\xFE"

#define TAG_KADMISCOPTIONS "\xF2"
#define TAG_SOURCEUPORT    "\xFC"

enum TagTypes {
    TAGTYPE_STRING = 0x02,
    TAGTYPE_UINT32 = 0x03,
    TAGTYPE_UINT16 = 0x08,
    TAGTYPE_UINT8  = 0x09
};

class Tag
{
    public:
        virtual ~Tag() {};
        TagTypes get_type() const { return _type; }
        void set_type(TagTypes tag_type) { _type = tag_type; }

        const std::string& get_name() const { return _name; }
        void set_tag_name(std::string& tag_name) { _name = tag_name; }

        unsigned int get_header_size() const { return 1 + 2 + _name.length(); }
        virtual unsigned int get_value_size() const = 0;
        unsigned int get_size() const { return get_header_size() + get_value_size(); }

        void dump_header(unsigned char *buffer) const
        {
            buffer[0] = _type;

            uint16_t len = _name.length();
            memcpy(buffer + 1, &len, 2);

            memcpy(buffer + 3, _name.c_str(), len);
        }
        virtual void dump_value(unsigned char *buffer) const = 0;
        void dump(unsigned char *buffer) const
        {
            dump_header(buffer);
            dump_value(buffer + get_header_size());
        }

    protected:
        TagTypes _type;
        std::string _name;
};

template<class T>
class TTag : public Tag
{
    public:
        const T get_value() const { return _value; }

    protected:
        T _value;
};

class Int8Tag : public TTag<uint8_t>
{
    public:
        Int8Tag(const std::string& name, uint8_t value) { _name = name; _value = value; _type = TAGTYPE_UINT8; }
        unsigned int get_value_size() const { return 1; }

        void dump_value(unsigned char *buffer) const
        {
            buffer[0] = _value;
        }
};

class Int16Tag : public TTag<uint16_t>
{
    public:
        Int16Tag(const std::string& name, uint16_t value) { _name = name; _value = value; _type = TAGTYPE_UINT16; }
        unsigned int get_value_size() const { return 2; }

        void dump_value(unsigned char *buffer) const
        {
            memcpy(buffer, &_value, 2);
        }
};

class Int32Tag : public TTag<uint32_t>
{
    public:
        Int32Tag(const std::string& name, uint32_t value) { _name = name; _value = value; _type = TAGTYPE_UINT32; }
        unsigned int get_value_size() const { return 4; }

        void dump_value(unsigned char *buffer) const
        {
            memcpy(buffer, &_value, 4);
        }
};

class StringTag : public TTag<std::string>
{
    public:
        StringTag(const std::string& name, std::string& value) { _name = name; _value = value; _type = TAGTYPE_STRING; }
        unsigned int get_value_size() const { return 2 + _value.size(); }

        void dump_value(unsigned char *buffer) const
        {
            uint16_t length = _value.size();
            memcpy(buffer, &length, 2);
            memcpy(buffer + 2, _value.c_str(), _value.size());
        }
};

#endif

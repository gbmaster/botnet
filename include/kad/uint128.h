#ifndef UINT128_H_INCLUDED
#define UINT128_H_INCLUDED

#include <sstream>
#include <iomanip>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

class uint128_t
{
    private:
        uint64_t _lo, _hi;

    public:
        uint128_t():
            _lo(0), _hi(0)
        {};

        template <typename T> uint128_t(T value)
        {
            _hi = 0;
            _lo = (uint64_t)value;
        }

        template <typename S, typename T> uint128_t(const S high, const T low)
        {
            _hi = (uint64_t)high;
            _lo = (uint64_t)low;
        }

        // Assignment
        template <typename T> uint128_t operator = (T right)
        {
            _hi = 0;
            _lo = (uint64_t) right;
            return *this;
        }

        uint128_t operator = (uint128_t right)
        {
            _hi = right._hi;
            _lo = right._lo;
            return *this;
        }

        /*
         * Bit-wise operations
         */

        // AND
        template <typename T> uint128_t operator & (T value)
        {
            return uint128_t(_hi, _lo & (uint64_t)value);
        }

        uint128_t operator & (uint128_t value)
        {
            return uint128_t(_hi & value._hi, _lo & value._lo);
        }

        template <typename T> uint128_t operator &= (T value)
        {
            _lo &= (uint64_t)value;
            return *this;
        }

        uint128_t operator &= (const uint128_t value)
        {
            _hi &= value._hi;
            _lo &= value._lo;
            return *this;
        }

        // OR
        template <typename T> uint128_t operator | (T value)
        {
            return uint128_t(_hi, _lo | (uint64_t)value);
        }

        uint128_t operator | (uint128_t value)
        {
            return uint128_t(_hi | value._hi, _lo | value._lo);
        }

        template <typename T> uint128_t operator |= (T value)
        {
            _lo |= (uint64_t)value;
            return *this;
        }

        uint128_t operator |= (const uint128_t value)
        {
            _hi |= value._hi;
            _lo |= value._lo;
            return *this;
        }

        // XOR
        template <typename T> uint128_t operator ^ (T value)
        {
            return uint128_t(_hi, _lo ^ (uint64_t)value);
        }

        uint128_t operator ^ (uint128_t value)
        {
            return uint128_t(_hi ^ value._hi, _lo ^ value._lo);
        }

        template <typename T> uint128_t operator ^= (T value)
        {
            _lo ^= (uint64_t)value;
            return *this;
        }

        uint128_t operator ^= (const uint128_t value)
        {
            _hi ^= value._hi;
            _lo ^= value._lo;
            return *this;
        }

        // SHIFT RIGHT
        template <typename T> uint128_t operator >> (const T shift) const
        {
            if (shift >= 128)
                return uint128_t(0, 0);
            else if (shift == 64)
                return uint128_t(0, _hi);
            else if (shift == 0)
                return *this;
            else if (shift < 64)
                return uint128_t(_hi >> shift, (_hi << (64 - shift)) + (_lo >> shift));
            else if ((128 > shift) && (shift > 64))
                return uint128_t(0, (_hi >> (shift - 64)));
            else
                return uint128_t(0);
        }

        // SHIFT LEFT
        template <typename T> uint128_t operator << (const T shift)
        {
            if (shift >= 128)
                return uint128_t(0, 0);
            else if (shift == 64)
                return uint128_t(_lo, 0);
            else if (shift == 0)
                return *this;
            else if (shift < 64)
                return uint128_t((_hi << shift) + (_lo >> (64 - shift)), _lo << shift);
            else if ((128 > shift) && (shift > 64))
                return uint128_t(_lo << (shift - 64), 0);
            else
                return uint128_t(0);
        }

        uint128_t operator <<= (int shift)
        {
            *this = *this << shift;
            return *this;
        }

        /*
         * Comparison
         */

        // Equality
        template <typename T> bool operator == (T value) const
        {
            // The high part MUST be 0, as value is supposed to be < 128 bit
            return (!_hi && (_lo == (uint64_t)value));
        }

        bool operator == (uint128_t value) const
        {
            return ((_hi == value._hi) && (_lo == value._lo));
        }

        // Greater
        template <typename T> bool operator > (T value) const
        {
            if (_hi) return true;
            return (_lo > (uint64_t) value);
        }

        bool operator > (uint128_t value) const
        {
            if (_hi == value._hi)
                return (_lo > value._lo);
            if (_hi > value._hi)
                return true;
            return false;
        }

        // Lesser
        template <typename T> bool operator < (T value) const
        {
            if (!_hi)
                return (_lo < (uint64_t)value);
            return false;
        }

        bool operator < (uint128_t value) const
        {
            if (_hi == value._hi)
                return (_lo < value._lo);
            if (_hi < value._hi)
                return true;
            return false;
        }

        /*
         * Arithmetic
         */

        // SUM
        template <typename T> uint128_t operator += (T right)
        {
            _hi = _hi + ((_lo + right) < _lo);
            _lo = _lo + right;
            return *this;
        }

        const uint64_t& high() const
        {
            return _hi;
        }

        const uint64_t& low() const
        {
            return _lo;
        }

        const unsigned char get_bit(unsigned char bit) const
        {
            return (*this >> (bit - 1)).low() & 1;
        }

        /*
         * Exporting
         */

        void to_buffer(unsigned char * buffer) const
        {
            uint32_t value_high_high = (_hi & 0xFFFFFFFF00000000) >> 32;
            uint32_t value_high_low = (_hi & 0xFFFFFFFF);
            uint32_t value_low_high = (_lo & 0xFFFFFFFF00000000) >> 32;
            uint32_t value_low_low = (_lo & 0xFFFFFFFF);
            memcpy(&(buffer[0]), (unsigned char *)&value_high_high, sizeof(uint32_t));
            memcpy(&(buffer[4]), (unsigned char *)&value_high_low, sizeof(uint32_t));
            memcpy(&(buffer[8]), (unsigned char *)&value_low_high, sizeof(uint32_t));
            memcpy(&(buffer[12]), (unsigned char *)&value_low_low, sizeof(uint32_t));
        }

        /*
         * Static functions
         */

        static uint128_t get_random_128()
        {
            uint64_t low_part = ((uint64_t)rand() << 32) + (uint32_t)rand();
            uint64_t high_part = ((uint64_t)rand() << 32) + (uint32_t)rand();

            return uint128_t(high_part, low_part);
        }

        static uint128_t get_from_buffer(const unsigned char *buffer)
        {
            uint64_t low_part = *(uint32_t *)(buffer + 8);
            low_part <<= 32;
            low_part += *(uint32_t *)(buffer + 12);
            uint64_t high_part = *(uint32_t *)buffer;
            high_part <<= 32;
            high_part += *(uint32_t *)(buffer + 4);

            return uint128_t(high_part, low_part);
        }
};

// Sum
template <typename T> T & operator += (T & left, uint128_t right)
{
    left = (T) (right + left);
    return left;
}

// XOR operator
template <typename T> T operator ^ (T left, uint128_t right)
{
    T res = left ^ (T)right.low();
    return res;
}

inline std::ostream &operator << (std::ostream &stream, const uint128_t &value)
{
    std::stringstream ret;
    ret << "0x" << std::hex << std::setfill('0') << std::setw(16) << value.high();
    ret << std::hex << std::setfill('0') << std::setw(16) << value.low();

    stream << ret.str();
    return stream;
}

#endif

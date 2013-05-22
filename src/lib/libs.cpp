#ifdef _WIN32
#include <windows.h>
#endif

#ifdef __linux__
#include <unistd.h>
#endif

#include "lib/libs.h"

/*
 * md5sum stuff
 */

typedef struct md5context
{
    uint32_t state[4];
    uint32_t count[2];
    unsigned char buffer[64];
} md5context;

static unsigned char PADDING[64] = {
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

/*
    A function like sleep()
*/
unsigned int sec_sleep(unsigned int seconds)
{
#ifdef __linux__
    return sleep(seconds);
#elif defined _WIN32
	Sleep(seconds * 1000);
	return 0;
#else
#error OS not supported
#endif
}

/*
    A function like usleep()
*/
unsigned int millisec_sleep(unsigned int milliseconds)
{
#ifdef __linux__
    return usleep(milliseconds * 1000);
#elif defined _WIN32
	Sleep(milliseconds);
	return 0;
#else
#error OS not supported
#endif
}

/*
    A function like time()
*/
#ifdef __linux__
time_t get_current_time()
{
    return time(NULL);
}
#elif defined _WIN32
DWORD get_current_time()
{
    return GetTickCount();
}
#else
#error OS not supported
#endif

/*
    A function like pthread_mutex_lock()
*/
#ifdef __linux__
int enter_critical_section(pthread_mutex_t *mutex)
{
    return pthread_mutex_lock(mutex);
}
#elif defined _WIN32
void enter_critical_section(LPCRITICAL_SECTION mutex)
{
    return EnterCriticalSection(mutex);
}
#else
#error OS not supported
#endif

/*
    A function like pthread_mutex_unlock()
*/
#ifdef __linux__
int leave_critical_section(pthread_mutex_t *mutex)
{
    return pthread_mutex_unlock(mutex);
}
#elif defined _WIN32
void leave_critical_section(LPCRITICAL_SECTION mutex)
{
    return LeaveCriticalSection(mutex);
}
#else
#error OS not supported
#endif

/*
    A function that extracts a tag from a buffer
*/
Tag * extract_tag(const unsigned char *buffer, unsigned int &bytes_processed)
{
    unsigned char tag_type = buffer[0];
    uint16_t name_length = *(uint16_t *)&(buffer[1]);

    std::string name((const char *)buffer, name_length);

    Tag *tag = NULL;

    switch(tag_type)
    {
        case TAGTYPE_UINT16:
        {
            uint16_t value = *(uint16_t *)&(buffer[1 + 2 + name_length]);
            tag = new Int16Tag(name, value);
            bytes_processed = 1 + 2 + name_length + 2;
            break;
        }

        case TAGTYPE_UINT8:
        {
            unsigned char value = *(unsigned char *)&(buffer[1 + 2 + name_length]);
            tag = new Int8Tag(name, value);
            bytes_processed = 1 + 2 + name_length + 1;
            break;
        }
        default:
            assert(false);
    }

    return tag;
}

/*
 * MD5SUM stuff
 */

void md5init(md5context *context)
{
    context->count[0] = context->count[1] = 0;
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
}

void md5encode(unsigned char *output, uint32_t *input, unsigned int length)
{
    unsigned int i, j;

    assert(length % 4 == 0);

    for (i = 0, j = 0; j < length; i++, j += 4)
    {
        output[j] = (unsigned char)(input[i] & 0xFF);
        output[j + 1] = (unsigned char)((input[i] >> 8) & 0xFF);
        output[j + 2] = (unsigned char)((input[i] >> 16) & 0xFF);
        output[j + 3] = (unsigned char)((input[i] >> 24) & 0xFF);
    }
}

void md5decode(uint32_t* dest, const unsigned char *src, uint32_t length)
{
	uint32_t i, j;

	assert(length % 4 == 0);

	for (i = 0, j = 0; j < length; i++, j += 4)
	{
		dest[i] = ((uint32_t)src[j]) | (((uint32_t)src[j + 1]) << 8) |
			      (((uint32_t)src[j + 2]) << 16) | (((uint32_t)src[j + 3]) << 24);
	}
}

uint32_t rotate_left(uint32_t x, uint32_t n)
{
    return ((x << n) | (x >> (32 - n)));
}

uint32_t F(uint32_t x, uint32_t y, uint32_t z)
{
    return ((x & y) | (~x & z));
}

uint32_t G(uint32_t x, uint32_t y, uint32_t z)
{
    return ((x & z) | (y & ~z));
}

uint32_t H(uint32_t x, uint32_t y, uint32_t z)
{
    return (x ^ y ^ z);
}

uint32_t I(uint32_t x, uint32_t y, uint32_t z)
{
    return (y ^ (x | ~z));
}

void FF(uint32_t& a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t ac)
{
    a += F(b, c, d) + x + ac;
    a = rotate_left(a, s);
    a += b;
}

void GG(uint32_t& a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t ac)
{
    a += G(b, c, d) + x + ac;
    a = rotate_left(a, s);
    a += b;
}

void HH(uint32_t& a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t ac)
{
    a += H(b, c, d) + x + ac;
    a = rotate_left(a, s);
    a += b;
}

void II(uint32_t& a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, uint32_t s, uint32_t ac)
{
    a += I(b, c, d) + x + ac;
    a = rotate_left(a, s);
    a += b;
}

void md5transform (md5context *context, const unsigned char *block)
{
    uint32_t a = context->state[0], b = context->state[1], c = context->state[2], d = context->state[3], x[16];

    md5decode(x, block, 64);

    // Round 1
    FF (a, b, c, d, x[ 0], S11, 0xd76aa478);
    FF (d, a, b, c, x[ 1], S12, 0xe8c7b756);
    FF (c, d, a, b, x[ 2], S13, 0x242070db);
    FF (b, c, d, a, x[ 3], S14, 0xc1bdceee);
    FF (a, b, c, d, x[ 4], S11, 0xf57c0faf);
    FF (d, a, b, c, x[ 5], S12, 0x4787c62a);
    FF (c, d, a, b, x[ 6], S13, 0xa8304613);
    FF (b, c, d, a, x[ 7], S14, 0xfd469501);
    FF (a, b, c, d, x[ 8], S11, 0x698098d8);
    FF (d, a, b, c, x[ 9], S12, 0x8b44f7af);
    FF (c, d, a, b, x[10], S13, 0xffff5bb1);
    FF (b, c, d, a, x[11], S14, 0x895cd7be);
    FF (a, b, c, d, x[12], S11, 0x6b901122);
    FF (d, a, b, c, x[13], S12, 0xfd987193);
    FF (c, d, a, b, x[14], S13, 0xa679438e);
    FF (b, c, d, a, x[15], S14, 0x49b40821);

    // Round 2
    GG (a, b, c, d, x[ 1], S21, 0xf61e2562);
    GG (d, a, b, c, x[ 6], S22, 0xc040b340);
    GG (c, d, a, b, x[11], S23, 0x265e5a51);
    GG (b, c, d, a, x[ 0], S24, 0xe9b6c7aa);
    GG (a, b, c, d, x[ 5], S21, 0xd62f105d);
    GG (d, a, b, c, x[10], S22,  0x2441453);
    GG (c, d, a, b, x[15], S23, 0xd8a1e681);
    GG (b, c, d, a, x[ 4], S24, 0xe7d3fbc8);
    GG (a, b, c, d, x[ 9], S21, 0x21e1cde6);
    GG (d, a, b, c, x[14], S22, 0xc33707d6);
    GG (c, d, a, b, x[ 3], S23, 0xf4d50d87);
    GG (b, c, d, a, x[ 8], S24, 0x455a14ed);
    GG (a, b, c, d, x[13], S21, 0xa9e3e905);
    GG (d, a, b, c, x[ 2], S22, 0xfcefa3f8);
    GG (c, d, a, b, x[ 7], S23, 0x676f02d9);
    GG (b, c, d, a, x[12], S24, 0x8d2a4c8a);

    // Round 3
    HH (a, b, c, d, x[ 5], S31, 0xfffa3942);
    HH (d, a, b, c, x[ 8], S32, 0x8771f681);
    HH (c, d, a, b, x[11], S33, 0x6d9d6122);
    HH (b, c, d, a, x[14], S34, 0xfde5380c);
    HH (a, b, c, d, x[ 1], S31, 0xa4beea44);
    HH (d, a, b, c, x[ 4], S32, 0x4bdecfa9);
    HH (c, d, a, b, x[ 7], S33, 0xf6bb4b60);
    HH (b, c, d, a, x[10], S34, 0xbebfbc70);
    HH (a, b, c, d, x[13], S31, 0x289b7ec6);
    HH (d, a, b, c, x[ 0], S32, 0xeaa127fa);
    HH (c, d, a, b, x[ 3], S33, 0xd4ef3085);
    HH (b, c, d, a, x[ 6], S34, 0x04881d05);
    HH (a, b, c, d, x[ 9], S31, 0xd9d4d039);
    HH (d, a, b, c, x[12], S32, 0xe6db99e5);
    HH (c, d, a, b, x[15], S33, 0x1fa27cf8);
    HH (b, c, d, a, x[ 2], S34, 0xc4ac5665);

    // Round 4
    II (a, b, c, d, x[ 0], S41, 0xf4292244);
    II (d, a, b, c, x[ 7], S42, 0x432aff97);
    II (c, d, a, b, x[14], S43, 0xab9423a7);
    II (b, c, d, a, x[ 5], S44, 0xfc93a039);
    II (a, b, c, d, x[12], S41, 0x655b59c3);
    II (d, a, b, c, x[ 3], S42, 0x8f0ccc92);
    II (c, d, a, b, x[10], S43, 0xffeff47d);
    II (b, c, d, a, x[ 1], S44, 0x85845dd1);
    II (a, b, c, d, x[ 8], S41, 0x6fa87e4f);
    II (d, a, b, c, x[15], S42, 0xfe2ce6e0);
    II (c, d, a, b, x[ 6], S43, 0xa3014314);
    II (b, c, d, a, x[13], S44, 0x4e0811a1);
    II (a, b, c, d, x[ 4], S41, 0xf7537e82);
    II (d, a, b, c, x[11], S42, 0xbd3af235);
    II (c, d, a, b, x[ 2], S43, 0x2ad7d2bb);
    II (b, c, d, a, x[ 9], S44, 0xeb86d391);

    context->state[0] += a;
    context->state[1] += b;
    context->state[2] += c;
    context->state[3] += d;

    memset(x, 0, sizeof(x));
}

void md5update(md5context *context, const unsigned char *buffer, const uint32_t length)
{
    uint32_t i, index, partLen;

	// Compute number of bytes mod 64
	index = (unsigned int)((context->count[0] >> 3) & 0x3F);

	// Update number of bits
	if ((context->count[0] += (length << 3)) < (length << 3))
		context->count[1]++;
	context->count[1] += (length >> 29);

	partLen = 64 - index;

	// Transform as many times as possible.
	if (length >= partLen)
	{
		memcpy(&(context->buffer[index]), buffer, partLen);
		md5transform(context, context->buffer);

		for (i = partLen; i + 63 < length; i += 64)
			md5transform(context, &buffer[i]);

		index = 0;
	}
	else
		i = 0;

    // Buffer remaining input
    memcpy(&(context->buffer[index]), &buffer[i], length - i);
}

void md5final(md5context *context, unsigned char digest[16])
{
    unsigned char bits[8];
    unsigned int index, padLen;

    // Save number of bits
    md5encode(bits, context->count, 8);

    // Pad out to 56 mod 64
	index = (unsigned int)((context->count[0] >> 3) & 0x3F);
	padLen = (index < 56) ? (56 - index) : (120 - index);
	md5update(context, PADDING, padLen);

    // Append length (before padding)
    md5update(context, bits, 8);

    // Store state in digest
    md5encode(digest, context->state, 16);

    // Zeroize sensitive information
    memset((unsigned char *)context, 0, sizeof(*context));
}

void md5sum(const unsigned char *buffer, const uint32_t length, unsigned char digest[16])
{
    md5context context;

    md5init(&context);
    md5update(&context, buffer, length);
    md5final(&context, digest);
}

/*
 * RC4 stuff
 */

void swap(unsigned char *a, unsigned char *b)
{
    unsigned char c;

    c = *a;
    *a = *b;
    *b = c;
}

rc4key *rc4_createkey(const unsigned char *buffer, uint32_t length, rc4key *key)
{
    unsigned int i;
    unsigned char j;

    if(key == NULL)
        key = new rc4key;

    for(i = 0; i < 256; i++)
        key->state[i] = i;
    key->index1 = key->index2 = 0;

    for(i = j = 0; i < 256; i++)
    {
        j += key->state[i] + buffer[i % length];
        swap(&(key->state[i]), &(key->state[j]));
    }

    return key;
}

void rc4_process(const unsigned char* in_buffer, unsigned char* out_buffer, uint32_t length, rc4key* key)
{
    if(key == NULL)
        return;

    unsigned char ks = 0;

    for(uint32_t l = 0; l < length; l++)
    {
        key->index1++;
        key->index2 += key->state[key->index1];
        swap(&(key->state[key->index1]), &(key->state[key->index2]));

        ks = key->state[key->index1] + key->state[key->index2];
        if(in_buffer != NULL)
            out_buffer[l] = in_buffer[l] ^ key->state[ks];
    }
}

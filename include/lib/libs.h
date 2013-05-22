#ifndef LIB_H_INCLUDED
#define LIB_H_INCLUDED

#include <arpa/inet.h>
#include <assert.h>
#include "lib/tag.h"

#ifdef __linux__

#include <stdint.h>
#include <time.h>
#include <pthread.h>

#define SOCKET int
#define INVALID_SOCKET (SOCKET)(~0)
#define SOCKET_ERROR -1

time_t get_current_time();
int enter_critical_section(pthread_mutex_t *mutex);
int leave_critical_section(pthread_mutex_t *mutex);

#elif defined _WIN32

#include <windows.h>

typedef unsigned __int16 uint16_t;
typedef unsigned __int32 uint32_t;

typedef int socklen_t;

DWORD get_current_time();
void enter_critical_section(LPCRITICAL_SECTION mutex);
void leave_critical_section(LPCRITICAL_SECTION mutex);

#else
#error OS not supported
#endif

unsigned int sec_sleep(unsigned int seconds);
unsigned int millisec_sleep(unsigned int milliseconds);

inline char *ip_to_str(uint32_t ip)
{
    return inet_ntoa(*(struct in_addr *)&ip);
}

Tag * extract_tag(const unsigned char *buffer, unsigned int &bytes_processed);

/*
 * MD5 stuff
 */

void md5sum(const unsigned char *buffer, const uint32_t length, unsigned char digest[16]);

/*
 * RC4 stuff
 */

typedef struct rc4key
{
    unsigned char state[256];
    unsigned char index1;
    unsigned char index2;
} rc4key;

rc4key *rc4_createkey(const unsigned char *buffer, uint32_t length, rc4key *key);
void rc4_process(const unsigned char* in_buffer, unsigned char* out_buffer, uint32_t length, rc4key* key);

#endif

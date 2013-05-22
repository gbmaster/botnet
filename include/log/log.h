#ifndef LOG_H_INCLUDED
#define LOG_H_INCLUDED

#include <iostream>
#include <sstream>
#include <cerrno>
#include <string.h>
#include <time.h>

#ifdef _DEBUG

#define WriteLog(x) \
    std::cout << get_date_time() << " INFO " << x << std::endl

#define WriteWarnLog(x) \
    std::cout << get_date_time() << " WARN " << x << std::endl

#define WriteErrLog(x) \
    std::cout << get_date_time() << " ERR  " << x << std::endl

inline std::string get_date_time()
{
    char buffer[20];
    time_t now = time(NULL);

    struct tm *t = gmtime(&now);

    strftime(buffer, sizeof(buffer), "%d-%m-%Y %H:%M:%S", t);

    return buffer;
}

#else

#define WriteLog(x)
#define WriteWarnLog(x)
#define WriteErrLog(x)

#endif

#endif

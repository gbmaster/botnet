#ifndef LOG_H_INCLUDED
#define LOG_H_INCLUDED

#include <algorithm>
#include <iostream>
#include <sstream>
#include <cerrno>
#include <string.h>
#include <time.h>

#ifdef _DEBUG

#define WriteLog(x) \
    std::cout << get_date_time() << " INFO [" << get_file_name(__FILE__) << ":" << __LINE__ << "] " << x << std::endl

#define WriteWarnLog(x) \
    std::cout << get_date_time() << " WARN [" << get_file_name(__FILE__) << ":" << __LINE__ << "] " << x << std::endl

#define WriteErrLog(x) \
    std::cout << get_date_time() << " ERR  [" << get_file_name(__FILE__) << ":" << __LINE__ << "] " << x << std::endl

inline std::string get_date_time()
{
    char buffer[20];
    time_t now = time(NULL);

    struct tm *t = gmtime(&now);

    strftime(buffer, sizeof(buffer), "%d-%m-%Y %H:%M:%S", t);

    return buffer;
}

struct path_separator
{
    bool operator()(char ch) const
    {
#ifdef __linux__
        return ch == '/';
#elif defined _WIN32
        return ch == '\\' || ch == '/';
#else
#error OS not supported
#endif
    }
};

inline std::string get_file_name(std::string const& pathname)
{
    return std::string(std::find_if(pathname.rbegin(),
                                    pathname.rend(),
                                    path_separator()
                                   ).base(), pathname.end());
}

#else

#define WriteLog(x)
#define WriteWarnLog(x)
#define WriteErrLog(x)

#endif

#endif

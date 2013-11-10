#ifndef LOG_H_INCLUDED
#define LOG_H_INCLUDED

#include <algorithm>
#include <iostream>
#include <sstream>
#include <cerrno>
#include <string.h>
#include <time.h>

#ifdef _DEBUG

#define LOG_RESETCOLOR  "\033[0m"
#define LOG_BOLDRED     "\033[1;31m"
#define LOG_BOLDGREEN   "\033[1;32m"
#define LOG_BOLDYELLOW  "\033[1;33m"
#define LOG_BOLDBLUE    "\033[1;34m"
#define LOG_YELLOW      "\033[33m"
#define LOG_BLUE        "\033[34m"
#define LOG_CYAN        "\033[36m"

#define LOG_MESSAGE_NAME(x)  LOG_BLUE << x << LOG_RESETCOLOR
#define LOG_MESSAGE_NAME2(x) LOG_BOLDBLUE << x << LOG_RESETCOLOR
#define LOG_SECTION(x)       LOG_YELLOW << x << LOG_RESETCOLOR

#define WriteLog(x) \
    std::cout << get_date_time() << " " << LOG_BOLDGREEN  << "INFO" << LOG_RESETCOLOR << " [" << get_file_name(__FILE__) << ":" << __LINE__ << "] " << x << std::endl

#define WriteWarnLog(x) \
    std::cout << get_date_time() << " " << LOG_BOLDYELLOW << "WARN" << LOG_RESETCOLOR << " ["  << get_file_name(__FILE__) << ":" << __LINE__ << "] " << x << std::endl

#define WriteErrLog(x) \
    std::cout << get_date_time() << " " << LOG_BOLDRED    << "ERR" << LOG_RESETCOLOR << "  ["  << get_file_name(__FILE__) << ":" << __LINE__ << "] " << x << std::endl

inline std::string get_date_time()
{
    char buffer[20];
    time_t now = time(NULL);

    struct tm *t = localtime(&now);

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

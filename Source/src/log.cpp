#include "runpe/log.h"

#include <cstdarg>
#include <cstdio>

namespace runpe::log {

namespace {

bool g_verbose = false;

void write(std::FILE* stream, const char* prefix, const char* format, va_list args) {
    std::fputs(prefix, stream);
    std::vfprintf(stream, format, args);
    std::fputc('\n', stream);
    std::fflush(stream);
}

} // namespace

void setVerbose(bool enabled) noexcept {
    g_verbose = enabled;
}

bool verbose() noexcept {
    return g_verbose;
}

void info(const char* format, ...) {
    va_list args;
    va_start(args, format);
    write(stdout, "[+] ", format, args);
    va_end(args);
}

void warn(const char* format, ...) {
    va_list args;
    va_start(args, format);
    write(stderr, "[!] ", format, args);
    va_end(args);
}

void error(const char* format, ...) {
    va_list args;
    va_start(args, format);
    write(stderr, "[-] ", format, args);
    va_end(args);
}

void debug(const char* format, ...) {
    if (!g_verbose)
        return;

    va_list args;
    va_start(args, format);
    write(stdout, "[.] ", format, args);
    va_end(args);
}

} // namespace runpe::log

#include "runpe/error.h"

#include <cstdio>
#include <utility>

namespace runpe {

std::string formatWin32Message(DWORD code) {
    LPWSTR buffer = nullptr;
    const DWORD length = FormatMessageW(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        nullptr,
        code,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        reinterpret_cast<LPWSTR>(&buffer),
        0,
        nullptr);

    std::string message;
    if (length != 0 && buffer != nullptr) {
        const int utf8Length = WideCharToMultiByte(CP_UTF8, 0, buffer,
                                                   static_cast<int>(length), nullptr, 0,
                                                   nullptr, nullptr);
        if (utf8Length > 0) {
            message.resize(static_cast<size_t>(utf8Length));
            WideCharToMultiByte(CP_UTF8, 0, buffer, static_cast<int>(length),
                                message.data(), utf8Length, nullptr, nullptr);
        }

        while (!message.empty() &&
               (message.back() == '\r' || message.back() == '\n' || message.back() == ' ')) {
            message.pop_back();
        }
    } else {
        message = "unknown error";
    }

    if (buffer != nullptr)
        LocalFree(buffer);

    return message;
}

Error lastError(std::string_view context, DWORD code) {
    std::string message(context);
    message += ": ";
    message += formatWin32Message(code);

    char hex[16]{};
    std::snprintf(hex, sizeof(hex), " (0x%08lX)", static_cast<unsigned long>(code));
    message += hex;

    return Error{std::move(message), code};
}

Error lastError(std::string_view context) {
    return lastError(context, GetLastError());
}

} // namespace runpe

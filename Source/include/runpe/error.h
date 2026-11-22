#pragma once

#include <windows.h>

#include <optional>
#include <string>
#include <string_view>
#include <variant>

namespace runpe {

struct Error {
    std::string message;
    DWORD code = 0;

    Error() = default;

    explicit Error(std::string text, DWORD win32Code = 0)
        : message(std::move(text)), code(win32Code) {}
};

// Formats a Win32 error code using FormatMessage.
std::string formatWin32Message(DWORD code);

// Builds an Error from a context string and the current (or supplied) GetLastError().
Error lastError(std::string_view context);
Error lastError(std::string_view context, DWORD code);

template <class T>
class Result {
public:
    Result(T value) : value_(std::in_place_index<0>, std::move(value)) {}
    Result(Error error) : value_(std::in_place_index<1>, std::move(error)) {}

    bool hasValue() const noexcept { return value_.index() == 0; }
    explicit operator bool() const noexcept { return hasValue(); }

    T& value() & { return std::get<0>(value_); }
    const T& value() const& { return std::get<0>(value_); }
    T&& value() && { return std::get<0>(std::move(value_)); }

    T& operator*() & { return value(); }
    const T& operator*() const& { return value(); }
    T* operator->() { return &value(); }
    const T* operator->() const { return &value(); }

    const Error& error() const& { return std::get<1>(value_); }
    Error&& error() && { return std::get<1>(std::move(value_)); }

private:
    std::variant<T, Error> value_;
};

template <>
class Result<void> {
public:
    Result() = default;
    Result(Error error) : error_(std::move(error)) {}

    bool hasValue() const noexcept { return !error_.has_value(); }
    explicit operator bool() const noexcept { return hasValue(); }

    const Error& error() const& { return *error_; }
    Error&& error() && { return std::move(*error_); }

private:
    std::optional<Error> error_;
};

} // namespace runpe

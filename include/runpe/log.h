#pragma once

namespace runpe::log {

void setVerbose(bool enabled) noexcept;
bool verbose() noexcept;

void info(const char* format, ...);
void warn(const char* format, ...);
void error(const char* format, ...);
void debug(const char* format, ...);

} // namespace runpe::log

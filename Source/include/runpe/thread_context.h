#pragma once

#include <windows.h>

#include <cstdint>

#include "runpe/arch.h"
#include "runpe/error.h"

namespace runpe {

class Process;

// Captures the entry-point register and PEB address of a suspended process.
class ThreadContext {
public:
    static Result<ThreadContext> capture(const Process& process);

    uintptr_t pebAddress() const noexcept;
    void setEntryPoint(uintptr_t entryPoint) noexcept;
    Result<void> apply(const Process& process) const;

private:
    ThreadContext() = default;

    Arch arch_{Arch::x64};
    CONTEXT x64_{};
    WOW64_CONTEXT x86_{};
};

} // namespace runpe

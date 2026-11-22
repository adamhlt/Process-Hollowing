#pragma once

#include <windows.h>

#include <cstdint>
#include <filesystem>

#include "runpe/arch.h"
#include "runpe/error.h"

namespace runpe {

// RAII wrapper around a suspended process and its main thread.
// If the process is still armed when the object is destroyed, it is terminated.
class Process {
public:
    static Result<Process> createSuspended(const std::filesystem::path& executable);

    ~Process();

    Process(Process&& other) noexcept;
    Process& operator=(Process&& other) noexcept;
    Process(const Process&) = delete;
    Process& operator=(const Process&) = delete;

    HANDLE handle() const noexcept { return process_; }
    HANDLE thread() const noexcept { return thread_; }
    Arch arch() const noexcept { return arch_; }

    Result<void> resume();
    Result<void> terminate(uint32_t exitCode);

private:
    Process(HANDLE process, HANDLE thread, Arch arch) noexcept;

    void release() noexcept;

    HANDLE process_{nullptr};
    HANDLE thread_{nullptr};
    Arch arch_{Arch::x64};
    bool armed_{true};
};

Result<Arch> detectProcessArchitecture(HANDLE process);

} // namespace runpe

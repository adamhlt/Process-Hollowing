#include "runpe/process.h"

#include <string>
#include <utility>

namespace runpe {

Result<Arch> detectProcessArchitecture(HANDLE process) {
    USHORT processMachine = 0;
    USHORT nativeMachine = 0;
    if (IsWow64Process2(process, &processMachine, &nativeMachine)) {
        if (processMachine == IMAGE_FILE_MACHINE_I386)
            return Arch::x86;
        if (processMachine == IMAGE_FILE_MACHINE_UNKNOWN &&
            nativeMachine == IMAGE_FILE_MACHINE_AMD64) {
            return Arch::x64;
        }
        return Error{"unsupported target architecture"};
    }

    // Fallback for systems without IsWow64Process2.
    BOOL wow64 = FALSE;
    if (!IsWow64Process(process, &wow64))
        return lastError("IsWow64Process");

    return wow64 ? Arch::x86 : Arch::x64;
}

Result<Process> Process::createSuspended(const std::filesystem::path& executable) {
    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);

    PROCESS_INFORMATION info{};
    std::wstring commandLine = L"\"" + executable.wstring() + L"\"";

    if (!CreateProcessW(executable.c_str(), commandLine.data(), nullptr, nullptr, FALSE,
                        CREATE_SUSPENDED, nullptr, nullptr, &startup, &info)) {
        return lastError("CreateProcessW");
    }

    auto arch = detectProcessArchitecture(info.hProcess);
    if (!arch) {
        TerminateProcess(info.hProcess, 1);
        CloseHandle(info.hThread);
        CloseHandle(info.hProcess);
        return arch.error();
    }

    return Process{info.hProcess, info.hThread, *arch};
}

Process::Process(HANDLE process, HANDLE thread, Arch arch) noexcept
    : process_(process), thread_(thread), arch_(arch) {}

Process::~Process() {
    release();
}

Process::Process(Process&& other) noexcept
    : process_(other.process_),
      thread_(other.thread_),
      arch_(other.arch_),
      armed_(other.armed_) {
    other.process_ = nullptr;
    other.thread_ = nullptr;
    other.armed_ = false;
}

Process& Process::operator=(Process&& other) noexcept {
    if (this != &other) {
        release();
        process_ = other.process_;
        thread_ = other.thread_;
        arch_ = other.arch_;
        armed_ = other.armed_;
        other.process_ = nullptr;
        other.thread_ = nullptr;
        other.armed_ = false;
    }
    return *this;
}

void Process::release() noexcept {
    if (thread_ != nullptr) {
        CloseHandle(thread_);
        thread_ = nullptr;
    }

    if (process_ != nullptr) {
        if (armed_)
            TerminateProcess(process_, 1);
        CloseHandle(process_);
        process_ = nullptr;
    }

    armed_ = false;
}

Result<void> Process::resume() {
    if (thread_ == nullptr)
        return Error{"ResumeThread: no thread handle"};

    if (ResumeThread(thread_) == static_cast<DWORD>(-1))
        return lastError("ResumeThread");

    armed_ = false;
    return {};
}

Result<void> Process::terminate(uint32_t exitCode) {
    if (process_ == nullptr)
        return {};

    if (!TerminateProcess(process_, exitCode))
        return lastError("TerminateProcess");

    armed_ = false;
    return {};
}

} // namespace runpe

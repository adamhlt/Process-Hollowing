#include "runpe/thread_context.h"

#include <utility>

#include "runpe/process.h"

namespace runpe {

Result<ThreadContext> ThreadContext::capture(const Process& process) {
    ThreadContext context;
    context.arch_ = process.arch();

    if (context.arch_ == Arch::x86) {
        context.x86_.ContextFlags = WOW64_CONTEXT_FULL;
        if (!Wow64GetThreadContext(process.thread(), &context.x86_))
            return lastError("Wow64GetThreadContext");
    } else {
        context.x64_.ContextFlags = CONTEXT_FULL;
        if (!GetThreadContext(process.thread(), &context.x64_))
            return lastError("GetThreadContext");
    }

    return std::move(context);
}

uintptr_t ThreadContext::pebAddress() const noexcept {
    return arch_ == Arch::x86 ? static_cast<uintptr_t>(x86_.Ebx)
                              : static_cast<uintptr_t>(x64_.Rdx);
}

void ThreadContext::setEntryPoint(uintptr_t entryPoint) noexcept {
    if (arch_ == Arch::x86)
        x86_.Eax = static_cast<DWORD>(entryPoint);
    else
        x64_.Rcx = static_cast<DWORD64>(entryPoint);
}

Result<void> ThreadContext::apply(const Process& process) const {
    if (arch_ == Arch::x86) {
        if (!Wow64SetThreadContext(process.thread(), &x86_))
            return lastError("Wow64SetThreadContext");
    } else {
        if (!SetThreadContext(process.thread(), &x64_))
            return lastError("SetThreadContext");
    }

    return {};
}

} // namespace runpe

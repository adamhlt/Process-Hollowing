#pragma once

#include <string>

#include "runpe/error.h"

namespace runpe {

class PeImage;
class Process;

struct InjectionOptions {
    // Path exposed to the payload through GetModuleFileNameW(NULL).
    std::wstring imagePath;
    // Full command line exposed to the payload through GetCommandLineW().
    std::wstring commandLine;
};

// Maps `image` into `target`, applies relocations if needed, updates the PEB
// (image base and process parameters) and resumes the main thread at the image
// entry point.
//
// The process parameter strings are rewritten in place in the target's existing
// RTL_USER_PROCESS_PARAMETERS. Their buffers are owned by the target's process
// heap, so they cannot be replaced with a VirtualAllocEx allocation (the loader
// would later free a non-heap pointer). When a new value does not fit in the
// existing buffer, it is left unchanged and a warning is logged.
Result<void> inject(Process& target, const PeImage& image, const InjectionOptions& options);

} // namespace runpe

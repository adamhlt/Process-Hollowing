#include <windows.h>

#include <cstdio>
#include <exception>
#include <filesystem>
#include <string>
#include <string_view>

#include "runpe/error.h"
#include "runpe/injector.h"
#include "runpe/log.h"
#include "runpe/pe_image.h"
#include "runpe/process.h"

namespace {

enum class ExitCode : int {
    Success = 0,
    Usage = 1,
    InvalidPe = 2,
    ProcessCreation = 3,
    InjectionFailed = 4,
};

void printUsage(const wchar_t* program) {
    std::printf(
        "Usage: %ls [--verbose] <pe_file> <target_process>\n"
        "\n"
        "  --verbose, -v   print detailed progress\n"
        "  --help, -h      show this help\n",
        program);
}

// Quotes an argument the same way CommandLineToArgvW parses it, so the payload
// sees the expected command line through GetCommandLineW().
std::wstring quoteArgument(const std::wstring& value) {
    if (value.find_first_of(L" \t\n\v\"") == std::wstring::npos)
        return value;

    std::wstring quoted = L"\"";

    for (auto it = value.begin();; ++it) {
        size_t backslashes = 0;
        while (it != value.end() && *it == L'\\') {
            ++it;
            ++backslashes;
        }

        if (it == value.end()) {
            quoted.append(backslashes * 2, L'\\');
            break;
        }

        if (*it == L'"')
            quoted.append(backslashes * 2 + 1, L'\\');
        else
            quoted.append(backslashes, L'\\');

        quoted.push_back(*it);
    }

    quoted.push_back(L'"');
    return quoted;
}

} // namespace

int wmain(int argc, wchar_t* argv[]) {
    SetConsoleOutputCP(CP_UTF8);

    bool verbose = false;
    std::filesystem::path source;
    std::filesystem::path target;

    for (int i = 1; i < argc; ++i) {
        const std::wstring_view arg = argv[i];

        if (arg == L"--help" || arg == L"-h") {
            printUsage(argv[0]);
            return static_cast<int>(ExitCode::Success);
        }

        if (arg == L"--verbose" || arg == L"-v") {
            verbose = true;
            continue;
        }

        if (source.empty()) {
            source = argv[i];
        } else if (target.empty()) {
            target = argv[i];
        } else {
            printUsage(argv[0]);
            return static_cast<int>(ExitCode::Usage);
        }
    }

    runpe::log::setVerbose(verbose);

    if (source.empty() || target.empty()) {
        printUsage(argv[0]);
        return static_cast<int>(ExitCode::Usage);
    }

    std::printf("[PROCESS HOLLOWING]\n");
    std::fflush(stdout);

    try {
        const std::filesystem::path sourcePath = std::filesystem::absolute(source);

        auto image = runpe::PeImage::fromFile(sourcePath);
        if (!image) {
            runpe::log::error("%s", image.error().message.c_str());
            return static_cast<int>(ExitCode::InvalidPe);
        }

        runpe::log::info("source image: %ls (%s, base 0x%llX, size 0x%X)",
                         sourcePath.c_str(),
                         runpe::toString(image->arch()),
                         static_cast<unsigned long long>(image->imageBase()),
                         static_cast<unsigned>(image->sizeOfImage()));
        runpe::log::debug("sections: %zu, relocations: %s",
                          image->sections().size(),
                          image->hasRelocations() ? "yes" : "no");

        auto process = runpe::Process::createSuspended(target);
        if (!process) {
            runpe::log::error("%s", process.error().message.c_str());
            return static_cast<int>(ExitCode::ProcessCreation);
        }

        runpe::log::info("target process created suspended (%s)",
                         runpe::toString(process->arch()));

        runpe::InjectionOptions options;
        options.imagePath = sourcePath.wstring();
        options.commandLine = quoteArgument(options.imagePath);

        auto result = runpe::inject(*process, *image, options);
        if (!result) {
            runpe::log::error("%s", result.error().message.c_str());
            return static_cast<int>(ExitCode::InjectionFailed);
        }

        runpe::log::info("injection succeeded");
        return static_cast<int>(ExitCode::Success);
    } catch (const std::exception& exception) {
        runpe::log::error("unexpected exception: %s", exception.what());
        return static_cast<int>(ExitCode::InjectionFailed);
    }
}

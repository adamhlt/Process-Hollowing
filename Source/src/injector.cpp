#include "runpe/injector.h"

#include <windows.h>
#include <winternl.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <string>

#include "runpe/log.h"
#include "runpe/pe_image.h"
#include "runpe/process.h"
#include "runpe/thread_context.h"

namespace runpe {

namespace {

constexpr uintptr_t kPebImageBaseOffsetX86 = 0x08;
constexpr uintptr_t kPebImageBaseOffsetX64 = 0x10;

constexpr uintptr_t kPebProcessParametersOffsetX86 = 0x10;
constexpr uintptr_t kPebProcessParametersOffsetX64 = 0x20;

constexpr uintptr_t kProcessParametersImagePathNameX86 = 0x38;
constexpr uintptr_t kProcessParametersImagePathNameX64 = 0x60;
constexpr uintptr_t kProcessParametersCommandLineX86 = 0x40;
constexpr uintptr_t kProcessParametersCommandLineX64 = 0x70;

uintptr_t pebImageBaseOffset(Arch arch) noexcept {
    return arch == Arch::x86 ? kPebImageBaseOffsetX86 : kPebImageBaseOffsetX64;
}

template <class T>
Result<T> readRemote(const Process& process, uintptr_t address) {
    T value{};
    SIZE_T read = 0;
    if (!ReadProcessMemory(process.handle(), reinterpret_cast<LPCVOID>(address),
                           &value, sizeof(T), &read)) {
        return lastError("ReadProcessMemory");
    }
    if (read != sizeof(T))
        return Error{"ReadProcessMemory returned a partial read"};

    return value;
}

template <class T>
Result<void> writeRemote(const Process& process, uintptr_t address, const T& value) {
    SIZE_T written = 0;
    if (!WriteProcessMemory(process.handle(), reinterpret_cast<LPVOID>(address),
                            &value, sizeof(T), &written)) {
        return lastError("WriteProcessMemory");
    }
    if (written != sizeof(T))
        return Error{"WriteProcessMemory returned a partial write"};

    return {};
}

Result<void> writeRemoteBytes(const Process& process, uintptr_t address,
                              const void* data, size_t size) {
    if (size == 0)
        return {};

    SIZE_T written = 0;
    if (!WriteProcessMemory(process.handle(), reinterpret_cast<LPVOID>(address),
                            data, size, &written)) {
        return lastError("WriteProcessMemory");
    }
    if (written != size)
        return Error{"WriteProcessMemory returned a partial write"};

    return {};
}

Result<void> zeroRemote(const Process& process, uintptr_t address, size_t size) {
    static const std::array<std::byte, 4096> zeros{};

    while (size > 0) {
        const size_t chunk = std::min(size, zeros.size());
        if (auto result = writeRemoteBytes(process, address, zeros.data(), chunk); !result)
            return result;

        address += chunk;
        size -= chunk;
    }

    return {};
}

Result<uintptr_t> readPebImageBase(const Process& process, const ThreadContext& context) {
    if (process.arch() == Arch::x86) {
        auto value = readRemote<uint32_t>(
            process, context.pebAddress() + pebImageBaseOffset(Arch::x86));
        if (!value)
            return value.error();
        return static_cast<uintptr_t>(*value);
    }

    auto value = readRemote<uint64_t>(
        process, context.pebAddress() + pebImageBaseOffset(Arch::x64));
    if (!value)
        return value.error();
    return static_cast<uintptr_t>(*value);
}

Result<void> writePebImageBase(const Process& process, const ThreadContext& context,
                               uintptr_t base) {
    if (process.arch() == Arch::x86) {
        return writeRemote<uint32_t>(process,
                                     context.pebAddress() + pebImageBaseOffset(Arch::x86),
                                     static_cast<uint32_t>(base));
    }

    return writeRemote<uint64_t>(process,
                                 context.pebAddress() + pebImageBaseOffset(Arch::x64),
                                 static_cast<uint64_t>(base));
}

Result<uintptr_t> readProcessParameters(const Process& process,
                                        const ThreadContext& context) {
    if (process.arch() == Arch::x86) {
        auto value = readRemote<uint32_t>(
            process, context.pebAddress() + kPebProcessParametersOffsetX86);
        if (!value)
            return value.error();
        return static_cast<uintptr_t>(*value);
    }

    auto value = readRemote<uint64_t>(
        process, context.pebAddress() + kPebProcessParametersOffsetX64);
    if (!value)
        return value.error();
    return static_cast<uintptr_t>(*value);
}

Result<uintptr_t> readUnicodeStringBuffer(const Process& process, uintptr_t fieldAddress) {
    if (process.arch() == Arch::x86) {
        auto value = readRemote<uint32_t>(process, fieldAddress + 4);
        if (!value)
            return value.error();
        return static_cast<uintptr_t>(*value);
    }

    auto value = readRemote<uint64_t>(process, fieldAddress + 8);
    if (!value)
        return value.error();
    return static_cast<uintptr_t>(*value);
}

struct UnicodeStringHeader {
    USHORT length;
    USHORT maximumLength;
};

// Rewrites the string in place. The buffer is owned by the target's process
// heap, so replacing it with a VirtualAllocEx allocation would make the loader
// free a non-heap pointer and crash.
Result<void> rewriteUnicodeString(const Process& process, uintptr_t fieldAddress,
                                  const std::wstring& text) {
    const size_t lengthBytes = text.size() * sizeof(wchar_t);
    if (lengthBytes + sizeof(wchar_t) > 0xFFFF)
        return Error{"process parameter string is too long"};

    auto header = readRemote<UnicodeStringHeader>(process, fieldAddress);
    if (!header || header->length > header->maximumLength)
        return Error{"PEB: unexpected RTL_USER_PROCESS_PARAMETERS layout"};

    if (lengthBytes + sizeof(wchar_t) > header->maximumLength)
        return Error{"process parameter string does not fit in the existing buffer"};

    auto buffer = readUnicodeStringBuffer(process, fieldAddress);
    if (!buffer)
        return buffer.error();
    if (*buffer == 0)
        return Error{"PEB: process parameter string has no buffer"};

    if (auto result = writeRemoteBytes(process, *buffer, text.c_str(),
                                       lengthBytes + sizeof(wchar_t)); !result) {
        return result;
    }

    const auto length = static_cast<USHORT>(lengthBytes);
    return writeRemote<UnicodeStringHeader>(
        process, fieldAddress, UnicodeStringHeader{length, header->maximumLength});
}

Result<void> rewriteProcessParameters(const Process& process, const ThreadContext& context,
                                      const InjectionOptions& options) {
    if (options.imagePath.empty() && options.commandLine.empty())
        return {};

    auto parameters = readProcessParameters(process, context);
    if (!parameters) {
        log::warn("could not read the PEB process parameters: %s",
                  parameters.error().message.c_str());
        return {};
    }

    const uintptr_t imagePathField =
        *parameters + (process.arch() == Arch::x86 ? kProcessParametersImagePathNameX86
                                                   : kProcessParametersImagePathNameX64);
    const uintptr_t commandLineField =
        *parameters + (process.arch() == Arch::x86 ? kProcessParametersCommandLineX86
                                                   : kProcessParametersCommandLineX64);

    const auto rewrite = [&](const char* name, uintptr_t field, const std::wstring& text) {
        if (text.empty())
            return;

        if (auto result = rewriteUnicodeString(process, field, text); !result) {
            log::warn("could not rewrite %s: %s", name, result.error().message.c_str());
            return;
        }

        log::debug("rewrote PEB %s", name);
    };

    rewrite("ImagePathName", imagePathField, options.imagePath);
    rewrite("CommandLine", commandLineField, options.commandLine);
    return {};
}

Result<uint16_t> readTargetSubsystem(const Process& process, uintptr_t imageBase) {
    auto dos = readRemote<IMAGE_DOS_HEADER>(process, imageBase);
    if (!dos)
        return dos.error();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return Error{"target image: missing MZ signature"};
    if (dos->e_lfanew < 0)
        return Error{"target image: negative e_lfanew"};

    const uintptr_t ntAddress = imageBase + static_cast<uintptr_t>(dos->e_lfanew);

    if (process.arch() == Arch::x86) {
        auto nt = readRemote<IMAGE_NT_HEADERS32>(process, ntAddress);
        if (!nt)
            return nt.error();
        if (nt->Signature != IMAGE_NT_SIGNATURE)
            return Error{"target image: missing PE signature"};
        return nt->OptionalHeader.Subsystem;
    }

    auto nt = readRemote<IMAGE_NT_HEADERS64>(process, ntAddress);
    if (!nt)
        return nt.error();
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return Error{"target image: missing PE signature"};
    return nt->OptionalHeader.Subsystem;
}

using NtUnmapViewOfSectionFn = NTSTATUS(NTAPI*)(HANDLE, PVOID);

NtUnmapViewOfSectionFn resolveNtUnmapViewOfSection() {
    static const NtUnmapViewOfSectionFn function = []() -> NtUnmapViewOfSectionFn {
        const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (ntdll == nullptr)
            return nullptr;
#pragma warning(suppress : 4191)
        return reinterpret_cast<NtUnmapViewOfSectionFn>(
            GetProcAddress(ntdll, "NtUnmapViewOfSection"));
    }();

    return function;
}

Result<void> unmapView(const Process& process, uintptr_t base) {
    const auto function = resolveNtUnmapViewOfSection();
    if (function == nullptr)
        return Error{"NtUnmapViewOfSection is unavailable"};

    const NTSTATUS status = function(process.handle(), reinterpret_cast<PVOID>(base));
    if (status < 0) {
        char message[64]{};
        std::snprintf(message, sizeof(message),
                      "NtUnmapViewOfSection failed (NTSTATUS 0x%08lX)",
                      static_cast<unsigned long>(status));
        return Error{message};
    }

    return {};
}

Result<uintptr_t> allocateImage(const Process& process, uintptr_t oldBase,
                                const PeImage& image) {
    const auto preferred = static_cast<uintptr_t>(image.imageBase());
    const auto size = image.sizeOfImage();

    if (auto at = VirtualAllocEx(process.handle(), reinterpret_cast<LPVOID>(preferred), size,
                                 MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)) {
        log::debug("allocated image at preferred base 0x%p", at);
        return reinterpret_cast<uintptr_t>(at);
    }

    // The preferred base is taken. If it is the target's own image, free it and
    // retry. This is skipped for WOW64 targets: unmapping the 32-bit image
    // corrupts the WOW64 loader and the payload crashes on resume, so they
    // always keep the original image and relocate instead.
    if (process.arch() != Arch::x86 && preferred == oldBase) {
        if (auto result = unmapView(process, oldBase); !result)
            return result.error();

        if (auto at = VirtualAllocEx(process.handle(), reinterpret_cast<LPVOID>(preferred),
                                     size, MEM_COMMIT | MEM_RESERVE,
                                     PAGE_EXECUTE_READWRITE)) {
            log::debug("allocated image at preferred base 0x%p after unmapping the target",
                       at);
            return reinterpret_cast<uintptr_t>(at);
        }
    }

    if (!image.hasRelocations())
        return Error{"the preferred base is unavailable and the image has no relocations"};

    auto anywhere = VirtualAllocEx(process.handle(), nullptr, size, MEM_COMMIT | MEM_RESERVE,
                                   PAGE_EXECUTE_READWRITE);
    if (anywhere == nullptr)
        return lastError("VirtualAllocEx");

    log::debug("allocated image at 0x%p (preferred base unavailable)", anywhere);
    return reinterpret_cast<uintptr_t>(anywhere);
}

Result<void> writeImage(const Process& process, const PeImage& image, uintptr_t base) {
    const uint32_t sizeOfImage = image.sizeOfImage();
    const uint32_t sizeOfHeaders = image.sizeOfHeaders();

    if (sizeOfHeaders > image.size())
        return Error{"PE: SizeOfHeaders exceeds the file size"};

    if (auto result = writeRemoteBytes(process, base, image.data(), sizeOfHeaders); !result)
        return result;

    log::debug("wrote headers (%u bytes)", static_cast<unsigned>(sizeOfHeaders));

    for (const auto& section : image.sections()) {
        const uint64_t virtualEnd =
            static_cast<uint64_t>(section.VirtualAddress) +
            std::max<uint32_t>(section.Misc.VirtualSize, section.SizeOfRawData);
        if (virtualEnd > sizeOfImage)
            return Error{"PE: section extends past SizeOfImage"};

        if (section.SizeOfRawData != 0) {
            if (section.PointerToRawData > image.size() ||
                image.size() - section.PointerToRawData < section.SizeOfRawData) {
                return Error{"PE: section raw data is out of bounds"};
            }

            if (auto result = writeRemoteBytes(process,
                                               base + section.VirtualAddress,
                                               image.data() + section.PointerToRawData,
                                               section.SizeOfRawData); !result) {
                return result;
            }
        }

        if (section.Misc.VirtualSize > section.SizeOfRawData) {
            const size_t zeroSize = section.Misc.VirtualSize - section.SizeOfRawData;
            if (auto result = zeroRemote(process,
                                         base + section.VirtualAddress + section.SizeOfRawData,
                                         zeroSize); !result) {
                return result;
            }
        }

        log::debug("mapped section %.*s (%u bytes at RVA 0x%X)",
                   static_cast<int>(IMAGE_SIZEOF_SHORT_NAME),
                   reinterpret_cast<const char*>(section.Name),
                   static_cast<unsigned>(section.SizeOfRawData),
                   static_cast<unsigned>(section.VirtualAddress));
    }

    return {};
}

Result<void> patchRemoteImageBase(const Process& process, const PeImage& image,
                                  uintptr_t base) {
    const uintptr_t fieldAddress = base + image.imageBaseFieldOffset();

    if (process.arch() == Arch::x86)
        return writeRemote<uint32_t>(process, fieldAddress, static_cast<uint32_t>(base));

    return writeRemote<uint64_t>(process, fieldAddress, static_cast<uint64_t>(base));
}

Result<void> applyRelocations(const Process& process, const PeImage& image,
                              uintptr_t base) {
    if (base == static_cast<uintptr_t>(image.imageBase()))
        return {};

    const auto& directory = image.directory(IMAGE_DIRECTORY_ENTRY_BASERELOC);
    if (directory.Size == 0)
        return {};

    const auto delta =
        static_cast<int64_t>(base) - static_cast<int64_t>(image.imageBase());
    const uint64_t sizeOfImage = image.sizeOfImage();

    uint32_t offset = 0;
    while (offset < directory.Size) {
        if (directory.Size - offset < sizeof(IMAGE_BASE_RELOCATION))
            return Error{"PE: truncated relocation block"};

        const uint32_t blockRva = directory.VirtualAddress + offset;
        const auto blockOffset = image.rvaToOffset(blockRva);
        if (!blockOffset)
            return Error{"PE: relocation block is out of bounds"};

        const auto* block = image.at<IMAGE_BASE_RELOCATION>(blockRva);
        if (block == nullptr)
            return Error{"PE: relocation block is out of bounds"};
        if (block->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION))
            return Error{"PE: invalid relocation block size"};
        if (block->SizeOfBlock > directory.Size - offset)
            return Error{"PE: relocation block exceeds the directory"};
        if (*blockOffset > image.size() ||
            image.size() - *blockOffset < block->SizeOfBlock) {
            return Error{"PE: relocation block is out of bounds"};
        }

        const uint32_t entryCount =
            (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);
        const auto* entries = reinterpret_cast<const uint16_t*>(block + 1);

        for (uint32_t i = 0; i < entryCount; ++i) {
            const uint16_t type = entries[i] >> 12;
            const uint16_t sectionOffset = entries[i] & 0x0FFF;
            if (type == IMAGE_REL_BASED_ABSOLUTE)
                continue;

            const uint64_t targetRva =
                static_cast<uint64_t>(block->VirtualAddress) + sectionOffset;
            const uint64_t width = type == IMAGE_REL_BASED_DIR64 ? 8 : 4;
            if (targetRva + width > sizeOfImage)
                return Error{"PE: relocation target is out of bounds"};

            const auto address = base + static_cast<uintptr_t>(targetRva);

            switch (type) {
            case IMAGE_REL_BASED_HIGHLOW: {
                auto value = readRemote<uint32_t>(process, address);
                if (!value)
                    return value.error();
                if (auto result = writeRemote<uint32_t>(
                        process, address, static_cast<uint32_t>(*value + delta));
                    !result) {
                    return result;
                }
                break;
            }
            case IMAGE_REL_BASED_DIR64: {
                auto value = readRemote<uint64_t>(process, address);
                if (!value)
                    return value.error();
                if (auto result = writeRemote<uint64_t>(
                        process, address, static_cast<uint64_t>(*value + delta));
                    !result) {
                    return result;
                }
                break;
            }
            default:
                return Error{"PE: unsupported relocation type"};
            }
        }

        offset += block->SizeOfBlock;
    }

    log::debug("applied relocations (delta 0x%llX)",
               static_cast<unsigned long long>(delta));
    return {};
}

DWORD sectionProtection(const IMAGE_SECTION_HEADER& section) noexcept {
    const DWORD characteristics = section.Characteristics;
    const bool executable = (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    const bool readable = (characteristics & IMAGE_SCN_MEM_READ) != 0;
    const bool writable = (characteristics & IMAGE_SCN_MEM_WRITE) != 0;

    if (executable && writable)
        return PAGE_EXECUTE_READWRITE;
    if (executable && readable)
        return PAGE_EXECUTE_READ;
    if (executable)
        return PAGE_EXECUTE;
    if (writable)
        return PAGE_READWRITE;
    if (readable)
        return PAGE_READONLY;

    return PAGE_NOACCESS;
}

Result<void> protectImage(const Process& process, const PeImage& image, uintptr_t base) {
    for (const auto& section : image.sections()) {
        const auto size =
            std::max<uint32_t>(section.Misc.VirtualSize, section.SizeOfRawData);
        if (size == 0)
            continue;

        DWORD oldProtection = 0;
        if (!VirtualProtectEx(process.handle(),
                              reinterpret_cast<LPVOID>(base + section.VirtualAddress),
                              size, sectionProtection(section), &oldProtection)) {
            return lastError("VirtualProtectEx");
        }
    }

    const DWORD headerProtection =
        image.entryPointRva() < image.sizeOfHeaders() ? PAGE_EXECUTE_READ : PAGE_READONLY;

    DWORD oldProtection = 0;
    if (!VirtualProtectEx(process.handle(), reinterpret_cast<LPVOID>(base),
                          image.sizeOfHeaders(), headerProtection, &oldProtection)) {
        return lastError("VirtualProtectEx (headers)");
    }

    return {};
}

} // namespace

Result<void> inject(Process& target, const PeImage& image, const InjectionOptions& options) {
    if (target.arch() != image.arch()) {
        return Error{std::string("architecture mismatch: image is ") + toString(image.arch()) +
                     ", target is " + toString(target.arch())};
    }

    auto context = ThreadContext::capture(target);
    if (!context)
        return context.error();

    auto oldBase = readPebImageBase(target, *context);
    if (!oldBase)
        return oldBase.error();

    log::debug("PEB: 0x%p, current image base: 0x%p",
               reinterpret_cast<void*>(context->pebAddress()),
               reinterpret_cast<void*>(*oldBase));

    if (auto subsystem = readTargetSubsystem(target, *oldBase)) {
        if (*subsystem != image.subsystem()) {
            log::warn("subsystem mismatch (image 0x%X, target 0x%X); continuing anyway",
                      static_cast<unsigned>(image.subsystem()),
                      static_cast<unsigned>(*subsystem));
        }
    } else {
        log::warn("could not read the target subsystem: %s",
                  subsystem.error().message.c_str());
    }

    auto base = allocateImage(target, *oldBase, image);
    if (!base)
        return base.error();

    if (auto result = writeImage(target, image, *base); !result)
        return result;

    if (auto result = patchRemoteImageBase(target, image, *base); !result)
        return result;

    if (auto result = applyRelocations(target, image, *base); !result)
        return result;

    if (auto result = writePebImageBase(target, *context, *base); !result)
        return result;

    if (auto result = rewriteProcessParameters(target, *context, options); !result)
        return result;

    if (auto result = protectImage(target, image, *base); !result)
        return result;

    if (image.entryPointRva() >= image.sizeOfImage())
        return Error{"PE: entry point is out of bounds"};

    const uintptr_t entryPoint = *base + image.entryPointRva();
    context->setEntryPoint(entryPoint);

    if (auto result = context->apply(target); !result)
        return result;

    log::info("image mapped at 0x%p (entry point 0x%p)",
              reinterpret_cast<void*>(*base), reinterpret_cast<void*>(entryPoint));

    return target.resume();
}

} // namespace runpe

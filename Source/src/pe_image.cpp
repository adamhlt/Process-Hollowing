#include "runpe/pe_image.h"

#include <algorithm>
#include <utility>

namespace runpe {

namespace {

constexpr WORD kMaxSections = 96;

} // namespace

Result<PeImage> PeImage::fromFile(const std::filesystem::path& path) {
    const HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE)
        return lastError("CreateFileW");

    LARGE_INTEGER fileSize{};
    if (!GetFileSizeEx(file, &fileSize)) {
        const Error error = lastError("GetFileSizeEx");
        CloseHandle(file);
        return error;
    }

    constexpr LONGLONG kMaxPeSize = 0xFFFFFFFFll;
    if (fileSize.QuadPart <= 0 || fileSize.QuadPart > kMaxPeSize) {
        CloseHandle(file);
        return Error{"PE: unsupported file size"};
    }

    std::vector<std::byte> bytes(static_cast<size_t>(fileSize.QuadPart));
    size_t totalRead = 0;
    while (totalRead < bytes.size()) {
        const DWORD chunk = static_cast<DWORD>(
            std::min<size_t>(bytes.size() - totalRead, 1u << 20));
        DWORD read = 0;
        if (!ReadFile(file, bytes.data() + totalRead, chunk, &read, nullptr)) {
            const Error error = lastError("ReadFile");
            CloseHandle(file);
            return error;
        }
        if (read == 0) {
            CloseHandle(file);
            return Error{"PE: unexpected end of file"};
        }
        totalRead += read;
    }

    CloseHandle(file);
    return fromMemory(std::move(bytes));
}

Result<PeImage> PeImage::fromMemory(std::vector<std::byte> bytes) {
    PeImage image;
    image.bytes_ = std::move(bytes);

    const size_t size = image.bytes_.size();
    if (size < sizeof(IMAGE_DOS_HEADER))
        return Error{"PE: file is smaller than a DOS header"};

    image.dos_ = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.bytes_.data());
    if (image.dos_->e_magic != IMAGE_DOS_SIGNATURE)
        return Error{"PE: missing MZ signature"};

    if (image.dos_->e_lfanew < 0)
        return Error{"PE: negative e_lfanew"};

    const auto ntOffset = static_cast<size_t>(image.dos_->e_lfanew);
    if (ntOffset > size || size - ntOffset < sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER))
        return Error{"PE: e_lfanew is out of bounds"};

    const DWORD signature = *reinterpret_cast<const DWORD*>(image.bytes_.data() + ntOffset);
    if (signature != IMAGE_NT_SIGNATURE)
        return Error{"PE: missing PE signature"};

    image.file_ = reinterpret_cast<const IMAGE_FILE_HEADER*>(
        image.bytes_.data() + ntOffset + sizeof(DWORD));

    const size_t optionalOffset = ntOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    if (image.file_->SizeOfOptionalHeader < sizeof(WORD) ||
        size - optionalOffset < image.file_->SizeOfOptionalHeader) {
        return Error{"PE: optional header is truncated"};
    }

    const WORD magic = *reinterpret_cast<const WORD*>(image.bytes_.data() + optionalOffset);
    if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        if (image.file_->SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER32))
            return Error{"PE: 32-bit optional header is too small"};
        image.arch_ = Arch::x86;
    } else if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if (image.file_->SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64))
            return Error{"PE: 64-bit optional header is too small"};
        image.arch_ = Arch::x64;
    } else {
        return Error{"PE: unknown optional header magic"};
    }

    image.optional_ = image.bytes_.data() + optionalOffset;
    image.optionalOffset_ = optionalOffset;

    if (image.file_->NumberOfSections == 0)
        return Error{"PE: no sections"};
    if (image.file_->NumberOfSections > kMaxSections)
        return Error{"PE: too many sections"};

    const size_t sectionOffset = optionalOffset + image.file_->SizeOfOptionalHeader;
    const size_t sectionBytes =
        static_cast<size_t>(image.file_->NumberOfSections) * sizeof(IMAGE_SECTION_HEADER);
    if (sectionOffset > size || size - sectionOffset < sectionBytes)
        return Error{"PE: section table is out of bounds"};

    image.sections_ = std::span<const IMAGE_SECTION_HEADER>(
        reinterpret_cast<const IMAGE_SECTION_HEADER*>(image.bytes_.data() + sectionOffset),
        image.file_->NumberOfSections);

    const uint32_t sizeOfImage = image.sizeOfImage();
    const uint32_t sizeOfHeaders = image.sizeOfHeaders();
    if (sizeOfImage == 0 || sizeOfHeaders == 0 || sizeOfHeaders > sizeOfImage)
        return Error{"PE: invalid image or headers size"};

    for (const auto& section : image.sections_) {
        const uint64_t end = static_cast<uint64_t>(section.VirtualAddress) +
                             std::max<uint32_t>(section.Misc.VirtualSize, section.SizeOfRawData);
        if (end > sizeOfImage)
            return Error{"PE: section extends past SizeOfImage"};

        if (section.SizeOfRawData != 0 &&
            (section.PointerToRawData > size ||
             size - section.PointerToRawData < section.SizeOfRawData)) {
            return Error{"PE: section raw data is out of bounds"};
        }
    }

    for (size_t i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; ++i) {
        // The security directory stores a file offset, not an RVA.
        if (i == IMAGE_DIRECTORY_ENTRY_SECURITY)
            continue;

        const auto& entry = image.directory(i);
        if (entry.VirtualAddress == 0)
            continue;
        if (entry.VirtualAddress >= sizeOfImage ||
            entry.Size > sizeOfImage - entry.VirtualAddress) {
            return Error{"PE: data directory is out of bounds"};
        }
    }

    return std::move(image);
}

const IMAGE_OPTIONAL_HEADER32* PeImage::optional32() const noexcept {
    return reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(optional_);
}

const IMAGE_OPTIONAL_HEADER64* PeImage::optional64() const noexcept {
    return reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(optional_);
}

uint64_t PeImage::imageBase() const noexcept {
    return arch_ == Arch::x64 ? optional64()->ImageBase : optional32()->ImageBase;
}

uint32_t PeImage::sizeOfImage() const noexcept {
    return arch_ == Arch::x64 ? optional64()->SizeOfImage : optional32()->SizeOfImage;
}

uint32_t PeImage::sizeOfHeaders() const noexcept {
    return arch_ == Arch::x64 ? optional64()->SizeOfHeaders : optional32()->SizeOfHeaders;
}

uint32_t PeImage::entryPointRva() const noexcept {
    return arch_ == Arch::x64 ? optional64()->AddressOfEntryPoint
                              : optional32()->AddressOfEntryPoint;
}

uint16_t PeImage::subsystem() const noexcept {
    return arch_ == Arch::x64 ? optional64()->Subsystem : optional32()->Subsystem;
}

bool PeImage::hasRelocations() const noexcept {
    const auto& reloc = directory(IMAGE_DIRECTORY_ENTRY_BASERELOC);
    return reloc.VirtualAddress != 0 && reloc.Size != 0;
}

const IMAGE_DATA_DIRECTORY& PeImage::directory(size_t index) const noexcept {
    static const IMAGE_DATA_DIRECTORY empty{};
    if (index >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
        return empty;

    return arch_ == Arch::x64 ? optional64()->DataDirectory[index]
                              : optional32()->DataDirectory[index];
}

bool PeImage::containsRva(uint32_t rva, size_t length) const noexcept {
    if (length == 0)
        return true;

    const uint64_t last = static_cast<uint64_t>(rva) + length - 1;
    if (last > 0xFFFFFFFFull)
        return false;

    return rvaToOffset(rva).has_value() &&
           rvaToOffset(static_cast<uint32_t>(last)).has_value();
}

std::optional<size_t> PeImage::rvaToOffset(uint32_t rva) const noexcept {
    if (rva < sizeOfHeaders()) {
        if (rva < bytes_.size())
            return static_cast<size_t>(rva);
        return std::nullopt;
    }

    for (const auto& section : sections_) {
        const uint64_t start = section.VirtualAddress;
        const uint64_t span =
            std::max<uint32_t>(section.Misc.VirtualSize, section.SizeOfRawData);
        if (rva < start || rva >= start + span)
            continue;

        const uint64_t delta = rva - start;
        if (delta >= section.SizeOfRawData)
            return std::nullopt; // zero-filled region, not backed by the file

        const uint64_t offset = static_cast<uint64_t>(section.PointerToRawData) + delta;
        if (offset >= bytes_.size())
            return std::nullopt;

        return static_cast<size_t>(offset);
    }

    return std::nullopt;
}

size_t PeImage::imageBaseFieldOffset() const noexcept {
    return optionalOffset_ +
           (arch_ == Arch::x64 ? offsetof(IMAGE_OPTIONAL_HEADER64, ImageBase)
                               : offsetof(IMAGE_OPTIONAL_HEADER32, ImageBase));
}

} // namespace runpe

#pragma once

#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <vector>

#include "runpe/arch.h"
#include "runpe/error.h"

namespace runpe {

// Owns the bytes of a PE file and exposes a bounds-checked view over its headers.
class PeImage {
public:
    static Result<PeImage> fromFile(const std::filesystem::path& path);
    static Result<PeImage> fromMemory(std::vector<std::byte> bytes);

    PeImage(PeImage&&) noexcept = default;
    PeImage& operator=(PeImage&&) noexcept = default;
    PeImage(const PeImage&) = delete;
    PeImage& operator=(const PeImage&) = delete;

    Arch arch() const noexcept { return arch_; }
    uint64_t imageBase() const noexcept;
    uint32_t sizeOfImage() const noexcept;
    uint32_t sizeOfHeaders() const noexcept;
    uint32_t entryPointRva() const noexcept;
    uint16_t subsystem() const noexcept;
    bool hasRelocations() const noexcept;

    std::span<const IMAGE_SECTION_HEADER> sections() const noexcept { return sections_; }
    const IMAGE_DATA_DIRECTORY& directory(size_t index) const noexcept;

    // Returns true when [rva, rva + length) is entirely backed by file bytes.
    bool containsRva(uint32_t rva, size_t length) const noexcept;

    // Maps an RVA to a file offset. Returns nullopt for BSS-like or out-of-range RVAs.
    std::optional<size_t> rvaToOffset(uint32_t rva) const noexcept;

    template <class T>
    const T* at(uint32_t rva) const noexcept {
        const auto offset = rvaToOffset(rva);
        if (!offset || bytes_.size() - *offset < sizeof(T))
            return nullptr;
        return reinterpret_cast<const T*>(bytes_.data() + *offset);
    }

    // File offset of the OptionalHeader.ImageBase field, used to patch the mapped headers.
    size_t imageBaseFieldOffset() const noexcept;

    const std::byte* data() const noexcept { return bytes_.data(); }
    size_t size() const noexcept { return bytes_.size(); }

private:
    PeImage() = default;

    const IMAGE_OPTIONAL_HEADER32* optional32() const noexcept;
    const IMAGE_OPTIONAL_HEADER64* optional64() const noexcept;

    std::vector<std::byte> bytes_;
    const IMAGE_DOS_HEADER* dos_{};
    const IMAGE_FILE_HEADER* file_{};
    const void* optional_{};
    size_t optionalOffset_{};
    std::span<const IMAGE_SECTION_HEADER> sections_{};
    Arch arch_{Arch::x64};
};

} // namespace runpe

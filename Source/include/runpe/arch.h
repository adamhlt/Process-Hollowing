#pragma once

namespace runpe {

enum class Arch {
    x86,
    x64,
};

constexpr const char* toString(Arch arch) noexcept {
    return arch == Arch::x86 ? "x86" : "x64";
}

} // namespace runpe

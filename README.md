<div align="center">

# Process Hollowing

**Process hollowing in C++, PE image replacement (x86 / x64)**

![Language](https://img.shields.io/badge/C%2B%2B-16171C?logo=cplusplus)
![Platform](https://img.shields.io/badge/Windows-16171C)
![Arch](https://img.shields.io/badge/x86%20%7C%20x64-16171C)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-16171C)](LICENSE)

</div>

---

Process Hollowing replaces the PE image of a legitimately started process with another one, without ever letting the original entry point run. The loader is an x64 executable that can inject into both x86 and x64 target processes.

If you don't know how the PE format is structured, take a look at this [project](https://github.com/adamhlt/PE-Explorer).

### Example
https://user-images.githubusercontent.com/48086737/158390795-e7371e21-b475-481e-ba9a-f1b646ee5cfc.mp4

## Features

**Checks performed before mapping**
- The PE image has a valid signature
- The target process and the PE image share the same architecture
- The PE image has a relocation table (otherwise its preferred image base must be free)
- The target subsystem matches (a mismatch is only reported as a warning)

**Mapping**
- Supports PE images with and without a relocation table
- An image with no relocation table is mapped at its preferred base address

**PEB rewrite**
- `ImagePathName` and `CommandLine` are rewritten in the target's PEB before the main thread is resumed, so the payload does not inherit the target's command line (`GetCommandLineW`) or image path (`GetModuleFileNameW`)
- The strings are rewritten in place: the rewrite only happens when the new value fits in the existing buffer, otherwise a warning is logged and the original value is kept

## Usage

```shell
runpe.exe [--verbose] <source image> <target process>
```

- `--verbose`, `-v`: print detailed progress.
- `--help`, `-h`: show the help.

### Project layout

```
Source/
├── include/runpe/   # public interfaces
└── src/             # implementation
```

## Build

> [!WARNING]
> This is an **x64 executable**: you cannot compile the loader itself in x86. It is designed to inject into both x86 and x64 processes.

1. Open `Source/Process Hollowing.sln`.
2. Build the project in Release (x64).

## License

This project is licensed under the [GNU GPLv3](LICENSE).

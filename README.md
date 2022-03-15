![Banner](https://github.com/adamhlt/Process-Hollowing/blob/main/Ressources/banner.png)

# Process Hollowing

 [![C++](https://img.shields.io/badge/language-C%2B%2B-%23f34b7d.svg?style=for-the-badge&logo=appveyor)](https://en.wikipedia.org/wiki/C%2B%2B) [![Windows](https://img.shields.io/badge/platform-Windows-0078d7.svg?style=for-the-badge&logo=appveyor)](https://en.wikipedia.org/wiki/Microsoft_Windows) [![x64](https://img.shields.io/badge/arch-x64-green.svg?style=for-the-badge&logo=appveyor)](https://en.wikipedia.org/wiki/X64)

## :open_book: Project Overview :

This process hollowing implementation is written in C++, the loader is a x64 executable with can inject into x86 and x64 processes.

The loader make severals checks before trying to inject the new PE image.

- Check if the PE image have a valid signature.
- Check if the target process and the PE image have the same architecture.
- Check if the target process and the PE image have the same subsystem.
- Check if the PE image have a relocation table.

The loader is able to inject PE image with and witout relocation table, if there is no relocation table the loader try to allocate memory at the preferred image base address.

If you don't know how PE format are structured you can look at this [project](https://github.com/adamhlt/PE-Explorer).

## :rocket: Getting Started :

This is a **x64 executable**, you can't compile this project in x86, this loader is made to inject into x86 and x64 processes.
You can easily make a x86 process hollowing program based on this repository.

### Visual Studio :

1. Open the solution file (.sln).
2. Build the project in Release (x64)

### Other IDE using CMAKE :

This **CMakeLists.txt** should compile the project.

```cmake
cmake_minimum_required(VERSION 3.0)
project(runpe)

set(CMAKE_CXX_STANDARD 17)

add_executable(runpe Process_Hollowing.cpp)
```

Tested on CLion with MSVC compiler, you can get Visual Studio Build Tools [**here**](https://visualstudio.microsoft.com/fr/downloads/?q=build+tools).

## 🧪 Usage :

### How to use the program :

Use it in the command line :

```shell
runpe.exe <source image> <target process>
```

### Demonstration :
https://user-images.githubusercontent.com/48086737/158390795-e7371e21-b475-481e-ba9a-f1b646ee5cfc.mp4

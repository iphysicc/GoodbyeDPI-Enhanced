# Build Instructions

For complete build instructions, platform-specific setup, and usage documentation, see the main [README.md](README.md#building-from-source).

## Quick Reference

```bash
# All platforms
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .

# Linux dependencies
sudo apt install cmake libnetfilter-queue-dev

# macOS dependencies
brew install cmake

# Windows (legacy Makefile)
cd src && make CPREFIX=x86_64-w64-mingw32- BIT64=1 \
    WINDIVERTHEADERS=../WinDivert/include \
    WINDIVERTLIBS=../WinDivert/x64
```

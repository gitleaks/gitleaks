# C smoke test

This is a tiny C program that calls the exported C API from `libgitleaks`.

## Build prerequisites

- Go toolchain with CGO enabled (plus a C compiler for your platform)
- The shared library built from `./cgo` (see `build-scripts/` scripts)

## Example commands

### Linux

```bash
./build-scripts/build-linux.sh
gcc -I./cgo -L./build/out/linux-amd64 -Wl,-rpath,'$ORIGIN' cgo/test/main.c -lgitleaks -o build/out/linux-amd64/cgo-test
./build/out/linux-amd64/cgo-test
```

### macOS

```bash
./build-scripts/build-darwin.sh arm64
clang -I./cgo -L./build/out/darwin-arm64 cgo/test/main.c -lgitleaks -o build/out/darwin-arm64/cgo-test
DYLD_LIBRARY_PATH=./build/out/darwin-arm64 ./build/out/darwin-arm64/cgo-test
```

### Windows (MinGW)

```bash
./build-scripts/build-windows.sh
gcc -I./cgo -L./build/out/windows-amd64 cgo/test/main.c -lgitleaks -o build/out/windows-amd64/cgo-test.exe
./build/out/windows-amd64/cgo-test.exe
```



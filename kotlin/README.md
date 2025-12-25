# Kotlin interop wrapper

This Gradle module provides Kotlin Multiplatform bindings over the Go `libgitleaks` shared library.

High-level flow:

1. Build the shared library from the repo root (see `build-scripts/` scripts).
2. Configure Kotlin/Native `cinterop` to use the C header and link the produced library.
3. Implement `IMatcher` from `org.angryscan:core` using the native calls.



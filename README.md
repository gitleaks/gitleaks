# angryscan-gitleaks

Kotlin Multiplatform library providing bindings for the [Gitleaks](https://github.com/gitleaks/gitleaks) secret detection engine.

> **Note:** This library is a Kotlin wrapper around the original [Gitleaks](https://github.com/gitleaks/gitleaks) project. For the original Go-based CLI tool and documentation, please visit the [official Gitleaks repository](https://github.com/gitleaks/gitleaks).

## Overview

`angryscan-gitleaks` provides Kotlin Multiplatform bindings over the Go `libgitleaks` shared library. It implements the `IMatcher` interface from `org.angryscan:core`, allowing you to use Gitleaks' powerful secret detection capabilities in your Kotlin/JVM applications.

The library uses JNA (Java Native Access) to load and interact with the native `libgitleaks` shared library, which is built from the Go source code in this repository.

## Features

- **Kotlin Multiplatform Support**: Currently supports JVM target (Native targets coming soon)
- **Default and Custom Configurations**: Use Gitleaks' default detection rules or provide your own TOML configuration
- **Seamless Integration**: Implements `org.angryscan:core` `IMatcher` interface for easy integration
- **Cross-Platform Native Libraries**: Bundled native libraries for Windows, Linux, and macOS (x86-64 and ARM64)

## Installation

### Gradle (Kotlin DSL)

```kotlin
dependencies {
    implementation("org.angryscan:gitleaks:0.1.0")
}
```

### Gradle (Groovy)

```groovy
dependencies {
    implementation 'org.angryscan:gitleaks:0.1.0'
}
```

### Maven

```xml
<dependency>
    <groupId>org.angryscan</groupId>
    <artifactId>gitleaks</artifactId>
    <version>0.1.0</version>
</dependency>
```

## Usage

### Basic Usage

```kotlin
import org.angryscan.gitleaks.matcher.GitleaksMatcher

// Initialize the matcher with default Gitleaks configuration
GitleaksMatcher.init(useDefaultConfig = true)

try {
    // Scan text for secrets
    val text = "GITHUB_TOKEN=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"
    val matches = GitleaksMatcher.scan(text)
    
    matches.forEach { match ->
        println("Found secret: ${match.value}")
        println("Position: ${match.startPosition}-${match.endPosition}")
        println("Context: ...${match.before}${match.value}${match.after}...")
    }
} finally {
    // Clean up resources
    GitleaksMatcher.close()
}
```

### Custom Configuration

```kotlin
import org.angryscan.gitleaks.matcher.GitleaksMatcher

// Define custom detection rules
val customConfig = """
    [[rules]]
    id = 'custom-api-key'
    description = 'Custom API Key Pattern'
    regex = '''api_key_[A-Z0-9]{32}'''
""".trimIndent()

// Initialize with custom configuration
GitleaksMatcher.init(useDefaultConfig = false, configToml = customConfig)

try {
    val text = "api_key_ABCD1234EFGH5678IJKL9012MNOP3456"
    val matches = GitleaksMatcher.scan(text)
    // Process matches...
} finally {
    GitleaksMatcher.close()
}
```

### Integration with angryscan-core

```kotlin
import org.angryscan.common.engine.IMatcher
import org.angryscan.gitleaks.matcher.GitleaksMatcher

// GitleaksMatcher implements IMatcher from org.angryscan:core
val matcher: IMatcher = GitleaksMatcher

// Initialize before use
GitleaksMatcher.init(useDefaultConfig = true)

try {
    // Use with angryscan-core engine
    val matches = matcher.scan("Your text to scan here")
    // Process matches...
} finally {
    GitleaksMatcher.close()
}
```

## Requirements

- **Java**: JDK 8 or higher
- **Native Libraries**: The library includes bundled native libraries for supported platforms. For custom builds, you may need to build the native `libgitleaks` library from the Go source code.

## Building from Source

To build the library from source:

1. **Build the native library** (required):
   ```bash
   # For your platform
   bash build-scripts/build-linux.sh      # Linux
   bash build-scripts/build-windows.sh    # Windows
   bash build-scripts/build-darwin.sh     # macOS
   
   # Or build all platforms
   bash build-scripts/build-all.sh
   ```

2. **Build the Kotlin library**:
   ```bash
   cd kotlin
   ./gradlew build
   ```

3. **Run tests**:
   ```bash
   cd kotlin
   ./gradlew test
   ```

## Architecture

The library follows this high-level architecture:

1. **Native Library**: The Go `libgitleaks` shared library (`libgitleaks.so`/`.dll`/`.dylib`) provides the core detection engine
2. **JNA Bridge**: JVM implementation uses JNA to load and call native functions
3. **Kotlin API**: `GitleaksMatcher` provides a clean Kotlin API implementing `IMatcher`
4. **Resource Bundling**: Native libraries are bundled in JAR resources for cross-platform support

## Configuration

The library supports both default and custom Gitleaks configurations:

- **Default Configuration**: Uses Gitleaks' built-in detection rules for common secrets (API keys, tokens, passwords, etc.)
- **Custom Configuration**: Provide your own TOML configuration file with custom rules

For more information about Gitleaks configuration format, see the [official Gitleaks documentation](https://github.com/gitleaks/gitleaks#configuration).

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Related Projects

- **[Gitleaks](https://github.com/gitleaks/gitleaks)**: The original Go-based secret detection tool
- **[angryscan-core](https://github.com/angryscan/angryscan-core)**: Core scanning engine interface

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Support

For issues related to:
- **This Kotlin library**: Please open an issue in this repository
- **Gitleaks detection engine**: Please refer to the [official Gitleaks repository](https://github.com/gitleaks/gitleaks)

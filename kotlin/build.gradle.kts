import org.gradle.api.tasks.Copy
import org.gradle.language.jvm.tasks.ProcessResources
import java.io.File

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.maven.publish)
}

group = project.properties["group"] as String
version = project.properties["version"] as String

repositories {
    mavenCentral()
}

kotlin {
    compilerOptions.freeCompilerArgs.add("-Xexpect-actual-classes")
    
    jvm()

    // Native targets temporarily disabled - need to prepare angryscan-core first
    // TODO: Re-enable Native targets after angryscan-core supports all Native platforms
    // mingwX64()
    // linuxX64()
    // macosX64()
    // macosArm64()

    sourceSets {
        @Suppress("unused")
        val commonMain by getting {
            dependencies {
                api(libs.angryscan.core)
                implementation(libs.kotlinx.serialization)
            }
        }
        @Suppress("unused")
        val jvmMain by getting {
            dependencies {
                // JNA is used to load libgitleaks shared library at runtime
                // The library (libgitleaks.so/.dll/.dylib) must be built from Go code
                // and available in java.library.path or system library path
                // Using 'api' instead of 'implementation' to make it a transitive dependency
                // so users don't need to manually add JNA
                api(libs.jna)
            }
        }
        @Suppress("unused")
        val commonTest by getting {
            dependencies {
                implementation(kotlin("test"))
            }
        }

        // Native source sets temporarily disabled
        // val nativeMain by creating {
        //     dependsOn(commonMain)
        // }
        // val nativeTest by creating {
        //     dependsOn(commonTest)
        // }
    }

    // Native target configuration temporarily disabled
    // targets.withType<KotlinNativeTarget>().configureEach { ...     }
}

// Task to copy native libraries into JAR resources for cross-platform support.
// JNA can extract bundled libraries from the classpath when they are located at:
//   <os-arch>/<library-file>
// Example: win32-x86-64/libgitleaks.dll
val copyNativeLibraries = tasks.register<Copy>("copyNativeLibraries") {
    val repoRoot = projectDir.parentFile
    val resourcesDir = sourceSets.getByName("jvmMain").resources.srcDirs.first()
    val nativeResourcesDir = File(resourcesDir, "")
    
    data class NativeLibrary(
        val platformDir: String,
        val libName: String,
        val jnaPaths: List<String>
    )

    // Define required native libraries with their source paths and target JNA paths.
    // JNA uses OS-ARCH directory names like: win32-x86-64, win32-aarch64, linux-x86-64, linux-aarch64, darwin-x86-64, darwin-aarch64.
    val requiredLibraries = listOf(
        NativeLibrary("windows-amd64", "libgitleaks.dll", listOf("win32-x86-64")),
        NativeLibrary("windows-arm64", "libgitleaks.dll", listOf("win32-aarch64")),
        NativeLibrary("linux-amd64", "libgitleaks.so", listOf("linux-x86-64")),
        NativeLibrary("linux-arm64", "libgitleaks.so", listOf("linux-aarch64")),
        NativeLibrary("darwin-amd64", "libgitleaks.dylib", listOf("darwin-x86-64")),
        NativeLibrary("darwin-arm64", "libgitleaks.dylib", listOf("darwin-aarch64"))
    )
    
    val skipCheck = project.findProperty("skipNativeLibraryCheck")?.toString() == "true"
    
    // Copy available libraries to the correct JNA resource structure (<os-arch>/<lib>)
    into(nativeResourcesDir)
    
    requiredLibraries.forEach { lib ->
        val sourceFile = File(repoRoot, "build/out/${lib.platformDir}/${lib.libName}")
        if (!sourceFile.exists()) return@forEach
        lib.jnaPaths.forEach { jnaPath ->
            from(sourceFile) {
                into(jnaPath)
            }
        }
    }
    
    // Ensure output directory exists and check for missing libraries
    doFirst {
        nativeResourcesDir.mkdirs()

        // Clean up previously generated locations to avoid duplicating native libs in the JAR.
        // We only keep "<os-arch>/<lib>" (e.g. win32-x86-64/libgitleaks.dll).
        val generatedDirs = listOf(
            "win32-x86-64",
            "win32-aarch64",
            "linux-x86-64",
            "linux-aarch64",
            "darwin-x86-64",
            "darwin-aarch64",
            "META-INF/native"
        )
        generatedDirs.forEach { rel ->
            val dir = File(resourcesDir, rel)
            if (dir.exists()) {
                dir.deleteRecursively()
            }
        }
        
        // Check for missing libraries if check is enabled
        if (!skipCheck) {
            val missingLibraries = mutableListOf<String>()
            requiredLibraries.forEach { lib ->
                val sourceFile = File(repoRoot, "build/out/${lib.platformDir}/${lib.libName}")
                if (!sourceFile.exists()) {
                    missingLibraries.add("  - ${lib.platformDir}/${lib.libName}")
                }
            }
            
            if (missingLibraries.isNotEmpty()) {
                logger.warn(
                    "WARNING: Some native libraries are missing:\n" +
                    missingLibraries.joinToString("\n") + "\n" +
                    "The JAR will be built with only available libraries.\n" +
                    "To build all libraries, run: bash build-scripts/build-all.sh\n" +
                    "To skip this check, use: -PskipNativeLibraryCheck=true"
                )
            }
        }
        
        // Log copied libraries
        requiredLibraries.forEach { lib ->
            val sourceFile = File(repoRoot, "build/out/${lib.platformDir}/${lib.libName}")
            if (sourceFile.exists()) {
                val paths = lib.jnaPaths.joinToString(", ")
                logger.info("Copying native library: ${lib.platformDir}/${lib.libName} -> $paths/${lib.libName}")
            } else if (!skipCheck) {
                logger.debug("Skipping missing library: ${lib.platformDir}/${lib.libName}")
            }
        }
    }
}

// Make jvmJar depend on copyNativeLibraries to ensure native libraries are included
tasks.named<org.gradle.jvm.tasks.Jar>("jvmJar") {
    dependsOn(copyNativeLibraries)
}

// Gradle validation: jvmProcessResources reads from the same resources dir that copyNativeLibraries writes into.
// Declare the dependency explicitly to avoid ordering issues.
tasks.named<ProcessResources>("jvmProcessResources") {
    dependsOn(copyNativeLibraries)
}

// Configure JVM tests to have access to native library
tasks.named<Test>("jvmTest") {
    // Add library path to JVM system properties for tests
    val repoRoot = projectDir.parentFile
    val osName = System.getProperty("os.name", "").lowercase()
    val osArch = System.getProperty("os.arch", "").lowercase()
    val libDir = when {
        osName.startsWith("windows") -> {
            if (osArch == "aarch64" || osArch == "arm64") {
                repoRoot.resolve("build/out/windows-arm64")
            } else {
                repoRoot.resolve("build/out/windows-amd64")
            }
        }
        osName.startsWith("linux") -> {
            if (osArch == "aarch64" || osArch == "arm64") {
                repoRoot.resolve("build/out/linux-arm64")
            } else {
                repoRoot.resolve("build/out/linux-amd64")
            }
        }
        osName.startsWith("mac") -> {
            if (osArch == "aarch64" || osArch == "arm64") {
                repoRoot.resolve("build/out/darwin-arm64")
            } else {
                repoRoot.resolve("build/out/darwin-amd64")
            }
        }
        else -> repoRoot.resolve("build/out")
    }
    
    // Set java.library.path to include the library directory
    systemProperty("java.library.path", libDir.absolutePath)
    
    // Also set jna.library.path as fallback
    systemProperty("jna.library.path", libDir.absolutePath)
    
    // Ensure library directory exists or provide helpful error
    doFirst {
        if (!libDir.exists()) {
            throw GradleException(
                "Native library directory does not exist: ${libDir.absolutePath}\n" +
                "Please build the native library first using:\n" +
                "  - Windows: build-scripts/build-windows.sh\n" +
                "  - Linux: build-scripts/build-linux.sh\n" +
                "  - macOS: build-scripts/build-darwin.sh"
            )
        }
    }
}

// Publishing to Maven Central (Sonatype OSSRH).
// Snapshot publishing is enabled automatically when the version ends with "-SNAPSHOT".
// Credentials and signing keys are expected to be provided via Gradle properties, e.g. in CI:
// - ORG_GRADLE_PROJECT_mavenCentralUsername / ORG_GRADLE_PROJECT_mavenCentralPassword
// - ORG_GRADLE_PROJECT_signingInMemoryKey / ORG_GRADLE_PROJECT_signingInMemoryKeyPassword
mavenPublishing {
    // Keep coordinates explicit to avoid changing artifactId when the Gradle project name changes.
    coordinates(
        groupId = group.toString(),
        artifactId = "gitleaks",
        version = version.toString()
    )

    // Publish to Maven Central (Sonatype). The plugin routes to the correct endpoint:
    // - release versions -> staging repository
    // - "-SNAPSHOT" versions -> snapshots repository
    publishToMavenCentral()

    // Sign all publications (required by Maven Central).
    signAllPublications()

    // POM metadata (recommended by com.vanniktech.maven.publish).
    pom {
        name.set("angryscan-gitleaks-kmp")
        description.set("Kotlin Multiplatform bindings over the Go libgitleaks shared library.")
        inceptionYear.set("2025")
        url.set("https://github.com/angryscan/angryscan-gitleaks")

        licenses {
            license {
                name.set("MIT License")
                url.set("https://opensource.org/licenses/MIT")
            }
        }

        scm {
            url.set("https://github.com/angryscan/angryscan-gitleaks")
            connection.set("scm:git:git://github.com/angryscan/angryscan-gitleaks.git")
            developerConnection.set("scm:git:ssh://git@github.com/angryscan/angryscan-gitleaks.git")
        }

        developers {
            developer {
                id.set("angryscan")
                name.set("angryscan")
                url.set("https://github.com/angryscan")
            }
        }
    }
}
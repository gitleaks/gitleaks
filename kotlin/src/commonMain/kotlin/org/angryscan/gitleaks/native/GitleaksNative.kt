package org.angryscan.gitleaks.bridge

import org.angryscan.gitleaks.model.FindingsPayload

/**
 * Platform bindings for the Go shared library.
 *
 * This is declared as expect/actual to support both Kotlin/Native (cinterop)
 * and other platforms (JVM can use JNA or be implemented later).
 */
expect class GitleaksNative() {
    fun createDefaultDetector(): ULong
    fun createDetectorFromToml(configToml: String): ULong
    fun freeDetector(handle: ULong)

    fun detectString(handle: ULong, text: String, filePath: String? = null): FindingsPayload
    fun detectBytes(handle: ULong, bytes: ByteArray, filePath: String? = null): FindingsPayload
}



package org.angryscan.gitleaks.bridge

import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Pointer
import com.sun.jna.ptr.PointerByReference
import kotlinx.serialization.json.Json
import org.angryscan.gitleaks.model.FindingsPayload

private interface LibGitleaks : Library {
    fun GitleaksCreateDefaultDetector(outErr: PointerByReference): Long
    fun GitleaksCreateDetectorFromToml(configToml: String, outErr: PointerByReference): Long
    fun GitleaksFreeDetector(handle: Long)

    fun GitleaksDetectString(
        handle: Long,
        text: String,
        filePath: String?,
        outErr: PointerByReference
    ): Pointer?

    fun GitleaksDetectBytes(
        handle: Long,
        data: ByteArray?,
        dataLen: Int,
        filePath: String?,
        outErr: PointerByReference
    ): Pointer?

    fun GitleaksFreeString(s: Pointer?)
}

private val json = Json { ignoreUnknownKeys = true }

/**
 * Determine library name based on the current platform.
 * JNA naming conventions:
 * - Windows: uses the name as-is with .dll extension. Our Go build produces "libgitleaks.dll", so we use "libgitleaks"
 * - Linux: adds "lib" prefix and ".so" extension -> "gitleaks" becomes "libgitleaks.so"
 * - macOS: adds "lib" prefix and ".dylib" extension -> "gitleaks" becomes "libgitleaks.dylib"
 */
private fun getLibraryName(): String {
    val osName = System.getProperty("os.name", "").lowercase()
    return when {
        osName.startsWith("windows") -> "libgitleaks" // Results in libgitleaks.dll
        else -> "gitleaks" // Results in libgitleaks.so (Linux) or libgitleaks.dylib (macOS)
    }
}

actual class GitleaksNative actual constructor() {
    private val lib: LibGitleaks = Native.load(getLibraryName(), LibGitleaks::class.java)

    private fun takeErr(ref: PointerByReference): String? {
        val p = ref.value ?: return null
        val msg = p.getString(0)
        lib.GitleaksFreeString(p)
        ref.value = null
        return msg
    }

    actual fun createDefaultDetector(): ULong {
        val err = PointerByReference()
        val h = lib.GitleaksCreateDefaultDetector(err)
        if (h == 0L) {
            throw RuntimeException(takeErr(err) ?: "GitleaksCreateDefaultDetector failed")
        }
        takeErr(err) // free if present
        return h.toULong()
    }

    actual fun createDetectorFromToml(configToml: String): ULong {
        val err = PointerByReference()
        val h = lib.GitleaksCreateDetectorFromToml(configToml, err)
        if (h == 0L) {
            throw RuntimeException(takeErr(err) ?: "GitleaksCreateDetectorFromToml failed")
        }
        takeErr(err)
        return h.toULong()
    }

    actual fun freeDetector(handle: ULong) {
        if (handle == 0uL) return
        lib.GitleaksFreeDetector(handle.toLong())
    }

    actual fun detectString(handle: ULong, text: String, filePath: String?): FindingsPayload {
        val err = PointerByReference()
        val res = lib.GitleaksDetectString(handle.toLong(), text, filePath, err)
        if (res == null) {
            throw RuntimeException(takeErr(err) ?: "GitleaksDetectString returned NULL")
        }
        val s = res.getString(0)
        lib.GitleaksFreeString(res)
        takeErr(err)
        return json.decodeFromString(FindingsPayload.serializer(), s)
    }

    actual fun detectBytes(handle: ULong, bytes: ByteArray, filePath: String?): FindingsPayload {
        val err = PointerByReference()
        val res = lib.GitleaksDetectBytes(handle.toLong(), bytes, bytes.size, filePath, err)
        if (res == null) {
            throw RuntimeException(takeErr(err) ?: "GitleaksDetectBytes returned NULL")
        }
        val s = res.getString(0)
        lib.GitleaksFreeString(res)
        takeErr(err)
        return json.decodeFromString(FindingsPayload.serializer(), s)
    }
}



package org.angryscan.gitleaks.bridge

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.CPointerVar
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.cstr
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.pointed
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.toKString
import kotlinx.cinterop.usePinned
import kotlinx.serialization.json.Json
import org.angryscan.gitleaks.model.FindingsPayload
import org.angryscan.gitleaks.native.GitleaksCreateDefaultDetector
import org.angryscan.gitleaks.native.GitleaksCreateDetectorFromToml
import org.angryscan.gitleaks.native.GitleaksDetectBytes
import org.angryscan.gitleaks.native.GitleaksDetectString
import org.angryscan.gitleaks.native.GitleaksFreeDetector
import org.angryscan.gitleaks.native.GitleaksFreeString

private val json = Json {
    ignoreUnknownKeys = true
}

@OptIn(ExperimentalForeignApi::class)
actual class GitleaksNative actual constructor() {
    actual fun createDefaultDetector(): ULong = memScoped {
        val err = alloc<CPointerVar<ByteVar>>()
        err.pointed = null
        val handle = GitleaksCreateDefaultDetector(err)
        if (handle == 0uL) {
            val errMsg = err.pointed?.toKString() ?: "GitleaksCreateDefaultDetector failed"
            err.pointed?.let { GitleaksFreeString(it) }
            throw RuntimeException(errMsg)
        }
        err.pointed?.let { GitleaksFreeString(it) }
        handle
    }

    actual fun createDetectorFromToml(configToml: String): ULong = memScoped {
        val err = alloc<CPointerVar<ByteVar>>()
        err.pointed = null
        val cfgPtr = configToml.cstr.getPointer(this)
        val handle = GitleaksCreateDetectorFromToml(cfgPtr, err)
        if (handle == 0uL) {
            val msg = err.pointed?.toKString() ?: "GitleaksCreateDetectorFromToml failed"
            err.pointed?.let { GitleaksFreeString(it) }
            throw RuntimeException(msg)
        }
        err.pointed?.let { GitleaksFreeString(it) }
        handle
    }

    actual fun freeDetector(handle: ULong) {
        if (handle == 0uL) return
        GitleaksFreeDetector(handle)
    }

    actual fun detectString(handle: ULong, text: String, filePath: String?): FindingsPayload = memScoped {
        val err = alloc<CPointerVar<ByteVar>>()
        err.pointed = null
        val textPtr = text.cstr.getPointer(this)
        val fpPtr = (filePath ?: "").cstr.getPointer(this)
        val res: CPointer<ByteVar>? = GitleaksDetectString(handle, textPtr, fpPtr, err)
        if (res == null) {
            val msg = err.pointed?.toKString() ?: "GitleaksDetectString returned NULL"
            err.pointed?.let { GitleaksFreeString(it) }
            throw RuntimeException(msg)
        }
        val s = res.toKString()
        GitleaksFreeString(res)
        err.pointed?.let { GitleaksFreeString(it) }
        json.decodeFromString(FindingsPayload.serializer(), s)
    }

    actual fun detectBytes(handle: ULong, bytes: ByteArray, filePath: String?): FindingsPayload = memScoped {
        val err = alloc<CPointerVar<ByteVar>>()
        err.pointed = null
        val fpPtr = (filePath ?: "").cstr.getPointer(this)
        bytes.usePinned { pinnedBytes ->
            val res: CPointer<ByteVar>? = GitleaksDetectBytes(
                handle,
                pinnedBytes.addressOf(0),
                bytes.size.convert(),
                fpPtr,
                err
            )
            if (res == null) {
                val msg = err.pointed?.toKString() ?: "GitleaksDetectBytes returned NULL"
                err.pointed?.let { GitleaksFreeString(it) }
                throw RuntimeException(msg)
            }
            val s = res.toKString()
            GitleaksFreeString(res)
            err.pointed?.let { GitleaksFreeString(it) }
            json.decodeFromString(FindingsPayload.serializer(), s)
        }
    }
}



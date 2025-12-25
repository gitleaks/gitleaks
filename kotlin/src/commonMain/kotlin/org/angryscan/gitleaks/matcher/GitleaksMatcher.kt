package org.angryscan.gitleaks.matcher

import kotlinx.serialization.Serializable
import org.angryscan.common.engine.IMatcher
import org.angryscan.common.engine.Match
import org.angryscan.common.engine.custom.ICustomMatcher
import org.angryscan.gitleaks.bridge.GitleaksNative
import org.angryscan.gitleaks.model.FindingsPayload

/**
 * Custom matcher backed by Go gitleaks engine via C-interop.
 *
 * This matcher returns matches for detected *secrets* (not the full regex match).
 */
@Serializable
object GitleaksMatcher : ICustomMatcher {

    override val name: String = "Gitleaks"

    @kotlinx.serialization.Transient
    private val native: GitleaksNative by lazy { GitleaksNative() }
    
    @kotlinx.serialization.Transient
    private var detectorHandle: ULong = 0uL
    
    @kotlinx.serialization.Transient
    private var customConfigToml: String? = null
    
    @kotlinx.serialization.Transient
    private var isInitialized: Boolean = false

    override fun check(value: String): Boolean = true

    override fun scan(text: String): List<Match> {
        // Require explicit initialization - don't auto-initialize
        require(isInitialized && detectorHandle != 0uL) {
            "GitleaksMatcher must be initialized before scanning. Call init() first."
        }
        val payload = native.detectString(detectorHandle, text, null)
        return findingsPayloadToMatches(text, payload, this)
    }

    fun init(useDefaultConfig: Boolean = true, configToml: String? = null) {
        // Close existing detector if any
        if (detectorHandle != 0uL) {
            native.freeDetector(detectorHandle)
            detectorHandle = 0uL
        }
        
        // Store custom config if provided
        customConfigToml = if (useDefaultConfig) {
            null
        } else {
            requireNotNull(configToml) { "configToml must be provided when useDefaultConfig is false" }
            configToml
        }
        
        // Create detector immediately
        detectorHandle = if (customConfigToml != null) {
            native.createDetectorFromToml(customConfigToml!!)
        } else {
            native.createDefaultDetector()
        }
        isInitialized = true
    }

    fun close() {
        if (detectorHandle != 0uL) {
            native.freeDetector(detectorHandle)
            detectorHandle = 0uL
        }
        customConfigToml = null
        isInitialized = false
    }
}

internal fun findingsPayloadToMatches(text: String, payload: FindingsPayload, matcher: IMatcher): List<Match> {
    return payload.findings.mapNotNull { f ->
        val value = (f.secret ?: f.match)?.takeIf { it.isNotEmpty() } ?: return@mapNotNull null

        // Go returns rune offsets with end exclusive. angryscan-core expects end inclusive.
        val start = f.secretStart.coerceIn(0, text.length)
        val endExclusive = f.secretEnd.coerceIn(start, text.length)
        val endInclusive = (endExclusive - 1).coerceAtLeast(start)

        Match(
            value = value,
            before = text.substring(maxOf(0, start - 10), start),
            after = text.substring(minOf(text.length, endInclusive + 1), minOf(text.length, endInclusive + 11)),
            startPosition = start.toLong(),
            endPosition = endInclusive.toLong(),
            matcher = matcher
        )
    }
}



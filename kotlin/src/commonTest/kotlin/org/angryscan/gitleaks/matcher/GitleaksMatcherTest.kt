package org.angryscan.gitleaks.matcher

import kotlin.test.*

/**
 * Integration tests for GitleaksMatcher.
 * 
 * These tests require the native libgitleaks library to be built and available.
 * The library path is configured in build.gradle.kts via java.library.path.
 */
class GitleaksMatcherTest {

    @BeforeTest
    fun setUp() {
        GitleaksMatcher.init(useDefaultConfig = true)
    }

    @AfterTest
    fun tearDown() {
        GitleaksMatcher.close()
    }

    @Test
    fun testMatcherName() {
        assertEquals("Gitleaks", GitleaksMatcher.name)
    }

    @Test
    fun testCheckAlwaysReturnsTrue() {
        // check() should always return true for GitleaksMatcher
        assertTrue(GitleaksMatcher.check("any value"))
        assertTrue(GitleaksMatcher.check(""))
        assertTrue(GitleaksMatcher.check("test123"))
    }

    @Test
    fun testScanWithNoSecrets() {
        val text = "This is a normal text without any secrets."
        val matches = GitleaksMatcher.scan(text)

        assertNotNull(matches)
        assertEquals(0, matches.size, "Should not find any secrets in normal text")
    }

    @Test
    fun testScanWithGitHubPAT() {
        // Use default config - GitHub PAT should be detected by default gitleaks config
        // GitHub PAT pattern: ghp_ followed by 36 alphanumeric characters
        // Default config regex: ghp_[0-9a-zA-Z]{36}
        val githubPAT = "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"
        val text = "GITHUB_TOKEN=$githubPAT"

        val matches = GitleaksMatcher.scan(text)

        assertNotNull(matches)
        // Default config should detect GitHub PAT - test must fail if nothing found
        assertTrue(matches.isNotEmpty(), 
            "Default config should detect GitHub PAT. PAT: $githubPAT")
        val match = matches.first()
        assertEquals("Gitleaks", match.matcher.name, "Matcher name should be Gitleaks")
        assertTrue(match.value.isNotEmpty(), "Match should have a value")
        assertTrue(match.startPosition >= 0, "Start position should be non-negative")
        assertTrue(match.endPosition >= match.startPosition, "End position should be >= start position")
        // Verify that the PAT is actually found
        assertTrue(match.value.contains(githubPAT) || githubPAT.contains(match.value), 
            "Match should contain the GitHub PAT")
    }

    @Test
    fun testScanWithAWSAccessKey() {
        // Use default config - AWS access key should be detected (but not if it ends with EXAMPLE)
        // AWS Access Key ID pattern: starts with AKIA/ASIA/ABIA/ACCA followed by 16 characters [A-Z2-7]
        // Default config regex: \b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b
        // Note: Keys ending with EXAMPLE are allowlisted, so we use a key that doesn't end with EXAMPLE
        // Use a key with sufficient entropy to ensure detection
        val awsKey = "ASIAY34FZKBOKMUTVV7A" // Valid format with good entropy, doesn't end with EXAMPLE
        val text = "aws_access_key_id = $awsKey"

        val matches = GitleaksMatcher.scan(text)

        assertNotNull(matches)
        // Default config should detect AWS access key - test must fail if nothing found
        assertTrue(matches.isNotEmpty(), 
            "Default config should detect AWS access key. Key: $awsKey")
        
        val match = matches.first()
        assertEquals("Gitleaks", match.matcher.name, "Matcher name should be Gitleaks")
        assertTrue(match.value.isNotEmpty(), "Match should have a value")
        assertTrue(match.startPosition >= 0, "Start position should be non-negative")
        assertTrue(match.endPosition >= match.startPosition, "End position should be >= start position")
        // Verify that the match is actually in the text
        assertTrue(match.startPosition < text.length, "Start position should be within text bounds")
        assertTrue(match.endPosition < text.length, "End position should be within text bounds")
        // Verify that the access key is actually found
        assertTrue(match.value.contains(awsKey) || awsKey.contains(match.value), 
            "Match should contain the AWS access key")
    }

    @Test
    fun testScanWithMultipleSecrets() {
        // Use default config - should detect multiple GitHub PATs
        val text = """
            GITHUB_TOKEN=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
            Some other text here
            GITHUB_PAT=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
        """.trimIndent()

        val matches = GitleaksMatcher.scan(text)

        assertNotNull(matches)
        // Default config should detect at least 2 GitHub PATs - test must fail if nothing found
        assertTrue(matches.size >= 2, 
            "Default config should detect at least 2 GitHub PATs. Found: ${matches.size}")
        
        // Verify that scan() works correctly with multiple potential secrets
        // Verify they are valid and don't overlap incorrectly
        matches.forEach { match ->
            assertEquals("Gitleaks", match.matcher.name, "Matcher name should be Gitleaks")
            assertTrue(match.value.isNotEmpty(), "Match should have a value")
            assertTrue(match.startPosition >= 0, "Start position should be non-negative")
            assertTrue(match.endPosition >= match.startPosition, "End position should be >= start position")
            assertTrue(match.startPosition < text.length, "Start position should be within text bounds")
            assertTrue(match.endPosition < text.length, "End position should be within text bounds")
            // Verify that the match value is actually in the text at the specified position
            val matchInText =
                text.substring(match.startPosition.toInt(), (match.endPosition + 1).toInt().coerceAtMost(text.length))
            assertTrue(
                matchInText.contains(match.value) || match.value.contains(matchInText),
                "Match value should correspond to text at specified position"
            )
            // Verify that it's a GitHub PAT (either classic ghp_ or fine-grained github_pat_)
            assertTrue(
                match.value.startsWith("ghp_") || match.value.startsWith("github_pat_"),
                "Match should be a GitHub PAT (ghp_ or github_pat_). Found: ${match.value.take(20)}..."
            )
        }
    }

    @Test
    fun testInitAndClose() {
        // Test that we can initialize and close multiple times
        GitleaksMatcher.init(useDefaultConfig = true)
        val matches1 = GitleaksMatcher.scan("test")
        assertNotNull(matches1, "Should be able to scan after init")
        GitleaksMatcher.close()

        // Verify that scan() fails after close()
        assertFails {
            GitleaksMatcher.scan("test")
        }

        // Test re-initialization
        GitleaksMatcher.init(useDefaultConfig = true)
        val matches2 = GitleaksMatcher.scan("test")
        assertNotNull(matches2, "Should be able to scan after re-init")
        GitleaksMatcher.close()

        // Verify that scan() fails again after close()
        assertFails {
            GitleaksMatcher.scan("test")
        }
    }

    @Test
    fun testScanWithoutInit() {
        // Test that scan() fails if matcher is not initialized
        // Close any existing initialization from setUp()
        GitleaksMatcher.close()

        // Verify that scan() throws an exception when not initialized
        assertFails {
            GitleaksMatcher.scan("test")
        }
    }

    @Test
    fun testInitWithCustomConfig() {
        // Test initialization with custom config
        // Using a minimal valid TOML config
        val customConfig = """
            [[rules]]
            id = 'test-rule'
            description = 'Test Rule'
            regex = '''test-secret-\d+'''
        """.trimIndent()

        GitleaksMatcher.init(useDefaultConfig = false, configToml = customConfig)
        val matches = GitleaksMatcher.scan("test-secret-12345")
        assertNotNull(matches)
        // With custom config, we should find the secret - test must fail if nothing found
        assertTrue(matches.isNotEmpty(), "Custom config should detect the secret")
        val match = matches.first()
        assertEquals("Gitleaks", match.matcher.name, "Matcher name should be Gitleaks")
        assertTrue(match.value.contains("test-secret-12345"), "Match should contain the secret")
        GitleaksMatcher.close()
    }

    @Test
    fun testCustomConfigWithEmailPattern() {
        // Test custom config with email-like pattern
        val customConfig = """
            [[rules]]
            id = 'email-secret'
            description = 'Email-like secret pattern'
            regex = '''secret-email-[a-z0-9]+@test\.com'''
        """.trimIndent()

        GitleaksMatcher.init(useDefaultConfig = false, configToml = customConfig)
        
        val textWithSecret = "My secret is secret-email-abc123xyz@test.com"
        val matches = GitleaksMatcher.scan(textWithSecret)
        
        assertNotNull(matches)
        // Custom config should detect the secret - test must fail if nothing found
        assertTrue(matches.isNotEmpty(), 
            "Custom config should detect email-like secret. Text: $textWithSecret")
        
        val match = matches.first()
        assertEquals("Gitleaks", match.matcher.name, "Matcher name should be Gitleaks")
        assertTrue(match.value.contains("secret-email-abc123xyz@test.com"), 
            "Match should contain the email-like secret")
        
        // Verify that default config doesn't find this (if we switch back)
        GitleaksMatcher.close()
        GitleaksMatcher.init(useDefaultConfig = true)
        val defaultMatches = GitleaksMatcher.scan(textWithSecret)
        // Default config should NOT find this custom pattern
        assertEquals(0, defaultMatches.size, 
            "Default config should not detect custom email pattern")
    }

    @Test
    fun testCustomConfigWithMultipleRules() {
        // Test custom config with multiple rules
        val customConfig = """
            [[rules]]
            id = 'api-key-rule'
            description = 'API Key Pattern'
            regex = '''api_key_[A-Z0-9]{32}'''
            
            [[rules]]
            id = 'token-rule'
            description = 'Token Pattern'
            regex = '''token_[a-z0-9]{36}'''
        """.trimIndent()

        GitleaksMatcher.init(useDefaultConfig = false, configToml = customConfig)
        
        val text = """
            api_key_ABCD1234EFGH5678IJKL9012MNOP3456
            some other text
            token_abcdefghijklmnopqrstuvwxyz1234567890
        """.trimIndent()
        
        val matches = GitleaksMatcher.scan(text)
        
        assertNotNull(matches)
        // Custom config should detect both secrets - test must fail if nothing found
        // Debug: show what was found
        val foundValues = matches.joinToString(", ") { it.value }
        assertTrue(matches.isNotEmpty(), 
            "Custom config should detect at least 1 secret. Found: ${matches.size}. Values: $foundValues")
        
        // Gitleaks may return only the secret part or the full match
        // Check that we found matches for both patterns
        val apiKeyMatch = matches.find { 
            it.value.contains("ABCD1234") || 
            it.value.contains("EFGH5678") || 
            it.value.contains("api_key_")
        }
        assertNotNull(apiKeyMatch, 
            "Should find API key match. Found matches: $foundValues")
        // Verify it contains at least part of the expected key
        assertTrue(
            apiKeyMatch.value.contains("ABCD1234") || 
            apiKeyMatch.value.contains("EFGH5678") ||
            apiKeyMatch.value.contains("IJKL9012") ||
            apiKeyMatch.value.contains("MNOP3456") ||
            apiKeyMatch.value.contains("api_key_"),
            "API key match should contain part of the key. Found: ${apiKeyMatch.value}"
        )
        
        val tokenMatch = matches.find { 
            it.value.contains("abcdefghijklmnopqrstuvwxyz") || 
            it.value.contains("1234567890") ||
            it.value.contains("token_")
        }
        assertNotNull(tokenMatch, 
            "Should find token match. Found matches: $foundValues")
        // Verify it contains at least part of the expected token
        assertTrue(
            tokenMatch.value.contains("abcdefghijklmnopqrstuvwxyz") || 
            tokenMatch.value.contains("1234567890") ||
            tokenMatch.value.contains("token_"),
            "Token match should contain part of the token. Found: ${tokenMatch.value}"
        )
        
        // Both matches are already verified by assertNotNull above
        GitleaksMatcher.close()
    }

    @Test
    fun testScanWithContext() {
        // Use default config - GitHub PAT should be detected
        val prefix = "0123456789"
        val githubPAT = "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"
        val suffix = "9876543210"
        val text = "${prefix}GITHUB_TOKEN=$githubPAT$suffix"

        val matches = GitleaksMatcher.scan(text)

        // Default config should detect GitHub PAT - test must fail if nothing found
        assertTrue(matches.isNotEmpty(), 
            "Default config should detect GitHub PAT. PAT: $githubPAT")
        val match = matches.first()
        
        // Check that context (before/after) is captured
        assertNotNull(match.before, "Before context should be captured")
        assertNotNull(match.after, "After context should be captured")
        // Verify that context corresponds to the actual text
        val contextStart = (match.startPosition - match.before.length.toLong()).coerceAtLeast(0)
        val contextEnd = (match.endPosition + 1 + match.after.length.toLong()).coerceAtMost(text.length.toLong())
        val actualBefore = text.substring(contextStart.toInt(), match.startPosition.toInt())
        val actualAfter = text.substring((match.endPosition + 1).toInt(), contextEnd.toInt())
        assertEquals(match.before, actualBefore, "Before context should match actual text")
        assertEquals(match.after, actualAfter, "After context should match actual text")
    }

    @Test
    fun testScanEmptyString() {
        val matches = GitleaksMatcher.scan("")
        assertNotNull(matches)
        assertEquals(0, matches.size, "Empty string should produce no matches")
    }

    @Test
    fun testScanLargeText() {
        // Use default config - GitHub PAT should be detected
        // Create a large text with a secret in the middle
        val githubPAT = "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"
        val largeText = ("x".repeat(1000) +
                "GITHUB_TOKEN=$githubPAT" +
                "y".repeat(1000)).repeat(10)

        val matches = GitleaksMatcher.scan(largeText)

        assertNotNull(matches)
        // Default config should detect GitHub PAT in large text - test must fail if nothing found
        assertEquals(10, matches.size, "")
        
        // Verify that scan() can handle large text without errors
        // Verify positions are correct for large text
        matches.forEach { match ->
            assertEquals("Gitleaks", match.matcher.name, "Matcher name should be Gitleaks")
            assertTrue(match.startPosition >= 0, "Start position should be non-negative")
            assertTrue(match.endPosition >= match.startPosition, "End position should be >= start position")
            assertTrue(match.startPosition < largeText.length, "Start position should be within text bounds")
            assertTrue(match.endPosition < largeText.length, "End position should be within text bounds")
            // Verify context is captured correctly for large text
            assertNotNull(match.before, "Before context should be captured")
            assertNotNull(match.after, "After context should be captured")
            // Verify that the PAT is actually found at the correct position
            assertTrue(match.value.contains(githubPAT) || githubPAT.contains(match.value), 
                "Match should contain the GitHub PAT")
        }
    }

    @Test
    fun testMatcherIsSerializable() {
        // Test that GitleaksMatcher can be serialized (it's marked as @Serializable)
        // This is a compile-time check, but we can verify the object structure
        assertNotNull(GitleaksMatcher)
        assertEquals("Gitleaks", GitleaksMatcher.name)
    }
}


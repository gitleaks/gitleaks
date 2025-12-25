package org.angryscan.gitleaks.matcher

import org.angryscan.common.engine.IMatcher
import org.angryscan.gitleaks.model.FindingPayload
import org.angryscan.gitleaks.model.FindingsPayload
import kotlin.test.Test
import kotlin.test.assertEquals

private object DummyMatcher : IMatcher {
    override val name: String = "dummy"
    override fun check(value: String): Boolean = true
}

class GitleaksMatcherMappingTest {
    @Test
    fun mapsOffsetsAndContext() {
        val text = "0123456789SECRET_ABCDEF0123456789"
        val payload = FindingsPayload(
            findings = listOf(
                FindingPayload(
                    ruleId = "aws-secret",
                    match = "AWS_SECRET_ACCESS_KEY=SECRET_ABCDEF",
                    secret = "SECRET_ABCDEF",
                    tags = emptyList(),
                    secretStart = 10,
                    secretEnd = 23,
                    startLine = 1,
                    endLine = 1,
                    startColumn = 11,
                    endColumn = 23,
                    file = "x",
                    commit = null
                )
            )
        )

        val matches = findingsPayloadToMatches(text, payload, DummyMatcher)

        assertEquals(1, matches.size)
        val m = matches.single()

        assertEquals("SECRET_ABCDEF", m.value)
        assertEquals(10L, m.startPosition)
        assertEquals(22L, m.endPosition) // end exclusive -> inclusive
        assertEquals("0123456789", m.before)
        assertEquals("0123456789", m.after)
        assertEquals(DummyMatcher, m.matcher)
    }
}



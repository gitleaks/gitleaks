package org.angryscan.gitleaks.model

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class FindingsPayload(
    @SerialName("findings")
    val findings: List<FindingPayload> = emptyList()
)

@Serializable
data class FindingPayload(
    @SerialName("ruleId")
    val ruleId: String,
    @SerialName("description")
    val description: String? = null,
    @SerialName("match")
    val match: String? = null,
    @SerialName("secret")
    val secret: String? = null,
    @SerialName("tags")
    val tags: List<String> = emptyList(),
    @SerialName("secretStart")
    val secretStart: Int,
    @SerialName("secretEnd")
    val secretEnd: Int,

    @SerialName("startLine")
    val startLine: Int? = null,
    @SerialName("endLine")
    val endLine: Int? = null,
    @SerialName("startColumn")
    val startColumn: Int? = null,
    @SerialName("endColumn")
    val endColumn: Int? = null,

    @SerialName("file")
    val file: String? = null,
    @SerialName("commit")
    val commit: String? = null
)



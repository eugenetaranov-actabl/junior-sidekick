package com.github.uncomplexco.sidekick.egress.policy

/** What the proxy does with a connection to a matched host. */
enum class EgressAction {
    /** Terminate TLS, inject the header, re-originate upstream. Requires injection fields. */
    TERMINATE,

    /** Blind byte-for-byte tunnel (upstream's real cert reaches the client). No injection. */
    TUNNEL,

    /** Refuse the connection. */
    DENY,
}

/**
 * A single first-match-wins egress rule.
 *
 * [host] is a hostname matcher: either an exact host (`api.github.com`) or a leading-wildcard suffix
 * (`*.atlassian.net`, matching any single-or-multi-label subdomain but not the bare apex). Matching
 * is case-insensitive.
 *
 * For [EgressAction.TERMINATE] rules the injection fields are required: [credentialRef] selects the
 * secret, [header] is the header name, and [valueTemplate] must contain the `{{token}}` placeholder.
 * [pathPrefix], when set, further scopes the rule to requests whose path starts with it. [allowPlaintext]
 * permits injection over cleartext `http://` (off by default — otherwise the secret would travel
 * unencrypted upstream).
 */
data class EgressRule(
    val id: String,
    val host: String,
    val action: EgressAction,
    val pathPrefix: String? = null,
    val credentialRef: String? = null,
    val header: String? = null,
    val valueTemplate: String? = null,
    val allowPlaintext: Boolean = false,
) {
    init {
        if (action == EgressAction.TERMINATE) {
            require(!credentialRef.isNullOrBlank()) { "rule '$id': credential-ref is required for terminate rules" }
            require(!header.isNullOrBlank()) { "rule '$id': header is required for terminate rules" }
            require(!valueTemplate.isNullOrBlank()) { "rule '$id': value-template is required for terminate rules" }
            require(valueTemplate.contains("{{token}}")) { "rule '$id': value-template must contain {{token}}" }
        }
    }

    private val normalizedHost = host.trim().lowercase()

    /** True if this rule's host matcher matches [candidate] (already lowercased by the caller). */
    fun matchesHost(candidate: String): Boolean =
        if (normalizedHost.startsWith("*.")) {
            val suffix = normalizedHost.substring(1) // ".atlassian.net"
            candidate.endsWith(suffix) && candidate.length > suffix.length
        } else {
            candidate == normalizedHost
        }

    /** True if this rule's optional path prefix matches [path] (or no prefix is configured). */
    fun matchesPath(path: String?): Boolean {
        val prefix = pathPrefix ?: return true
        return path != null && path.startsWith(prefix)
    }
}

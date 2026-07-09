package com.github.uncomplexco.sidekick.egress.policy

/**
 * First-match-wins egress policy.
 *
 * Decisions happen at two points because the path is not known until after TLS is terminated:
 *  - [decideConnect] runs at `CONNECT` time on the host alone, choosing terminate / tunnel / deny.
 *  - [matchRequest] runs once the request line is decoded, resolving the exact rule (host **and**
 *    path) that governs header injection.
 *
 * Rules are evaluated in declared order; the first whose matcher applies wins. If none apply,
 * [defaultAction] is used (which may only be [EgressAction.TUNNEL] or [EgressAction.DENY] —
 * terminating requires an explicit rule so we never MITM a host nobody configured).
 */
class EgressPolicy(
    val rules: List<EgressRule>,
    val defaultAction: EgressAction = EgressAction.DENY,
) {
    init {
        require(defaultAction != EgressAction.TERMINATE) {
            "default-action cannot be 'terminate' — terminating requires an explicit rule"
        }
    }

    /** Decision made at CONNECT time, where only the target host is known. */
    fun decideConnect(host: String): EgressAction {
        val normalized = normalizeHost(host)
        val rule = rules.firstOrNull { it.matchesHost(normalized) }
        return rule?.action ?: defaultAction
    }

    /**
     * Resolves the rule that governs a decoded request. Returns the first rule matching both host and
     * path, or null if none match (the caller applies [defaultAction] semantics for terminated
     * connections — i.e. forward without injection when the default is tunnel, refuse when deny).
     */
    fun matchRequest(host: String, path: String?): EgressRule? {
        val normalized = normalizeHost(host)
        return rules.firstOrNull { it.matchesHost(normalized) && it.matchesPath(path) }
    }

    private fun normalizeHost(host: String): String {
        var h = host.trim().lowercase()
        // Strip an explicit port (host:443) and a trailing FQDN dot.
        val colon = h.lastIndexOf(':')
        if (colon > 0 && h.indexOf(']') < colon) {
            h = h.substring(0, colon)
        }
        return h.removeSuffix(".")
    }
}

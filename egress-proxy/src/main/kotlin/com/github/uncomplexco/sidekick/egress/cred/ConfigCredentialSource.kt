package com.github.uncomplexco.sidekick.egress.cred

/**
 * A [CredentialSource] backed by static tokens supplied at startup (e.g. from the sandbox-service
 * config / environment). Each [resolve] returns a fresh [Secret] wrapping a copy of the stored
 * value, so callers may [Secret.close] their copy without destroying the source's.
 *
 * The stored values live only in this process; they are never written into the sandbox.
 */
class ConfigCredentialSource(
    credentials: Map<String, CharArray>,
) : CredentialSource {
    // Defensive copies so the caller can't mutate our backing store, and vice versa.
    private val store: Map<String, CharArray> = credentials.mapValues { it.value.copyOf() }

    override fun resolve(credentialRef: String): Secret? {
        val stored = store[credentialRef] ?: return null
        return Secret(stored.copyOf())
    }

    companion object {
        /** Convenience factory for config that arrives as strings. */
        fun fromStrings(credentials: Map<String, String>): ConfigCredentialSource =
            ConfigCredentialSource(credentials.mapValues { it.value.toCharArray() })
    }
}

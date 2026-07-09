package com.github.uncomplexco.sidekick.sandbox.service

import com.github.uncomplexco.sidekick.egress.policy.EgressAction
import com.github.uncomplexco.sidekick.egress.policy.EgressPolicy
import com.github.uncomplexco.sidekick.egress.policy.EgressRule
import io.ktor.server.config.ApplicationConfig
import java.nio.file.Path

/**
 * Parsed `egress { ... }` config block for the credential-injecting proxy. Absent or `enabled = false`
 * yields null and the service behaves exactly as before (no proxy, no CA mount).
 */
data class EgressServiceConfig(
    val listenAddress: String,
    val port: Int,
    val stateDir: Path,
    val defaultAction: EgressAction,
    val rules: List<EgressRule>,
    val credentials: Map<String, String>,
    /** When true, install the nftables jail so the sandbox can only reach the proxy (hard enforcement). */
    val enforce: Boolean,
    /** Uid the proxy runs as (kept unrestricted by the jail). Null = detect the current process uid. */
    val proxyUid: Int?,
) {
    fun policy(): EgressPolicy = EgressPolicy(rules, defaultAction)

    companion object {
        fun fromApplicationConfig(config: ApplicationConfig): EgressServiceConfig? {
            val enabled = config.propertyOrNull("egress.enabled")?.getString()?.toBoolean() ?: false
            if (!enabled) return null

            return EgressServiceConfig(
                listenAddress = config.propertyOrNull("egress.listen-address")?.getString() ?: "127.0.0.1",
                port = config.propertyOrNull("egress.port")?.getString()?.toInt() ?: 0,
                stateDir = Path.of(config.propertyOrNull("egress.state-dir")?.getString() ?: "./data/egress"),
                defaultAction = parseAction(config.propertyOrNull("egress.default-action")?.getString() ?: "deny"),
                rules = parseRules(config),
                credentials = parseCredentials(config),
                enforce = config.propertyOrNull("egress.enforce")?.getString()?.toBoolean() ?: false,
                proxyUid = config.propertyOrNull("egress.proxy-uid")?.getString()?.toInt(),
            )
        }

        private fun parseRules(config: ApplicationConfig): List<EgressRule> =
            runCatching { config.configList("egress.rules") }.getOrElse { emptyList() }.map { rule ->
                EgressRule(
                    id = rule.property("id").getString(),
                    host = rule.property("host").getString(),
                    action = parseAction(rule.property("action").getString()),
                    pathPrefix = rule.propertyOrNull("path-prefix")?.getString(),
                    credentialRef = rule.propertyOrNull("credential-ref")?.getString(),
                    header = rule.propertyOrNull("header")?.getString(),
                    valueTemplate = rule.propertyOrNull("value-template")?.getString(),
                    allowPlaintext = rule.propertyOrNull("allow-plaintext")?.getString()?.toBoolean() ?: false,
                )
            }

        private fun parseCredentials(config: ApplicationConfig): Map<String, String> =
            runCatching { config.configList("egress.credentials") }.getOrElse { emptyList() }.mapNotNull { cred ->
                val ref = cred.property("ref").getString()
                val value = cred.propertyOrNull("value")?.getString() ?: return@mapNotNull null
                ref to value
            }.toMap()

        private fun parseAction(value: String): EgressAction =
            when (value.trim().lowercase()) {
                "terminate" -> EgressAction.TERMINATE
                "tunnel" -> EgressAction.TUNNEL
                "deny" -> EgressAction.DENY
                else -> throw IllegalArgumentException("Unknown egress action: $value")
            }
    }
}

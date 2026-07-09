package com.github.uncomplexco.sidekick.sandbox.service

import com.github.uncomplexco.sidekick.egress.ca.ProxyCa
import com.github.uncomplexco.sidekick.egress.cred.ConfigCredentialSource
import com.github.uncomplexco.sidekick.egress.net.EgressProxyServer
import com.github.uncomplexco.sidekick.sandbox.bwrap.BwrapMount
import com.github.uncomplexco.sidekick.sandbox.bwrap.BwrapMountMode
import com.github.uncomplexco.sidekick.sandbox.bwrap.BwrapSandboxRequest
import org.slf4j.LoggerFactory
import java.nio.file.Files
import java.nio.file.Path

/**
 * Where the combined CA bundle (system CAs + our proxy CA) is mounted inside the sandbox. We bind it
 * over the rootfs's existing Debian system-trust path: the file already exists (so bwrap can bind over
 * it on the read-only root without creating a mountpoint) and tools trust it by default. Our bundle
 * includes the original system CAs, so nothing is lost for tunneled hosts with real certs.
 */
private const val CA_BUNDLE_SANDBOX_PATH = "/etc/ssl/certs/ca-certificates.crt"

/**
 * A started egress proxy plus the augmentor that stamps every sandbox request with the proxy env and
 * the read-only CA-bundle mount. Credential values live only here (in the proxy process); the sandbox
 * receives only the proxy URL and the public CA bundle.
 */
class EgressProxyRuntime private constructor(
    private val server: EgressProxyServer,
    val augmentRequest: (BwrapSandboxRequest) -> BwrapSandboxRequest,
) {
    fun stop() = server.stop()

    companion object {
        private val logger = LoggerFactory.getLogger(EgressProxyRuntime::class.java)

        /**
         * @param systemCaBundle path to the rootfs system CA bundle (e.g. Debian
         *   `etc/ssl/certs/ca-certificates.crt`). Our CA is appended to it so tunneled hosts that
         *   present real certificates still validate; null falls back to a proxy-CA-only bundle.
         */
        fun start(config: EgressServiceConfig, systemCaBundle: Path?, sandboxUid: Int): EgressProxyRuntime {
            Files.createDirectories(config.stateDir)
            val caCertPath = config.stateDir.resolve("ca.crt").toAbsolutePath()
            val caKeyPath = config.stateDir.resolve("ca.key").toAbsolutePath()
            val ca = ProxyCa.loadOrGenerate(caCertPath, caKeyPath)

            val bundlePath = writeCaBundle(config.stateDir, systemCaBundle, ca)

            val server =
                EgressProxyServer(
                    ca = ca,
                    policy = config.policy(),
                    credentialSource = ConfigCredentialSource.fromStrings(config.credentials),
                    bindAddress = config.listenAddress,
                    requestedPort = config.port,
                ).start()

            if (config.enforce) {
                val proxyUid = config.proxyUid ?: NftablesJail.currentUid()
                if (proxyUid == null) {
                    logger.warn("egress.enforce=true but the proxy uid could not be detected; set egress.proxy-uid. Jail NOT applied.")
                } else {
                    NftablesJail.applyIfSupported(sandboxUid, proxyUid, config.listenAddress, server.boundPort)
                }
            }

            val proxyUrl = "http://${config.listenAddress}:${server.boundPort}"
            val env = proxyEnv(proxyUrl, CA_BUNDLE_SANDBOX_PATH)
            val caMount = BwrapMount(source = bundlePath, target = CA_BUNDLE_SANDBOX_PATH, mode = BwrapMountMode.RO)

            val augment: (BwrapSandboxRequest) -> BwrapSandboxRequest = { request ->
                request.copy(env = request.env + env, mounts = request.mounts + caMount)
            }
            return EgressProxyRuntime(server, augment)
        }

        /** Combined trust bundle = system CAs (so real upstream certs on tunneled hosts still verify) + our CA. */
        private fun writeCaBundle(stateDir: Path, systemCaBundle: Path?, ca: ProxyCa): Path {
            val system =
                systemCaBundle?.takeIf { Files.exists(it) }?.let { Files.readString(it) }
                    ?: run {
                        logger.warn(
                            "System CA bundle not found ({}); sandbox will trust ONLY the proxy CA, " +
                                "which breaks TLS to tunneled (non-terminated) hosts",
                            systemCaBundle,
                        )
                        ""
                    }
            val bundlePath = stateDir.resolve("egress-ca-bundle.crt").toAbsolutePath()
            Files.writeString(bundlePath, system + "\n" + ca.certificatePem())
            return bundlePath
        }

        /** Points sandboxed HTTP tooling at the proxy and at the mounted CA bundle for TLS trust. */
        private fun proxyEnv(proxyUrl: String, caPath: String): Map<String, String> =
            mapOf(
                "HTTP_PROXY" to proxyUrl,
                "HTTPS_PROXY" to proxyUrl,
                "http_proxy" to proxyUrl,
                "https_proxy" to proxyUrl,
                "CURL_CA_BUNDLE" to caPath,
                "SSL_CERT_FILE" to caPath,
                "GIT_SSL_CAINFO" to caPath,
                "NODE_EXTRA_CA_CERTS" to caPath,
                "REQUESTS_CA_BUNDLE" to caPath,
                "PIP_CERT" to caPath,
            )
    }
}

package com.github.uncomplexco.sidekick.sandbox.service

import org.slf4j.LoggerFactory
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit

/**
 * Hard egress enforcement: an nftables owner-match ruleset that lets the dedicated sandbox uid reach
 * ONLY the proxy, dropping every other outbound connection. This makes the proxy the sole route out,
 * so a sandboxed command cannot `unset HTTPS_PROXY` and connect directly.
 *
 * Requires the service to run on Linux with CAP_NET_ADMIN, the sandbox to run as a dedicated real uid
 * (see [BwrapSandboxConfig.unshareUser] = false), and `nft` on PATH. Rendering is pure and unit-tested;
 * [applyIfSupported] is a guarded best-effort so non-Linux dev environments degrade to soft mode.
 */
object NftablesJail {
    private val logger = LoggerFactory.getLogger(NftablesJail::class.java)
    private const val TABLE = "sidekick_egress"

    /** Renders the `nft -f` ruleset. [proxyUid] keeps the proxy's own egress open; [sandboxUid] is jailed. */
    fun render(sandboxUid: Int, proxyUid: Int, listenAddress: String, proxyPort: Int): String =
        """
        add table inet $TABLE
        delete table inet $TABLE
        table inet $TABLE {
            chain output {
                type filter hook output priority 0; policy accept;
                meta skuid $proxyUid accept
                meta skuid $sandboxUid ip daddr $listenAddress tcp dport $proxyPort accept
                meta skuid $sandboxUid ct state established,related accept
                meta skuid $sandboxUid drop
            }
        }
        """.trimIndent() + "\n"

    /** True when the jail can be applied here (Linux with an `nft` binary). */
    fun isSupported(): Boolean =
        System.getProperty("os.name").orEmpty().lowercase().contains("linux") && nftOnPath()

    /**
     * Applies the ruleset if [isSupported]; otherwise logs and returns false so the caller can surface
     * that enforcement is not active (soft mode).
     */
    fun applyIfSupported(sandboxUid: Int, proxyUid: Int, listenAddress: String, proxyPort: Int): Boolean {
        if (!isSupported()) {
            logger.warn(
                "nftables egress jail NOT applied (unsupported here): sandbox uid {} can bypass the proxy. " +
                    "Deploy on Linux with CAP_NET_ADMIN + nft for hard enforcement.",
                sandboxUid,
            )
            return false
        }
        val ruleset = render(sandboxUid, proxyUid, listenAddress, proxyPort)
        val process = ProcessBuilder("nft", "-f", "-").redirectErrorStream(true).start()
        process.outputStream.use { it.write(ruleset.toByteArray()) }
        val finished = process.waitFor(10, TimeUnit.SECONDS)
        val output = process.inputStream.readBytes().decodeToString()
        if (!finished || process.exitValue() != 0) {
            error("Failed to install nftables egress jail (exit=${if (finished) process.exitValue() else "timeout"}): $output")
        }
        logger.info("Installed nftables egress jail: sandbox uid {} restricted to {}:{}", sandboxUid, listenAddress, proxyPort)
        return true
    }

    /** Best-effort detection of the current (proxy) process uid on Linux. */
    fun currentUid(): Int? =
        runCatching { Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Int }.getOrNull()

    private fun nftOnPath(): Boolean =
        runCatching {
            val p = ProcessBuilder("nft", "--version").redirectErrorStream(true).start()
            p.waitFor(5, TimeUnit.SECONDS) && p.exitValue() == 0
        }.getOrDefault(false)
}

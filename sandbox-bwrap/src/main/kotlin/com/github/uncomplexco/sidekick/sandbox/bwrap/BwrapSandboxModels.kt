package com.github.uncomplexco.sidekick.sandbox.bwrap

import java.nio.file.Path

data class BwrapSandboxConfig(
    val bwrapPath: String = "bwrap",
    val rootfs: Path,
    val maxOutputBytes: Int,
    val uid: Int,
    val gid: Int,
    /**
     * Whether to create a new user namespace (`--unshare-user`). Must be `false` for the nftables
     * egress jail: owner-match (`meta skuid`) keys on the socket owner's uid in the host namespace, so
     * the sandbox has to run as a real host [uid] rather than a namespace-mapped one. Dropping the user
     * namespace requires the launcher to have the privilege to setuid to [uid].
     */
    val unshareUser: Boolean = true,
)

data class BwrapSandboxRequest(
    val command: String,
    val workdir: String,
    val timeoutSeconds: Long,
    val networkEnabled: Boolean,
    val mounts: List<BwrapMount>,
    /**
     * Extra environment variables injected into the sandbox via `--setenv`, on top of the fixed
     * allowlist. Restricted to proxy / CA-trust variables (see [BwrapSandbox]); this is how the
     * egress proxy points sandboxed tools at itself without ever exposing a credential.
     */
    val env: Map<String, String> = emptyMap(),
)

data class BwrapMount(
    val source: Path,
    val target: String,
    val mode: BwrapMountMode,
)

enum class BwrapMountMode {
    RO,
    RW,
}

data class BwrapSandboxResult(
    val ok: Boolean,
    val exitCode: Int?,
    val timedOut: Boolean,
    val outputTruncated: Boolean,
    val output: String,
    val workdir: String,
)

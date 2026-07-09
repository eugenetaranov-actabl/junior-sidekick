package com.github.uncomplexco.sidekick.sandbox.bwrap

import org.junit.jupiter.api.Test
import java.nio.file.Files
import kotlin.io.path.pathString
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class BwrapSandboxTest {
    @Test
    fun `execute passes normalized request to bwrap process`() {
        // Arrange
        val temp = Files.createTempDirectory("bwrap-sandbox-test")
        val fakeBwrap = fakeBwrap(temp, "printf '%s\\n' \"\$@\"")
        val rootfs = Files.createDirectory(temp.resolve("rootfs"))
        val scratch = Files.createDirectory(temp.resolve("scratch"))
        val sandbox =
            BwrapSandbox(
                BwrapSandboxConfig(
                    bwrapPath = fakeBwrap.pathString,
                    rootfs = rootfs,
                    maxOutputBytes = 10_000,
                    uid = 123,
                    gid = 456,
                ),
            )

        // Act
        val result =
            sandbox.execute(
                BwrapSandboxRequest(
                    command = "pwd",
                    workdir = "tmp",
                    timeoutSeconds = 5,
                    networkEnabled = false,
                    mounts = listOf(BwrapMount(scratch, "/work", BwrapMountMode.RW)),
                ),
            )

        // Assert
        assertEquals(true, result.ok)
        assertEquals(0, result.exitCode)
        assertEquals("/tmp", result.workdir)
        assertTrue(result.output.lines().contains("--unshare-net"), result.output)
        assertTrue(result.output.lines().contains("--bind"), result.output)
        assertTrue(result.output.lines().contains(scratch.pathString), result.output)
        assertTrue(result.output.lines().contains("/work"), result.output)
        assertTrue(result.output.lines().contains("pwd"), result.output)
    }

    @Test
    fun `execute caps process output`() {
        // Arrange
        val temp = Files.createTempDirectory("bwrap-sandbox-test")
        val fakeBwrap = fakeBwrap(temp, "printf 'abcdef'")
        val rootfs = Files.createDirectory(temp.resolve("rootfs"))
        val sandbox =
            BwrapSandbox(
                BwrapSandboxConfig(
                    bwrapPath = fakeBwrap.pathString,
                    rootfs = rootfs,
                    maxOutputBytes = 3,
                    uid = 123,
                    gid = 456,
                ),
            )

        // Act
        val result =
            sandbox.execute(
                BwrapSandboxRequest(
                    command = "ignored",
                    workdir = "/",
                    timeoutSeconds = 5,
                    networkEnabled = true,
                    mounts = emptyList(),
                ),
            )

        // Assert
        assertEquals("abc", result.output)
        assertEquals(true, result.outputTruncated)
    }

    @Test
    fun `execute omits network namespace isolation when network is enabled`() {
        // Arrange
        val temp = Files.createTempDirectory("bwrap-sandbox-test")
        val fakeBwrap = fakeBwrap(temp, "printf '%s\\n' \"\$@\"")
        val rootfs = Files.createDirectory(temp.resolve("rootfs"))
        val sandbox =
            BwrapSandbox(
                BwrapSandboxConfig(
                    bwrapPath = fakeBwrap.pathString,
                    rootfs = rootfs,
                    maxOutputBytes = 10_000,
                    uid = 123,
                    gid = 456,
                ),
            )

        // Act
        val result =
            sandbox.execute(
                BwrapSandboxRequest(
                    command = "pwd",
                    workdir = "/",
                    timeoutSeconds = 5,
                    networkEnabled = true,
                    mounts = emptyList(),
                ),
            )

        // Assert
        assertTrue("--unshare-net" !in result.output.lines(), result.output)
    }

    @Test
    fun `execute injects allowlisted env vars as setenv`() {
        // Arrange
        val temp = Files.createTempDirectory("bwrap-sandbox-test")
        val fakeBwrap = fakeBwrap(temp, "printf '%s\\n' \"\$@\"")
        val rootfs = Files.createDirectory(temp.resolve("rootfs"))
        val sandbox =
            BwrapSandbox(
                BwrapSandboxConfig(bwrapPath = fakeBwrap.pathString, rootfs = rootfs, maxOutputBytes = 10_000, uid = 1, gid = 1),
            )

        // Act
        val result =
            sandbox.execute(
                BwrapSandboxRequest(
                    command = "pwd",
                    workdir = "/",
                    timeoutSeconds = 5,
                    networkEnabled = true,
                    mounts = emptyList(),
                    env = mapOf("HTTPS_PROXY" to "http://127.0.0.1:8888", "CURL_CA_BUNDLE" to "/etc/sidekick/egress-ca.crt"),
                ),
            )

        // Assert
        val lines = result.output.lines()
        assertTrue(lines.contains("HTTPS_PROXY"), result.output)
        assertTrue(lines.contains("http://127.0.0.1:8888"), result.output)
        assertTrue(lines.contains("CURL_CA_BUNDLE"), result.output)
        assertTrue(lines.contains("/etc/sidekick/egress-ca.crt"), result.output)
    }

    @Test
    fun `execute rejects env vars outside the allowlist`() {
        // Arrange
        val temp = Files.createTempDirectory("bwrap-sandbox-test")
        val fakeBwrap = fakeBwrap(temp, "printf 'x'")
        val rootfs = Files.createDirectory(temp.resolve("rootfs"))
        val sandbox =
            BwrapSandbox(
                BwrapSandboxConfig(bwrapPath = fakeBwrap.pathString, rootfs = rootfs, maxOutputBytes = 10_000, uid = 1, gid = 1),
            )

        // Act + Assert: a secret-bearing var must never be settable in the sandbox.
        kotlin.test.assertFailsWith<IllegalArgumentException> {
            sandbox.execute(
                BwrapSandboxRequest(
                    command = "pwd",
                    workdir = "/",
                    timeoutSeconds = 5,
                    networkEnabled = true,
                    mounts = emptyList(),
                    env = mapOf("AWS_SECRET_ACCESS_KEY" to "leaked"),
                ),
            )
        }
    }

    @Test
    fun `execute omits user namespace when unshareUser is false`() {
        // Arrange: nftables owner-match needs a real host uid, so the user namespace must be dropped.
        val temp = Files.createTempDirectory("bwrap-sandbox-test")
        val fakeBwrap = fakeBwrap(temp, "printf '%s\\n' \"\$@\"")
        val rootfs = Files.createDirectory(temp.resolve("rootfs"))
        val sandbox =
            BwrapSandbox(
                BwrapSandboxConfig(
                    bwrapPath = fakeBwrap.pathString,
                    rootfs = rootfs,
                    maxOutputBytes = 10_000,
                    uid = 6000,
                    gid = 6000,
                    unshareUser = false,
                ),
            )

        // Act
        val result =
            sandbox.execute(
                BwrapSandboxRequest(
                    command = "pwd",
                    workdir = "/",
                    timeoutSeconds = 5,
                    networkEnabled = true,
                    mounts = emptyList(),
                ),
            )

        // Assert
        val lines = result.output.lines()
        assertTrue("--unshare-user" !in lines, result.output)
        assertTrue(lines.contains("6000"), result.output)
    }

    private fun fakeBwrap(
        directory: java.nio.file.Path,
        body: String,
    ): java.nio.file.Path {
        val script = directory.resolve("fake-bwrap")
        Files.writeString(
            script,
            """
            #!/usr/bin/env bash
            $body
            """.trimIndent(),
        )
        script.toFile().setExecutable(true)
        return script
    }
}

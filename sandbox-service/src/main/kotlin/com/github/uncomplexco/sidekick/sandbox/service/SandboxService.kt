package com.github.uncomplexco.sidekick.sandbox.service

import com.github.uncomplexco.sidekick.sandbox.bwrap.BwrapSandbox
import com.github.uncomplexco.sidekick.sandbox.bwrap.BwrapSandboxConfig
import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationStarted
import io.ktor.server.application.ApplicationStopping
import io.ktor.server.application.log
import io.ktor.server.application.install
import io.ktor.server.netty.EngineMain
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation
import kotlinx.serialization.json.Json
import com.github.uncomplexco.sidekick.sandbox.bwrap.BwrapSandboxRequest

fun main(args: Array<String>): Unit = EngineMain.main(args)

fun Application.module() {
    sandboxServiceModule(SandboxServiceConfig.fromApplicationConfig(environment.config))
}

fun Application.sandboxServiceModule(
    config: SandboxServiceConfig,
    egressConfig: EgressServiceConfig? = EgressServiceConfig.fromApplicationConfig(environment.config),
    executor: SandboxCommandExecutor = bwrapExecutor(config, unshareUser = egressConfig?.enforce != true),
) {
    install(ContentNegotiation) {
        json(
            Json {
                ignoreUnknownKeys = false
                explicitNulls = false
            },
        )
    }

    val egress =
        egressConfig?.let {
            EgressProxyRuntime.start(
                config = it,
                systemCaBundle = config.rootfs.resolve("etc/ssl/certs/ca-certificates.crt"),
                sandboxUid = config.uid,
            )
        }
    val augmentRequest: (BwrapSandboxRequest) -> BwrapSandboxRequest = egress?.augmentRequest ?: { it }

    monitor.subscribe(ApplicationStarted) {
        log.info("Sandbox service started (egress proxy {})", if (egress != null) "enabled" else "disabled")
    }
    monitor.subscribe(ApplicationStopping) {
        egress?.stop()
    }

    executeRoute(
        token = config.token,
        mountSourcePolicy = MountSourcePolicy(config.allowedSourcePrefixes),
        executor = executor,
        augmentRequest = augmentRequest,
    )
}

private fun bwrapExecutor(config: SandboxServiceConfig, unshareUser: Boolean = true): SandboxCommandExecutor {
    val sandbox =
        BwrapSandbox(
            BwrapSandboxConfig(
                bwrapPath = config.bwrapPath,
                rootfs = config.rootfs,
                maxOutputBytes = config.maxOutputBytes,
                uid = config.uid,
                gid = config.gid,
                unshareUser = unshareUser,
            ),
        )
    return SandboxCommandExecutor { sandbox.execute(it) }
}

package com.github.uncomplexco.sidekick.adapters.sandbox

import com.github.uncomplexco.sidekick.ports.sandbox.SandboxExecutor
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.stereotype.Component

@Component
class SandboxExecutorFactory(
    private val config: SandboxExecutorConfig,
) {
    fun create(): SandboxExecutor =
        when (config.provider.trim().lowercase()) {
            "http" -> httpExecutor()
            else -> error("Unsupported bash sandbox provider: ${config.provider}")
        }

    private fun httpExecutor(): SandboxExecutor {
        val http = config.http
        if (http.baseUrl.isBlank()) {
            error("Bash sandbox HTTP base URL is not configured")
        }
        if (http.token.isBlank()) {
            error("Bash sandbox HTTP token is not configured")
        }
        return HttpSandboxExecutor(
            baseUrl = http.baseUrl,
            token = http.token,
        )
    }
}

@Component
@ConfigurationProperties(prefix = "agent.tools.bash")
class SandboxExecutorConfig {
    var provider: String = "http"
    var http: HttpProviderConfig = HttpProviderConfig()
}

class HttpProviderConfig {
    var baseUrl: String = ""
    var token: String = ""
}

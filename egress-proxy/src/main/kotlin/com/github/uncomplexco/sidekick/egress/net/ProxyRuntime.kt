package com.github.uncomplexco.sidekick.egress.net

import com.github.uncomplexco.sidekick.egress.cred.CredentialSource
import com.github.uncomplexco.sidekick.egress.policy.EgressPolicy
import io.netty.channel.EventLoopGroup
import java.net.InetSocketAddress

/** Maps a CONNECT target (host, port) to the socket address the proxy actually dials. */
fun interface UpstreamResolver {
    fun resolve(host: String, port: Int): InetSocketAddress

    companion object {
        /** Production default: dial the requested host/port directly (DNS handled by the OS). */
        val DIRECT = UpstreamResolver { host, port -> InetSocketAddress(host, port) }
    }
}

/** Shared, per-server collaborators handed to each connection's handlers. */
class ProxyRuntime(
    val policy: EgressPolicy,
    val credentialSource: CredentialSource,
    val sslContexts: ProxySslContexts,
    val upstreamResolver: UpstreamResolver,
    /** Event loop used for outbound (upstream) connections. */
    val upstreamGroup: EventLoopGroup,
    val maxBodyBytes: Int = 16 * 1024 * 1024,
)

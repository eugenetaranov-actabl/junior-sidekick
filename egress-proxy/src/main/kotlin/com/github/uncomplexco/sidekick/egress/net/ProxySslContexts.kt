package com.github.uncomplexco.sidekick.egress.net

import com.github.uncomplexco.sidekick.egress.ca.LeafCertFactory
import io.netty.handler.ssl.ApplicationProtocolConfig
import io.netty.handler.ssl.ApplicationProtocolNames
import io.netty.handler.ssl.SslContext
import io.netty.handler.ssl.SslContextBuilder
import java.util.concurrent.ConcurrentHashMap

/**
 * Builds the two families of SSL contexts the proxy needs:
 *  - server contexts (one per SNI host) presenting a leaf minted by our CA to the sandbox client;
 *  - the client context used to re-originate a validated TLS connection to the real upstream.
 *
 * All negotiate HTTP/1.1 only (ALPN), so the datapath never has to rewrite HTTP/2 header frames.
 */
class ProxySslContexts(
    private val leafFactory: LeafCertFactory,
    /** Upstream trust. Default validates against the system trust store. Tests may inject a custom one. */
    val upstreamContext: SslContext = defaultUpstreamContext(),
) {
    private val serverContexts = ConcurrentHashMap<String, SslContext>()

    /** Server-side context presenting a leaf cert for [host], cached per host. */
    fun serverContext(host: String): SslContext =
        serverContexts.computeIfAbsent(host.lowercase()) {
            val leaf = leafFactory.get(it)
            SslContextBuilder
                .forServer(leaf.privateKey, *leaf.chain)
                .applicationProtocolConfig(http1Only())
                .build()
        }

    companion object {
        fun defaultUpstreamContext(): SslContext =
            SslContextBuilder
                .forClient()
                .applicationProtocolConfig(http1Only())
                .build()

        private fun http1Only(): ApplicationProtocolConfig =
            ApplicationProtocolConfig(
                ApplicationProtocolConfig.Protocol.ALPN,
                ApplicationProtocolConfig.SelectorFailureBehavior.NO_ADVERTISE,
                ApplicationProtocolConfig.SelectedListenerFailureBehavior.ACCEPT,
                ApplicationProtocolNames.HTTP_1_1,
            )
    }
}

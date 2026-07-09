package com.github.uncomplexco.sidekick.egress.net

import com.github.uncomplexco.sidekick.egress.cred.CredentialSource
import com.github.uncomplexco.sidekick.egress.ca.LeafCertFactory
import com.github.uncomplexco.sidekick.egress.ca.ProxyCa
import com.github.uncomplexco.sidekick.egress.policy.EgressPolicy
import io.netty.bootstrap.ServerBootstrap
import io.netty.channel.Channel
import io.netty.channel.ChannelInitializer
import io.netty.channel.ChannelOption
import io.netty.channel.EventLoopGroup
import io.netty.channel.nio.NioEventLoopGroup
import io.netty.channel.socket.SocketChannel
import io.netty.channel.socket.nio.NioServerSocketChannel
import io.netty.handler.codec.http.HttpObjectAggregator
import io.netty.handler.codec.http.HttpServerCodec
import org.slf4j.LoggerFactory
import java.net.InetSocketAddress

/**
 * A forward MITM proxy the sandbox points `HTTPS_PROXY` at. It terminates TLS only for hosts with a
 * TERMINATE rule (to inject credentials the sandbox never sees) and blind-tunnels everything else.
 *
 * Bind with [start]; the OS-assigned port (when [requestedPort] is 0) is available as [boundPort].
 */
class EgressProxyServer(
    private val ca: ProxyCa,
    policy: EgressPolicy,
    credentialSource: CredentialSource,
    private val bindAddress: String = "127.0.0.1",
    private val requestedPort: Int = 0,
    private val upstreamResolver: UpstreamResolver = UpstreamResolver.DIRECT,
    upstreamContext: io.netty.handler.ssl.SslContext = ProxySslContexts.defaultUpstreamContext(),
) {
    private val logger = LoggerFactory.getLogger(EgressProxyServer::class.java)

    private val bossGroup: EventLoopGroup = NioEventLoopGroup(1)
    private val workerGroup: EventLoopGroup = NioEventLoopGroup()

    private val runtime =
        ProxyRuntime(
            policy = policy,
            credentialSource = credentialSource,
            sslContexts = ProxySslContexts(LeafCertFactory(ca), upstreamContext),
            upstreamResolver = upstreamResolver,
            upstreamGroup = workerGroup,
        )

    private var channel: Channel? = null

    val boundPort: Int
        get() = (channel?.localAddress() as? InetSocketAddress)?.port
            ?: error("Proxy is not started")

    fun start(): EgressProxyServer {
        val bootstrap =
            ServerBootstrap()
                .group(bossGroup, workerGroup)
                .channel(NioServerSocketChannel::class.java)
                .childOption(ChannelOption.AUTO_READ, true)
                .childHandler(
                    object : ChannelInitializer<SocketChannel>() {
                        override fun initChannel(ch: SocketChannel) {
                            ch.pipeline().addLast("http-codec", HttpServerCodec())
                            ch.pipeline().addLast("http-agg", HttpObjectAggregator(64 * 1024))
                            ch.pipeline().addLast("connect", ConnectHandler(runtime))
                        }
                    },
                )
        channel = bootstrap.bind(bindAddress, requestedPort).sync().channel()
        logger.info("Egress proxy listening on {}:{}", bindAddress, boundPort)
        return this
    }

    fun stop() {
        channel?.close()?.sync()
        workerGroup.shutdownGracefully()
        bossGroup.shutdownGracefully()
    }

    /** The CA public certificate (PEM) to mount into the sandbox so it trusts terminated hosts. */
    fun caCertificatePem(): String = ca.certificatePem()
}

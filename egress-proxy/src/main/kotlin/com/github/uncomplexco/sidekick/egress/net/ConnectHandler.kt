package com.github.uncomplexco.sidekick.egress.net

import com.github.uncomplexco.sidekick.egress.policy.EgressAction
import io.netty.bootstrap.Bootstrap
import io.netty.channel.Channel
import io.netty.channel.ChannelFutureListener
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelInitializer
import io.netty.channel.ChannelOption
import io.netty.channel.SimpleChannelInboundHandler
import io.netty.channel.socket.SocketChannel
import io.netty.channel.socket.nio.NioSocketChannel
import io.netty.handler.codec.http.DefaultFullHttpResponse
import io.netty.handler.codec.http.FullHttpRequest
import io.netty.handler.codec.http.HttpHeaderNames
import io.netty.handler.codec.http.HttpMethod
import io.netty.handler.codec.http.HttpObjectAggregator
import io.netty.handler.codec.http.HttpResponseStatus
import io.netty.handler.codec.http.HttpServerCodec
import io.netty.handler.codec.http.HttpVersion
import org.slf4j.LoggerFactory

/**
 * Handles the first request on a client connection. For `CONNECT` it applies the host-level policy
 * decision: deny (403), blind-tunnel, or MITM-terminate. Non-CONNECT (plaintext absolute-URI)
 * requests are refused for now unless a rule opts into plaintext injection (deferred), since
 * injecting over cleartext would leak the secret upstream.
 */
class ConnectHandler(
    private val runtime: ProxyRuntime,
) : SimpleChannelInboundHandler<FullHttpRequest>() {
    private val logger = LoggerFactory.getLogger(ConnectHandler::class.java)

    override fun channelRead0(ctx: ChannelHandlerContext, request: FullHttpRequest) {
        if (request.method() != HttpMethod.CONNECT) {
            logger.debug("Refusing non-CONNECT request to {}", request.uri())
            respondAndClose(ctx, HttpResponseStatus.METHOD_NOT_ALLOWED)
            return
        }

        val (host, port) = parseAuthority(request.uri())
        when (runtime.policy.decideConnect(host)) {
            EgressAction.DENY -> {
                logger.debug("Denying CONNECT to {}:{}", host, port)
                respondAndClose(ctx, HttpResponseStatus.FORBIDDEN)
            }
            EgressAction.TUNNEL -> establishTunnel(ctx, host, port)
            EgressAction.TERMINATE -> establishMitm(ctx, host, port)
        }
    }

    private fun establishMitm(ctx: ChannelHandlerContext, host: String, port: Int) {
        writeConnectEstablished(ctx) {
            val pipeline = ctx.pipeline()
            pipeline.remove("http-codec")
            pipeline.remove("http-agg")
            pipeline.remove("connect")
            pipeline.addLast("ssl", runtime.sslContexts.serverContext(host).newHandler(ctx.alloc()))
            pipeline.addLast("http-codec", HttpServerCodec())
            pipeline.addLast("http-agg", HttpObjectAggregator(runtime.maxBodyBytes))
            pipeline.addLast("mitm", MitmRequestHandler(runtime, host, port))
        }
    }

    private fun establishTunnel(ctx: ChannelHandlerContext, host: String, port: Int) {
        val clientChannel = ctx.channel()
        val bootstrap =
            Bootstrap()
                .group(runtime.upstreamGroup)
                .channel(NioSocketChannel::class.java)
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 15_000)
                .handler(
                    object : ChannelInitializer<SocketChannel>() {
                        override fun initChannel(ch: SocketChannel) {
                            // Bytes only flow after both sides are wired; add the relay once connected.
                        }
                    },
                )

        bootstrap.connect(runtime.upstreamResolver.resolve(host, port)).addListener(
            ChannelFutureListener { future ->
                if (!future.isSuccess) {
                    logger.debug("Tunnel connect to {}:{} failed", host, port)
                    respondAndClose(ctx, HttpResponseStatus.BAD_GATEWAY)
                    return@ChannelFutureListener
                }
                val upstream: Channel = future.channel()
                writeConnectEstablished(ctx) {
                    val pipeline = ctx.pipeline()
                    pipeline.remove("http-codec")
                    pipeline.remove("http-agg")
                    pipeline.remove("connect")
                    pipeline.addLast(RelayHandler(upstream))
                    upstream.pipeline().addLast(RelayHandler(clientChannel))
                }
            },
        )
    }

    /** Sends `200 Connection Established`, then runs [afterEncoded] once the response is on the wire. */
    private fun writeConnectEstablished(ctx: ChannelHandlerContext, afterEncoded: () -> Unit) {
        val response = DefaultFullHttpResponse(HttpVersion.HTTP_1_1, CONNECTION_ESTABLISHED)
        ctx.writeAndFlush(response).addListener { future ->
            if ((future as io.netty.channel.ChannelFuture).isSuccess) {
                afterEncoded()
            } else {
                ctx.close()
            }
        }
    }

    private fun respondAndClose(ctx: ChannelHandlerContext, status: HttpResponseStatus) {
        val response = DefaultFullHttpResponse(HttpVersion.HTTP_1_1, status)
        response.headers().set(HttpHeaderNames.CONTENT_LENGTH, 0)
        ctx.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE)
    }

    override fun exceptionCaught(ctx: ChannelHandlerContext, cause: Throwable) {
        logger.debug("Client connection error: {}", cause.message)
        ctx.close()
    }

    private fun parseAuthority(authority: String): Pair<String, Int> {
        val idx = authority.lastIndexOf(':')
        return if (idx > 0 && idx < authority.length - 1) {
            authority.substring(0, idx) to (authority.substring(idx + 1).toIntOrNull() ?: 443)
        } else {
            authority to 443
        }
    }

    companion object {
        private val CONNECTION_ESTABLISHED = HttpResponseStatus(200, "Connection Established")
    }
}

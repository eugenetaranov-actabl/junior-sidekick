package com.github.uncomplexco.sidekick.egress.net

import com.github.uncomplexco.sidekick.egress.cred.Secret
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
import io.netty.handler.codec.http.FullHttpResponse
import io.netty.handler.codec.http.HttpClientCodec
import io.netty.handler.codec.http.HttpHeaderNames
import io.netty.handler.codec.http.HttpObjectAggregator
import io.netty.handler.codec.http.HttpResponseStatus
import io.netty.handler.codec.http.HttpUtil
import io.netty.handler.codec.http.HttpVersion
import io.netty.util.AsciiString
import org.slf4j.LoggerFactory

/**
 * Runs on the decrypted side of a MITM-terminated connection. For each request it resolves the
 * governing rule, injects the configured header (the secret is read from the [Secret], written to
 * the header, and wiped), and re-originates the request over a fresh validated TLS connection to the
 * real upstream. Response bodies are aggregated then streamed back to the client.
 */
class MitmRequestHandler(
    private val runtime: ProxyRuntime,
    private val host: String,
    private val port: Int,
) : SimpleChannelInboundHandler<FullHttpRequest>() {
    private val logger = LoggerFactory.getLogger(MitmRequestHandler::class.java)

    override fun channelRead0(ctx: ChannelHandlerContext, request: FullHttpRequest) {
        val rule = runtime.policy.matchRequest(host, request.uri())

        if (rule != null && rule.action == EgressAction.DENY) {
            respondAndClose(ctx, HttpResponseStatus.FORBIDDEN)
            return
        }

        if (rule != null && rule.action == EgressAction.TERMINATE) {
            injectHeader(request, rule.header!!, rule.valueTemplate!!, rule.credentialRef!!)
        }

        forwardUpstream(ctx, request.retain())
    }

    private fun injectHeader(request: FullHttpRequest, header: String, template: String, credentialRef: String) {
        val secret = runtime.credentialSource.resolve(credentialRef)
        if (secret == null) {
            logger.warn("No credential configured for ref '{}'; forwarding without injection", credentialRef)
            return
        }
        secret.use {
            val rendered = it.renderInto(template)
            try {
                // AsciiString(char[]) keeps the value out of the String pool; wipe our copy afterwards.
                request.headers().set(header, AsciiString(rendered))
            } finally {
                Secret.wipe(rendered)
            }
        }
    }

    private fun forwardUpstream(clientCtx: ChannelHandlerContext, request: FullHttpRequest) {
        val clientChannel = clientCtx.channel()
        val bootstrap =
            Bootstrap()
                .group(runtime.upstreamGroup)
                .channel(NioSocketChannel::class.java)
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 15_000)
                .handler(
                    object : ChannelInitializer<SocketChannel>() {
                        override fun initChannel(ch: SocketChannel) {
                            val sslHandler = runtime.sslContexts.upstreamContext.newHandler(ch.alloc(), host, port)
                            val engine = sslHandler.engine()
                            engine.sslParameters =
                                engine.sslParameters.apply { endpointIdentificationAlgorithm = "HTTPS" }
                            ch.pipeline().addLast(sslHandler)
                            ch.pipeline().addLast(HttpClientCodec())
                            ch.pipeline().addLast(HttpObjectAggregator(runtime.maxBodyBytes))
                            ch.pipeline().addLast(UpstreamResponseHandler(clientChannel))
                        }
                    },
                )

        bootstrap.connect(runtime.upstreamResolver.resolve(host, port)).addListener(
            ChannelFutureListener { future ->
                if (future.isSuccess) {
                    future.channel().writeAndFlush(request)
                } else {
                    logger.warn("Upstream connect to {}:{} failed: {}", host, port, future.cause()?.message)
                    request.release()
                    respondAndClose(clientCtx, HttpResponseStatus.BAD_GATEWAY)
                }
            },
        )
    }

    private fun respondAndClose(ctx: ChannelHandlerContext, status: HttpResponseStatus) {
        val response = DefaultFullHttpResponse(HttpVersion.HTTP_1_1, status)
        response.headers().set(HttpHeaderNames.CONTENT_LENGTH, 0)
        ctx.writeAndFlush(response).addListener(ChannelFutureListener.CLOSE)
    }

    override fun exceptionCaught(ctx: ChannelHandlerContext, cause: Throwable) {
        logger.debug("MITM client channel error: {}", cause.message)
        ctx.close()
    }
}

/** Relays the aggregated upstream response back to the client, then closes the (per-request) upstream. */
private class UpstreamResponseHandler(
    private val clientChannel: Channel,
) : SimpleChannelInboundHandler<FullHttpResponse>() {
    override fun channelRead0(ctx: ChannelHandlerContext, response: FullHttpResponse) {
        val keepAlive = HttpUtil.isKeepAlive(response)
        clientChannel.writeAndFlush(response.retain()).addListener { future ->
            if (!keepAlive && (future as io.netty.channel.ChannelFuture).isDone) {
                clientChannel.close()
            }
        }
        ctx.close() // upstream connection is per-request
    }

    override fun exceptionCaught(ctx: ChannelHandlerContext, cause: Throwable) {
        ctx.close()
        clientChannel.close()
    }
}

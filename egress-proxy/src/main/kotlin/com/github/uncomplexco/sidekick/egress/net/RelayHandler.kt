package com.github.uncomplexco.sidekick.egress.net

import io.netty.buffer.ByteBuf
import io.netty.channel.Channel
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.SimpleChannelInboundHandler

/**
 * Pumps raw bytes from one channel to its peer. Two of these (client-to-upstream and
 * upstream-to-client) form a blind TLS tunnel: the proxy never decrypts, so the upstream's real
 * certificate reaches the sandbox client (cert-pinning-safe) and no header injection is possible.
 */
class RelayHandler(
    private val peer: Channel,
) : SimpleChannelInboundHandler<ByteBuf>() {
    override fun channelRead0(ctx: ChannelHandlerContext, msg: ByteBuf) {
        if (peer.isActive) {
            peer.writeAndFlush(msg.retain())
        }
    }

    override fun channelInactive(ctx: ChannelHandlerContext) {
        if (peer.isActive) {
            peer.close()
        }
    }

    override fun exceptionCaught(ctx: ChannelHandlerContext, cause: Throwable) {
        ctx.close()
        if (peer.isActive) {
            peer.close()
        }
    }
}

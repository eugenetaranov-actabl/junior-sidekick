package com.github.uncomplexco.sidekick.egress.net

import com.github.uncomplexco.sidekick.egress.ca.LeafCertFactory
import com.github.uncomplexco.sidekick.egress.ca.ProxyCa
import com.github.uncomplexco.sidekick.egress.cred.ConfigCredentialSource
import com.github.uncomplexco.sidekick.egress.policy.EgressAction
import com.github.uncomplexco.sidekick.egress.policy.EgressPolicy
import com.github.uncomplexco.sidekick.egress.policy.EgressRule
import io.netty.bootstrap.ServerBootstrap
import io.netty.buffer.Unpooled
import io.netty.channel.Channel
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelInboundHandlerAdapter
import io.netty.channel.ChannelInitializer
import io.netty.channel.EventLoopGroup
import io.netty.channel.nio.NioEventLoopGroup
import io.netty.channel.socket.SocketChannel
import io.netty.channel.socket.nio.NioServerSocketChannel
import io.netty.handler.codec.http.DefaultFullHttpResponse
import io.netty.handler.codec.http.FullHttpRequest
import io.netty.handler.codec.http.HttpHeaderNames
import io.netty.handler.codec.http.HttpObjectAggregator
import io.netty.handler.codec.http.HttpResponseStatus
import io.netty.handler.codec.http.HttpServerCodec
import io.netty.handler.codec.http.HttpVersion
import io.netty.channel.SimpleChannelInboundHandler
import io.netty.handler.ssl.SslContextBuilder
import java.io.IOException
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.ProxySelector
import java.net.Socket
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.KeyStore
import java.security.cert.X509Certificate
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class EgressProxyServerIntegrationTest {
    private val token = "SECRET-TOKEN-123"

    private lateinit var echoGroup: EventLoopGroup
    private lateinit var httpsEcho: Channel
    private lateinit var tcpEcho: Channel
    private lateinit var proxy: EgressProxyServer
    private lateinit var proxyCa: ProxyCa

    @BeforeTest
    fun setUp() {
        echoGroup = NioEventLoopGroup()

        // Upstream HTTPS echo presenting a cert for jira.test, signed by its own CA.
        val echoCa = ProxyCa.generate()
        val echoLeaf = LeafCertFactory(echoCa).get("jira.test")
        val echoServerContext = SslContextBuilder.forServer(echoLeaf.privateKey, *echoLeaf.chain).build()
        httpsEcho =
            ServerBootstrap()
                .group(echoGroup)
                .channel(NioServerSocketChannel::class.java)
                .childHandler(
                    object : ChannelInitializer<SocketChannel>() {
                        override fun initChannel(ch: SocketChannel) {
                            ch.pipeline().addLast(echoServerContext.newHandler(ch.alloc()))
                            ch.pipeline().addLast(HttpServerCodec())
                            ch.pipeline().addLast(HttpObjectAggregator(65536))
                            ch.pipeline().addLast(AuthEchoHandler())
                        }
                    },
                )
                .bind("127.0.0.1", 0).sync().channel()

        // Raw TCP echo for the blind-tunnel case.
        tcpEcho =
            ServerBootstrap()
                .group(echoGroup)
                .channel(NioServerSocketChannel::class.java)
                .childHandler(
                    object : ChannelInitializer<SocketChannel>() {
                        override fun initChannel(ch: SocketChannel) {
                            ch.pipeline().addLast(
                                object : ChannelInboundHandlerAdapter() {
                                    override fun channelRead(ctx: ChannelHandlerContext, msg: Any) {
                                        ctx.writeAndFlush(msg)
                                    }
                                },
                            )
                        }
                    },
                )
                .bind("127.0.0.1", 0).sync().channel()

        val httpsPort = (httpsEcho.localAddress() as InetSocketAddress).port
        val tcpPort = (tcpEcho.localAddress() as InetSocketAddress).port

        val policy =
            EgressPolicy(
                rules =
                    listOf(
                        EgressRule(
                            id = "jira",
                            host = "jira.test",
                            action = EgressAction.TERMINATE,
                            credentialRef = "jira-token",
                            header = "Authorization",
                            valueTemplate = "Bearer {{token}}",
                        ),
                        EgressRule(id = "tunnel", host = "tunnel.test", action = EgressAction.TUNNEL),
                    ),
                defaultAction = EgressAction.DENY,
            )

        proxyCa = ProxyCa.generate()
        proxy =
            EgressProxyServer(
                ca = proxyCa,
                policy = policy,
                credentialSource = ConfigCredentialSource.fromStrings(mapOf("jira-token" to token)),
                upstreamResolver = { host, _ ->
                    if (host == "tunnel.test") InetSocketAddress("127.0.0.1", tcpPort)
                    else InetSocketAddress("127.0.0.1", httpsPort)
                },
                upstreamContext = SslContextBuilder.forClient().trustManager(echoCa.certificate).build(),
            ).start()
    }

    @AfterTest
    fun tearDown() {
        proxy.stop()
        httpsEcho.close().sync()
        tcpEcho.close().sync()
        echoGroup.shutdownGracefully()
    }

    @Test
    fun `terminate rule injects the auth header the client never sent`() {
        val client =
            HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .proxy(ProxySelector.of(InetSocketAddress("127.0.0.1", proxy.boundPort)))
                .sslContext(trustOnly(proxyCa.certificate))
                .build()

        val response =
            client.send(
                HttpRequest.newBuilder(URI.create("https://jira.test/rest/api/2/myself")).GET().build(),
                HttpResponse.BodyHandlers.ofString(),
            )

        assertEquals(200, response.statusCode())
        // The echo server reports the Authorization header it received - proving proxy-side injection.
        assertContains(response.body(), "auth=Bearer $token")
    }

    @Test
    fun `denied host fails at CONNECT`() {
        val client =
            HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .proxy(ProxySelector.of(InetSocketAddress("127.0.0.1", proxy.boundPort)))
                .sslContext(trustOnly(proxyCa.certificate))
                .build()

        assertFailsWith<IOException> {
            client.send(
                HttpRequest.newBuilder(URI.create("https://denied.test/")).GET().build(),
                HttpResponse.BodyHandlers.ofString(),
            )
        }
    }

    @Test
    fun `tunnel host relays raw bytes without termination`() {
        Socket("127.0.0.1", proxy.boundPort).use { socket ->
            val out = socket.getOutputStream()
            out.write("CONNECT tunnel.test:443 HTTP/1.1\r\nHost: tunnel.test:443\r\n\r\n".toByteArray())
            out.flush()

            val head = readUntilHeaderEnd(socket.getInputStream())
            assertContains(head, "200")

            out.write("ping".toByteArray())
            out.flush()
            val echoed = ByteArray(4)
            readFully(socket.getInputStream(), echoed)
            assertEquals("ping", String(echoed))
        }
    }

    private fun readUntilHeaderEnd(input: InputStream): String {
        val sb = StringBuilder()
        while (!sb.endsWith("\r\n\r\n")) {
            val b = input.read()
            if (b < 0) break
            sb.append(b.toChar())
        }
        return sb.toString()
    }

    private fun readFully(input: InputStream, buffer: ByteArray) {
        var read = 0
        while (read < buffer.size) {
            val n = input.read(buffer, read, buffer.size - read)
            if (n < 0) break
            read += n
        }
    }

    private fun trustOnly(cert: X509Certificate): SSLContext {
        val keyStore = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null, null)
            setCertificateEntry("ca", cert)
        }
        val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(keyStore) }
        return SSLContext.getInstance("TLS").apply { init(null, tmf.trustManagers, null) }
    }

    private class AuthEchoHandler : SimpleChannelInboundHandler<FullHttpRequest>() {
        override fun channelRead0(ctx: ChannelHandlerContext, request: FullHttpRequest) {
            val auth = request.headers().get(HttpHeaderNames.AUTHORIZATION) ?: "none"
            val body = "auth=$auth".toByteArray()
            val response =
                DefaultFullHttpResponse(HttpVersion.HTTP_1_1, HttpResponseStatus.OK, Unpooled.wrappedBuffer(body))
            response.headers().set(HttpHeaderNames.CONTENT_LENGTH, body.size)
            response.headers().set(HttpHeaderNames.CONTENT_TYPE, "text/plain")
            ctx.writeAndFlush(response)
        }
    }
}

package com.github.uncomplexco.sidekick.egress.ca

import java.nio.file.Files
import java.nio.file.Path
import javax.security.auth.x500.X500Principal
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ProxyCaTest {
    @Test
    fun `generated CA is a self-signed CA cert`() {
        val ca = ProxyCa.generate()
        ca.certificate.verify(ca.certificate.publicKey) // self-signed
        assertTrue(ca.certificate.basicConstraints >= 0, "should be a CA cert")
        assertContains(ca.certificatePem(), "BEGIN CERTIFICATE")
    }

    @Test
    fun `leaf is signed by the CA and carries the host SAN`() {
        val ca = ProxyCa.generate()
        val factory = LeafCertFactory(ca)
        val leaf = factory.get("acme.atlassian.net")

        assertEquals(2, leaf.chain.size)
        assertEquals(ca.certificate, leaf.chain[1])
        leaf.chain[0].verify(ca.certificate.publicKey) // signed by CA

        val sans = leaf.chain[0].subjectAlternativeNames.map { it[1] as String }
        assertContains(sans, "acme.atlassian.net")
        assertEquals(X500Principal("CN=acme.atlassian.net"), leaf.chain[0].subjectX500Principal)
    }

    @Test
    fun `leaf certs are cached per host`() {
        val factory = LeafCertFactory(ProxyCa.generate())
        assertTrue(factory.get("api.github.com").chain[0] === factory.get("api.github.com").chain[0])
    }

    @Test
    fun `persist then load round-trips`(@org.junit.jupiter.api.io.TempDir dir: Path) {
        val certPath = dir.resolve("ca.crt")
        val keyPath = dir.resolve("ca.key")
        val generated = ProxyCa.loadOrGenerate(certPath, keyPath)
        assertTrue(Files.exists(certPath) && Files.exists(keyPath))

        val loaded = ProxyCa.loadOrGenerate(certPath, keyPath)
        assertEquals(generated.certificate, loaded.certificate)

        // loaded key must still sign leaves that verify against the persisted cert
        val leaf = LeafCertFactory(loaded).get("api.github.com")
        leaf.chain[0].verify(loaded.certificate.publicKey)
    }
}

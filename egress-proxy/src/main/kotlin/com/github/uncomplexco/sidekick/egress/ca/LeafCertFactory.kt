package com.github.uncomplexco.sidekick.egress.ca

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.Instant
import java.util.Date
import java.util.concurrent.ConcurrentHashMap

/** A minted leaf: the chain (leaf then CA) plus the leaf's private key, ready to build an SSL context. */
class LeafMaterial(
    val chain: Array<X509Certificate>,
    val privateKey: PrivateKey,
)

/**
 * Mints short-lived leaf certificates per SNI host, each signed by [ca], caching them in memory with
 * a TTL. A single leaf key pair is generated once and reused across all hosts (only the certificate
 * differs) so per-host minting is cheap.
 */
class LeafCertFactory(
    private val ca: ProxyCa,
    private val ttl: Duration = Duration.ofHours(24),
    private val clock: () -> Instant = Instant::now,
) {
    private val leafKeyPair: KeyPair =
        KeyPairGenerator.getInstance("RSA").apply { initialize(2048, SecureRandom()) }.generateKeyPair()

    private data class CachedLeaf(val material: LeafMaterial, val expiresAt: Instant)

    private val cache = ConcurrentHashMap<String, CachedLeaf>()

    /** Returns a leaf for [host], minting and caching one if absent or expired. */
    fun get(host: String): LeafMaterial {
        val key = host.lowercase()
        val now = clock()
        val cached = cache[key]
        if (cached != null && cached.expiresAt.isAfter(now)) {
            return cached.material
        }
        val material = mint(key, now)
        cache[key] = CachedLeaf(material, now.plus(ttl))
        return material
    }

    private fun mint(host: String, now: Instant): LeafMaterial {
        val extUtils = JcaX509ExtensionUtils()
        val builder =
            JcaX509v3CertificateBuilder(
                X500Name(ca.certificate.subjectX500Principal.name),
                BigInteger.valueOf(now.toEpochMilli()).multiply(BigInteger.valueOf(1000)).add(BigInteger.valueOf(host.hashCode().toLong() and 0xffff)),
                Date.from(now.minus(Duration.ofMinutes(5))),
                Date.from(now.plus(ttl).plus(Duration.ofMinutes(5))),
                X500Name("CN=$host"),
                leafKeyPair.public,
            ).apply {
                addExtension(Extension.basicConstraints, false, BasicConstraints(false))
                addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.digitalSignature or KeyUsage.keyEncipherment))
                addExtension(Extension.extendedKeyUsage, false, ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth))
                addExtension(Extension.subjectAlternativeName, false, GeneralNames(GeneralName(GeneralName.dNSName, host)))
                addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(leafKeyPair.public))
                addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(ca.certificate))
            }
        val signer = JcaContentSignerBuilder("SHA256withRSA").build(ca.privateKey)
        val leaf =
            JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(builder.build(signer))
        return LeafMaterial(arrayOf(leaf, ca.certificate), leafKeyPair.private)
    }
}

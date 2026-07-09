package com.github.uncomplexco.sidekick.egress.ca

import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.StringWriter
import java.math.BigInteger
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Security
import java.security.cert.X509Certificate
import java.time.Duration
import java.time.Instant
import java.util.Date

/**
 * The per-instance certificate authority the proxy uses to mint leaf certs for MITM-terminated
 * hosts. The CA is generated on first use and persisted to disk (private key `0600`) so it survives
 * restarts; only its **public** cert is ever mounted into the sandbox — the private key never leaves
 * this process's host.
 */
class ProxyCa private constructor(
    val certificate: X509Certificate,
    val keyPair: KeyPair,
) {
    val privateKey: PrivateKey get() = keyPair.private

    /** The CA's public certificate in PEM form, suitable for mounting into the sandbox rootfs. */
    fun certificatePem(): String = toPem(certificate)

    companion object {
        private const val KEY_SIZE = 2048
        private val CA_VALIDITY = Duration.ofDays(3650)

        init {
            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.addProvider(BouncyCastleProvider())
            }
        }

        /**
         * Loads the CA from [certPath]/[keyPath] if both exist, otherwise generates a fresh CA and
         * persists it (creating parent dirs, key file `0600`).
         */
        fun loadOrGenerate(certPath: Path, keyPath: Path): ProxyCa =
            if (Files.exists(certPath) && Files.exists(keyPath)) {
                load(certPath, keyPath)
            } else {
                generate().also { it.persist(certPath, keyPath) }
            }

        fun generate(): ProxyCa {
            val keyPair = newRsaKeyPair()
            val now = Instant.now()
            val subject = X500Name("CN=Sidekick Egress Proxy CA")
            val extUtils = JcaX509ExtensionUtils()
            val builder =
                JcaX509v3CertificateBuilder(
                    subject,
                    BigInteger.valueOf(now.toEpochMilli()),
                    Date.from(now.minus(Duration.ofMinutes(5))),
                    Date.from(now.plus(CA_VALIDITY)),
                    subject,
                    keyPair.public,
                ).apply {
                    addExtension(Extension.basicConstraints, true, BasicConstraints(0))
                    addExtension(
                        Extension.keyUsage,
                        true,
                        KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign),
                    )
                    addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(keyPair.public))
                }
            val signer = JcaContentSignerBuilder("SHA256withRSA").build(keyPair.private)
            val cert =
                JcaX509CertificateConverter()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getCertificate(builder.build(signer))
            return ProxyCa(cert, keyPair)
        }

        private fun load(certPath: Path, keyPath: Path): ProxyCa {
            val cert =
                PEMParser(Files.newBufferedReader(certPath)).use { parser ->
                    val obj = parser.readObject()
                    JcaX509CertificateConverter()
                        .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                        .getCertificate(obj as org.bouncycastle.cert.X509CertificateHolder)
                }
            val privateKey =
                PEMParser(Files.newBufferedReader(keyPath)).use { parser ->
                    val obj = parser.readObject()
                    val converter = JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    when (obj) {
                        is org.bouncycastle.openssl.PEMKeyPair -> converter.getKeyPair(obj).private
                        is org.bouncycastle.asn1.pkcs.PrivateKeyInfo -> converter.getPrivateKey(obj)
                        else -> error("Unsupported CA key PEM object: ${obj?.javaClass}")
                    }
                }
            return ProxyCa(cert, KeyPair(cert.publicKey, privateKey))
        }

        private fun newRsaKeyPair(): KeyPair =
            KeyPairGenerator.getInstance("RSA").apply { initialize(KEY_SIZE, SecureRandom()) }.generateKeyPair()

        private fun toPem(obj: Any): String =
            StringWriter().use { sw ->
                JcaPEMWriter(sw).use { it.writeObject(obj) }
                sw.toString()
            }
    }

    private fun persist(certPath: Path, keyPath: Path) {
        certPath.parent?.let { Files.createDirectories(it) }
        Files.writeString(certPath, certificatePem())
        Files.writeString(keyPath, toPem(privateKey))
        runCatching {
            Files.setPosixFilePermissions(keyPath, setOf(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE))
        }
    }
}

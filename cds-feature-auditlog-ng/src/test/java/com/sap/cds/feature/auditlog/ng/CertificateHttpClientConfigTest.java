package com.sap.cds.feature.auditlog.ng;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.apache.http.impl.client.CloseableHttpClient;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcaPKCS8Generator;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;

/**
 * Verifies that {@link CertificateHttpClientConfig} can build an HTTP client from
 * certificate/key material regardless of the key algorithm. Historically the private
 * key was parsed with a hardcoded RSA {@code KeyFactory}, which rejected EC keys as
 * issued by non-BTP certificate providers (e.g. the Zero Trust Identity Service).
 */
class CertificateHttpClientConfigTest {

    @Test
    void buildsHttpClientFromEcCertificateAndKey() throws Exception {
        KeyPairAndPem material = selfSigned("EC", "SHA256withECDSA");

        CloseableHttpClient client = CertificateHttpClientConfig.builder()
                .certPem(material.certPem)
                .keyPem(material.keyPem)
                .build()
                .getHttpClient();

        assertNotNull(client, "EC-keyed binding should produce an HTTP client");
    }

    @Test
    void buildsHttpClientFromRsaCertificateAndKey() throws Exception {
        KeyPairAndPem material = selfSigned("RSA", "SHA256withRSA");

        assertDoesNotThrow(() -> CertificateHttpClientConfig.builder()
                .certPem(material.certPem)
                .keyPem(material.keyPem)
                .build());
    }

    private record KeyPairAndPem(String certPem, String keyPem) {
    }

    private static KeyPairAndPem selfSigned(String keyAlgorithm, String signatureAlgorithm) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(keyAlgorithm);
        if ("EC".equals(keyAlgorithm)) {
            kpg.initialize(256);
        } else {
            kpg.initialize(2048);
        }
        KeyPair keyPair = kpg.generateKeyPair();

        X500Principal subject = new X500Principal("CN=test");
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                subject,
                BigInteger.valueOf(System.currentTimeMillis()),
                Date.from(now.minus(1, ChronoUnit.HOURS)),
                Date.from(now.plus(1, ChronoUnit.DAYS)),
                subject,
                keyPair.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder(signatureAlgorithm).build(keyPair.getPrivate());
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));

        return new KeyPairAndPem(toPem(cert), keyToPkcs8Pem(keyPair.getPrivate()));
    }

    private static String toPem(Object obj) throws Exception {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(sw)) {
            writer.writeObject(obj);
        }
        return sw.toString();
    }

    // Writes the key in PKCS#8 form ("BEGIN PRIVATE KEY"), matching what the ALS
    // binding provides and what parsePrivateKey expects.
    private static String keyToPkcs8Pem(PrivateKey key) throws Exception {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(sw)) {
            writer.writeObject(new JcaPKCS8Generator(key, null));
        }
        return sw.toString();
    }
}

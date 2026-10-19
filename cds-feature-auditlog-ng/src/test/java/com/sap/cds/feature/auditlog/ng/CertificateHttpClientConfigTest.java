package com.sap.cds.feature.auditlog.ng;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;
import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.jupiter.api.Test;
import org.bouncycastle.crypto.CryptoServicesRegistrar;

class CertificateHttpClientConfigTest {

    @Test
    void parsesCertificateChainWithJca() throws Exception {
        String certificate = pem("CERTIFICATE", selfSignedCertificate(rsaKeyPair(), "auditlog-test"));

        var certificates = CertificateHttpClientConfig.parseCertificateChain(certificate);

        assertEquals(1, certificates.length);
        assertEquals("X.509", certificates[0].getType());
    }

    @Test
    void parsesGeneratedPkcs8RsaKeyWithoutBouncyCastle() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        PrivateKey expected = generator.generateKeyPair().getPrivate();
        String keyPem = pem("PRIVATE KEY", expected.getEncoded());

        PrivateKey actual = CertificateHttpClientConfig.parsePrivateKey(keyPem, new char[0]);

        assertEquals("RSA", actual.getAlgorithm());
        assertArrayEquals(expected.getEncoded(), actual.getEncoded());
    }

    @Test
    void parsesJcaEncryptedPkcs8RsaKey() throws Exception {
        KeyPair keyPair = rsaKeyPair();
        char[] passphrase = "long-enough-standard-passphrase-123".toCharArray();
        String algorithm = "PBEWithSHA1AndDESede";
        var secretKey = SecretKeyFactory.getInstance(algorithm).generateSecret(new PBEKeySpec(passphrase));
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        EncryptedPrivateKeyInfo encrypted = new EncryptedPrivateKeyInfo(
                cipher.getParameters(), cipher.doFinal(keyPair.getPrivate().getEncoded()));

        PrivateKey actual = CertificateHttpClientConfig.parsePrivateKey(
                pem("ENCRYPTED PRIVATE KEY", encrypted.getEncoded()), passphrase);

        assertArrayEquals(keyPair.getPrivate().getEncoded(), actual.getEncoded());
    }

    @Test
    void rejectsNonPkcs8Key() {
        var nonPkcs8 = assertThrows(IllegalArgumentException.class,
                () -> CertificateHttpClientConfig.parsePrivateKey(
                        pem("RSA PRIVATE KEY", new byte[] { 1, 2, 3 }), new char[0]));
        assertTrue(nonPkcs8.getMessage().contains("PKCS#8"));
    }

    @Test
    void fipsApprovedOnlyModeIsInheritedByNewThreads() throws Exception {
        FipsCryptoSupport.configureApprovedOnlyMode();

        var approvedOnAnotherThread = new CompletableFuture<Boolean>();
        new Thread(() -> approvedOnAnotherThread.complete(
                CryptoServicesRegistrar.isInApprovedOnlyMode())).start();

        assertTrue(CryptoServicesRegistrar.isInApprovedOnlyMode());
        assertTrue(approvedOnAnotherThread.get());
    }

    @Test
    void standardModeCompletesMutualTlsRequest() throws Exception {
        KeyPair serverKeyPair = rsaKeyPair();
        KeyPair clientKeyPair = rsaKeyPair();
        String serverCertificatePem = pem("CERTIFICATE", selfSignedCertificate(serverKeyPair, "localhost"));
        String clientCertificatePem = pem("CERTIFICATE", selfSignedCertificate(clientKeyPair, "auditlog-client"));
        X509Certificate serverCertificate = certificate(serverCertificatePem);
        X509Certificate clientCertificate = certificate(clientCertificatePem);
        char[] password = "test-password".toCharArray();

        KeyStoreMaterial serverMaterial = keyStore(serverKeyPair, serverCertificate, clientCertificate, password);
        HttpsServer server = HttpsServer.create(new InetSocketAddress("localhost", 0), 0);
        SSLContext serverContext = sslContext(serverMaterial.keyStore, serverMaterial.trustStore, password);
        server.setHttpsConfigurator(new HttpsConfigurator(serverContext) {
            @Override
            public void configure(HttpsParameters parameters) {
                SSLParameters sslParameters = serverContext.getDefaultSSLParameters();
                sslParameters.setNeedClientAuth(true);
                parameters.setSSLParameters(sslParameters);
            }
        });
        server.createContext("/", exchange -> {
            exchange.sendResponseHeaders(200, 0);
            exchange.getResponseBody().close();
        });
        server.start();

        Path trustStorePath = Files.createTempFile("auditlog-client-trust", ".p12");
        String oldTrustStore = System.getProperty("javax.net.ssl.trustStore");
        String oldTrustStorePassword = System.getProperty("javax.net.ssl.trustStorePassword");
        try {
            KeyStore trustStore = KeyStore.getInstance("PKCS12");
            trustStore.load(null, password);
            trustStore.setCertificateEntry("server", serverCertificate);
            try (var output = Files.newOutputStream(trustStorePath)) {
                trustStore.store(output, password);
            }
            System.setProperty("javax.net.ssl.trustStore", trustStorePath.toString());
            System.setProperty("javax.net.ssl.trustStorePassword", new String(password));

            try (CloseableHttpClient client = CertificateHttpClientConfig.builder()
                    .certPem(clientCertificatePem)
                    .keyPem(pem("PRIVATE KEY", clientKeyPair.getPrivate().getEncoded()))
                    .cryptoMode(CertificateHttpClientConfig.CryptoMode.STANDARD)
                    .build()
                    .getHttpClient();
                    CloseableHttpResponse response = client.execute(
                            new HttpGet("https://localhost:" + server.getAddress().getPort() + "/"))) {
                assertEquals(200, response.getStatusLine().getStatusCode());
            }
        } finally {
            server.stop(0);
            restoreProperty("javax.net.ssl.trustStore", oldTrustStore);
            restoreProperty("javax.net.ssl.trustStorePassword", oldTrustStorePassword);
            Files.deleteIfExists(trustStorePath);
        }
    }

    static KeyPair rsaKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static KeyStoreMaterial keyStore(
            KeyPair keyPair, X509Certificate certificate, X509Certificate trustedCertificate, char[] password)
            throws Exception {
        var keyStore = java.security.KeyStore.getInstance("PKCS12");
        keyStore.load(null, password);
        keyStore.setKeyEntry("key", keyPair.getPrivate(), password, new java.security.cert.Certificate[] { certificate });
        var trustStore = java.security.KeyStore.getInstance("PKCS12");
        trustStore.load(null, password);
        trustStore.setCertificateEntry("trusted", trustedCertificate);
        return new KeyStoreMaterial(keyStore, trustStore);
    }

    private static SSLContext sslContext(
            java.security.KeyStore keyStore, java.security.KeyStore trustStore, char[] password) throws Exception {
        KeyManagerFactory keyManagers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagers.init(keyStore, password);
        TrustManagerFactory trustManagers = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagers.init(trustStore);
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keyManagers.getKeyManagers(), trustManagers.getTrustManagers(), new SecureRandom());
        return context;
    }

    private static X509Certificate certificate(String pem) throws Exception {
        byte[] der = Base64.getMimeDecoder().decode(pem.replaceAll("-----[^-]+-----", ""));
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(der));
    }

    static byte[] selfSignedCertificate(KeyPair keyPair, String commonName) throws Exception {
        byte[] algorithm = sequence(oid(new byte[] { 0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7,
                0x0D, 0x01, 0x01, 0x0B }), der(0x05, new byte[0]));
        byte[] name = sequence(set(sequence(oid(new byte[] { 0x55, 0x04, 0x03 }),
                der(0x0C, commonName.getBytes(StandardCharsets.UTF_8)))));
        Instant now = Instant.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'").withZone(ZoneOffset.UTC);
        byte[] validity = sequence(der(0x17, formatter.format(now).getBytes(StandardCharsets.US_ASCII)),
                der(0x17, formatter.format(now.plusSeconds(86400)).getBytes(StandardCharsets.US_ASCII)));
        byte[] tbs = sequence(
                der(0xA0, integer(BigInteger.valueOf(2))),
                integer(BigInteger.valueOf(Math.max(1, System.nanoTime()))),
                algorithm,
                name,
                validity,
                name,
                keyPair.getPublic().getEncoded());
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(tbs);
        return sequence(tbs, algorithm, der(0x03, concat(new byte[] { 0 }, signature.sign())));
    }

    private static byte[] integer(BigInteger value) {
        return der(0x02, value.toByteArray());
    }

    private static byte[] oid(byte[] value) {
        return der(0x06, value);
    }

    private static byte[] sequence(byte[]... values) {
        return der(0x30, concat(values));
    }

    private static byte[] set(byte[] value) {
        return der(0x31, value);
    }

    private static byte[] der(int tag, byte[] value) {
        byte[] length = length(value.length);
        byte[] result = new byte[1 + length.length + value.length];
        result[0] = (byte) tag;
        System.arraycopy(length, 0, result, 1, length.length);
        System.arraycopy(value, 0, result, 1 + length.length, value.length);
        return result;
    }

    private static byte[] length(int length) {
        if (length < 128) {
            return new byte[] { (byte) length };
        }
        int bytes = 0;
        for (int value = length; value > 0; value >>>= 8) {
            bytes++;
        }
        byte[] result = new byte[bytes + 1];
        result[0] = (byte) (0x80 | bytes);
        for (int i = bytes; i > 0; i--) {
            result[i] = (byte) (length >>> (8 * (bytes - i)));
        }
        return result;
    }

    private static byte[] concat(byte[]... values) {
        int size = 0;
        for (byte[] value : values) {
            size += value.length;
        }
        byte[] result = new byte[size];
        int offset = 0;
        for (byte[] value : values) {
            System.arraycopy(value, 0, result, offset, value.length);
            offset += value.length;
        }
        return result;
    }

    private static void restoreProperty(String name, String value) {
        if (value == null) {
            System.clearProperty(name);
        } else {
            System.setProperty(name, value);
        }
    }

    private record KeyStoreMaterial(java.security.KeyStore keyStore, java.security.KeyStore trustStore) {
    }

    static String pem(String type, byte[] value) {
        return "-----BEGIN " + type + "-----\n"
                + Base64.getMimeEncoder(64, new byte[] { '\n' }).encodeToString(value)
                + "\n-----END " + type + "-----\n";
    }
}

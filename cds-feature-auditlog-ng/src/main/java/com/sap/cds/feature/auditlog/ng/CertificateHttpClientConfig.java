package com.sap.cds.feature.auditlog.ng;

import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultHttpRequestRetryHandler;
import org.apache.http.impl.client.HttpClients;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provides a configurable HTTP client for certificate-based authentication with retry logic.
 * Usage example:
 *   CloseableHttpClient client = CertificateHttpClientConfig.builder()
 *       .certPem(certString)
 *       .keyPem(keyString)
 *       .keyPassphrase(passphrase) // optional, only for encrypted keys
 *       .maxRetries(3)
 *       .timeoutMillis(30000)
 *       .build()
 *       .getHttpClient();
 * 
 * This class supports both encrypted and unencrypted PKCS#8 private keys. If the key is encrypted,
 * a passphrase must be provided. If the key is unencrypted, passphrase can be null or empty.
 * <p>The default mode uses JDK cryptography APIs. FIPS mode is opt-in through
 * the cds.auditlog.crypto.mode=fips system property (or Builder#cryptoMode(CryptoMode)) and
 * requires the optional Bouncy Castle FIPS/JSSE dependencies supplied by the application.</p>
 */
public class CertificateHttpClientConfig {

    /** System property used to select the cryptographic mode. */
    public static final String CRYPTO_MODE_PROPERTY = "cds.auditlog.crypto.mode";
    private static final String PEM_BLOCK =
            "-----BEGIN ([A-Z0-9 ]+)-----\\s*(.*?)\\s*-----END \\1-----";
    private static final Pattern PEM_PATTERN = Pattern.compile(PEM_BLOCK, Pattern.DOTALL);
    private static final AtomicReference<CryptoMode> LATCHED_MODE = new AtomicReference<>();
    private static final Logger logger = LoggerFactory.getLogger(CertificateHttpClientConfig.class);

    private final CloseableHttpClient httpClient;

    CertificateHttpClientConfig(Builder builder) {
        CryptoMode mode = latchMode(builder.cryptoMode);
        this.httpClient = createHttpClient(builder, mode);
    }

    /**
     * Cryptographic implementation used by the client. The mode is latched when the first
     * client is built so changing a process-wide FIPS setting after initialization is rejected.
     */
    public enum CryptoMode {
        STANDARD,
        FIPS;

        private static CryptoMode parse(String value) {
            if (value == null || value.isBlank() || "standard".equalsIgnoreCase(value)) {
                return STANDARD;
            }
            if ("fips".equalsIgnoreCase(value)) {
                return FIPS;
            }
            throw new IllegalArgumentException(
                    "Unsupported audit log cryptographic mode: " + value + " (expected standard or fips)");
        }
    }

    /**
     * Returns the configured HTTP client with certificate authentication and retry logic.
     *
     * @return a configured CloseableHttpClient
     */
    public CloseableHttpClient getHttpClient() {
        return httpClient;
    }

    /**
     * Returns a builder for {@link CertificateHttpClientConfig}.
     *
     * @return a new Builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link CertificateHttpClientConfig}.
     * <p>
     * All fields are optional except for certPem and keyPem, which are required.
     * </p>
     */
    public static class Builder {

        private String certPem;
        private String keyPem;
        private String keyPassphrase;
        private int maxRetries = 3;
        private int timeoutMillis = 30000;
        private CryptoMode cryptoMode;

        /**
         * Sets the PEM-encoded certificate chain.
         * @param certPem PEM string
         * @return this builder
         */
        public Builder certPem(String certPem) {
            this.certPem = certPem;
            return this;
        }
        /**
         * Sets the PEM-encoded private key.
         * @param keyPem PEM string
         * @return this builder
         */
        public Builder keyPem(String keyPem) {
            this.keyPem = keyPem;
            return this;
        }
        /**
         * Sets the passphrase for the private key (optional, only for encrypted keys).
         * @param keyPassphrase passphrase string
         * @return this builder
         */
        public Builder keyPassphrase(String keyPassphrase) {
            this.keyPassphrase = keyPassphrase;
            return this;
        }
        /**
         * Sets the maximum number of HTTP retries.
         * @param maxRetries number of retries
         * @return this builder
         */
        public Builder maxRetries(int maxRetries) {
            this.maxRetries = maxRetries;
            return this;
        }
        /**
         * Sets the HTTP client timeout in milliseconds.
         * @param timeoutMillis timeout in ms
         * @return this builder
         */
        public Builder timeoutMillis(int timeoutMillis) {
            this.timeoutMillis = timeoutMillis;
            return this;
        }
        /** Explicitly selects standard or FIPS cryptography for this client. */
        public Builder cryptoMode(CryptoMode cryptoMode) {
            this.cryptoMode = cryptoMode;
            return this;
        }

        /**
         * Builds the {@link CertificateHttpClientConfig} instance.
         * @return a configured CertificateHttpClientConfig
         * @throws IllegalArgumentException if certPem or keyPem is missing
         */
        public CertificateHttpClientConfig build() {
            return new CertificateHttpClientConfig(this);
        }
    }

    private static CryptoMode latchMode(CryptoMode requested) {
        CryptoMode effective = requested != null ? requested : configuredMode();
        CryptoMode latched = LATCHED_MODE.get();
        if (latched == null && LATCHED_MODE.compareAndSet(null, effective)) {
            return effective;
        }
        latched = LATCHED_MODE.get();
        if (latched != effective) {
            throw new IllegalStateException(
                    "Audit log cryptographic mode is already latched as " + latched
                            + "; it cannot be changed to " + effective);
        }
        return latched;
    }

    private static CryptoMode configuredMode() {
        String value = System.getProperty(CRYPTO_MODE_PROPERTY);
        return CryptoMode.parse(value);
    }

    /**
     * Creates the configured HTTP client with certificate authentication and retry logic.
     *
     * @return a configured CloseableHttpClient
     * @throws RuntimeException if client creation fails
     */
    private static CloseableHttpClient createHttpClient(Builder builder, CryptoMode mode) {
        char[] passphrase = builder.keyPassphrase == null
                ? new char[0]
                : builder.keyPassphrase.toCharArray();
        try {
            logger.info("Creating HttpClient with certificate authentication and {} retries in {} mode",
                    builder.maxRetries, mode);
            SSLContext sslContext;
            if (mode == CryptoMode.FIPS) {
                try {
                    sslContext = FipsCryptoSupport.createSslContext(builder.certPem, builder.keyPem, passphrase);
                } catch (LinkageError e) {
                    throw new IllegalStateException(
                            "FIPS mode requires the optional Bouncy Castle FIPS dependencies", e);
                }
            } else {
                X509Certificate[] certChain = parseCertificateChain(builder.certPem);
                PrivateKey privateKey = parsePrivateKey(builder.keyPem, passphrase);
                KeyStore keyStore = KeyStore.getInstance("PKCS12");
                keyStore.load(null, null);
                keyStore.setKeyEntry("client", privateKey, new char[0], certChain);
                KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                kmf.init(keyStore, new char[0]);
                sslContext = SSLContext.getInstance("TLS");
                sslContext.init(kmf.getKeyManagers(), null, new SecureRandom());
            }
            return HttpClients.custom()
                    .setSSLContext(sslContext)
                    .setRetryHandler(new DefaultHttpRequestRetryHandler(builder.maxRetries, true))
                    .build();
        } catch (Exception e) {
            logger.error("Failed to create HttpClient with certificate/key", e);
            throw new RuntimeException("Failed to create HttpClient with certificate/key: " + e.getMessage(), e);
        } finally {
            // Overwrite passphrase for security
            Arrays.fill(passphrase, '\0');
        }
    }

    /**
     * Parses a PEM-encoded certificate chain into X509Certificate array.
     * @param certPem PEM string
     * @return array of X509Certificate
     * @throws Exception if parsing fails
     */
    static X509Certificate[] parseCertificateChain(String certPem) throws Exception {
        List<X509Certificate> certList = new ArrayList<>();
        Matcher matcher = PEM_PATTERN.matcher(certPem);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        while (matcher.find()) {
            if (!"CERTIFICATE".equals(matcher.group(1))) {
                continue;
            }
            byte[] der = Base64.getMimeDecoder().decode(matcher.group(2));
            Certificate cert = certificateFactory.generateCertificate(new ByteArrayInputStream(der));
            certList.add((X509Certificate) cert);
        }
        return certList.toArray(new X509Certificate[0]);
    }

    /**
     * Parses a PEM-encoded PKCS#8 private key, supporting both encrypted and unencrypted keys.
     * @param keyPem PEM string
     * @param passphrase passphrase char array (optional, only for encrypted keys)
     * @return the PrivateKey
     * @throws Exception if parsing or decryption fails
     */
    static PrivateKey parsePrivateKey(String keyPem, char[] passphrase) throws Exception {
        Matcher matcher = PEM_PATTERN.matcher(keyPem);
        if (!matcher.find() || (!"PRIVATE KEY".equals(matcher.group(1))
                && !"ENCRYPTED PRIVATE KEY".equals(matcher.group(1)))) {
            throw new IllegalArgumentException("Expected a PKCS#8 PEM private key");
        }
        byte[] der = Base64.getMimeDecoder().decode(matcher.group(2));
        PKCS8EncodedKeySpec keySpec;
        if ("ENCRYPTED PRIVATE KEY".equals(matcher.group(1))) {
            EncryptedPrivateKeyInfo encrypted = new EncryptedPrivateKeyInfo(der);
            String algorithm = encrypted.getAlgName();
            char[] effectivePassphrase = passphrase == null ? new char[0] : passphrase;
            SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(algorithm);
            SecretKey secretKey = keyFactory.generateSecret(new PBEKeySpec(effectivePassphrase));
            Cipher cipher = Cipher.getInstance(algorithm);
            if (encrypted.getAlgParameters() == null) {
                cipher.init(Cipher.DECRYPT_MODE, secretKey);
            } else {
                cipher.init(Cipher.DECRYPT_MODE, secretKey, encrypted.getAlgParameters());
            }
            keySpec = encrypted.getKeySpec(cipher);
        } else {
            keySpec = new PKCS8EncodedKeySpec(der);
        }
        return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
    }
}

package com.sap.cds.feature.auditlog.ng;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.DefaultHttpRequestRetryHandler;
import org.apache.http.impl.client.HttpClients;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provides a configurable HTTP client for certificate-based authentication with retry logic.
 * Usage example:
 *   CloseableHttpClient client = RetryHttpClientConfig.builder()
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
 */
public class CertificateHttpClientConfig {

    private static final Logger logger = LoggerFactory.getLogger(CertificateHttpClientConfig.class);

    static {
        // Register BouncyCastle provider if not already present
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final String certPem;
    private final String keyPem;
    private final String keyPassphrase;
    private final int maxRetries;
    private final int timeoutMillis;
    private final CloseableHttpClient httpClient;

    CertificateHttpClientConfig(Builder builder) {
        this.certPem = builder.certPem;
        this.keyPem = builder.keyPem;
        this.keyPassphrase = builder.keyPassphrase;
        this.maxRetries = builder.maxRetries;
        this.timeoutMillis = builder.timeoutMillis;
        this.httpClient = createHttpClient();
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
     * Returns a builder for {@link RetryHttpClientConfig}.
     *
     * @return a new Builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link RetryHttpClientConfig}.
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
        /**
         * Builds the {@link RetryHttpClientConfig} instance.
         * @return a configured RetryHttpClientConfig
         * @throws IllegalArgumentException if certPem or keyPem is missing
         */
        public CertificateHttpClientConfig build() {
            return new CertificateHttpClientConfig(this);
        }
    }

    /**
     * Creates the configured HTTP client with certificate authentication and retry logic.
     *
     * @return a configured CloseableHttpClient
     * @throws RuntimeException if client creation fails
     */
    private CloseableHttpClient createHttpClient() {
        try {
            char[] effectivePassphrase = (keyPassphrase != null) ? keyPassphrase.toCharArray() : new char[0];
            logger.info("Creating HttpClient with certificate authentication and {} retries", maxRetries);
            X509Certificate[] certChain = parseCertificateChain(certPem);
            PrivateKey privateKey = parsePrivateKey(keyPem, effectivePassphrase);

            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            keyStore.setKeyEntry("client", privateKey, new char[0], certChain);

            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, new char[0]);

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(kmf.getKeyManagers(), null, new SecureRandom());

            return HttpClients.custom()
                    .setSSLContext(sslContext)
                    .setRetryHandler(new DefaultHttpRequestRetryHandler(maxRetries, true))
                    .build();
        } catch (Exception e) {
            logger.error("Failed to create HttpClient with certificate/key", e);
            throw new RuntimeException("Failed to create HttpClient with certificate/key: " + e.getMessage(), e);
        } finally {
            // Overwrite passphrase for security
            if (keyPassphrase != null) {
                Arrays.fill(keyPassphrase.toCharArray(), '\0');
            }
        }
    }

    /**
     * Parses a PEM-encoded certificate chain into X509Certificate array.
     * @param certPem PEM string
     * @return array of X509Certificate
     * @throws Exception if parsing fails
     */
    private static X509Certificate[] parseCertificateChain(String certPem) throws Exception {
        try (PEMParser pemParser = new PEMParser(new StringReader(certPem))) {
            List<X509Certificate> certList = new ArrayList<>();
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Object object;
            while ((object = pemParser.readObject()) != null) {
                if (object instanceof X509CertificateHolder holder) {
                    Certificate cert = cf.generateCertificate(
                            new ByteArrayInputStream(holder.getEncoded()));
                    certList.add((X509Certificate) cert);
                }
            }
            return certList.toArray(new X509Certificate[0]);
        }
    }

    /**
     * Parses a PEM-encoded PKCS#8 private key, supporting both encrypted and unencrypted keys.
     * @param keyPem PEM string
     * @param passphrase passphrase char array (optional, only for encrypted keys)
     * @return the PrivateKey
     * @throws Exception if parsing or decryption fails
     */
    private static PrivateKey parsePrivateKey(String keyPem, char[] passphrase) throws Exception {
        char[] effectivePassphrase = (passphrase != null) ? passphrase : new char[0];
        try (PEMParser pemParser = new PEMParser(new StringReader(keyPem))) {
            Object object = pemParser.readObject();
            if (object instanceof PrivateKeyInfo keyInfo) {
                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyInfo.getEncoded());
                return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
            } else if (object instanceof PKCS8EncryptedPrivateKeyInfo encInfo) {
                try {
                    InputDecryptorProvider decryptorProvider = new JceOpenSSLPKCS8DecryptorProviderBuilder().build(effectivePassphrase);
                    PrivateKeyInfo keyInfo = encInfo.decryptPrivateKeyInfo(decryptorProvider);
                    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyInfo.getEncoded());
                    return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
                } catch (IOException e) {
                    throw new RuntimeException("Failed to decrypt private key. Check that the passphrase is correct and the key is compatible. Original error: " + e.getMessage(), e);
                }
            } else {
                throw new IllegalArgumentException("Invalid private key format: "
                        + (object != null ? object.getClass().getName() : "null"));
            }
        }
    }
}

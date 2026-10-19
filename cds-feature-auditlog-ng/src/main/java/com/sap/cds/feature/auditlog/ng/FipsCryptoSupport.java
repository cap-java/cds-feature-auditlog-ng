package com.sap.cds.feature.auditlog.ng;

import java.io.StringReader;
import java.security.KeyStore;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;

/**
 * Optional FIPS implementation. This class is deliberately isolated from the standard path:
 * the main configuration class loads it only after FIPS mode was explicitly selected.
 */
final class FipsCryptoSupport {

    private static final String BCFIPS = "BCFIPS";
    private static final String BCJSSE = "BCJSSE";
    private static final String APPROVED_ONLY_PROPERTY = "org.bouncycastle.fips.approved_only";

    private FipsCryptoSupport() {
    }

    static SSLContext createSslContext(String certPem, String keyPem, char[] passphrase) throws Exception {
        rejectStandardBouncyCastle();
        configureApprovedOnlyMode();
        Provider fipsProvider = installFipsProvider();
        SecureRandom secureRandom = ((BouncyCastleFipsProvider) fipsProvider).getDefaultSecureRandom();
        CryptoServicesRegistrar.setSecureRandom(secureRandom);
        Provider jsseProvider = installJsseProvider();

        X509Certificate[] certificateChain = parseCertificateChain(certPem, fipsProvider);
        PrivateKey privateKey = parsePrivateKey(keyPem, passphrase, fipsProvider);
        char[] keyStorePassword = keyStorePassword(secureRandom);
        try {
            KeyStore keyStore = KeyStore.getInstance("BCFKS", fipsProvider);
            keyStore.load(null, keyStorePassword);
            keyStore.setKeyEntry("client", privateKey, keyStorePassword, certificateChain);

            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance("PKIX", jsseProvider);
            keyManagerFactory.init(keyStore, keyStorePassword);
            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance("PKIX", jsseProvider);
            trustManagerFactory.init((KeyStore) null);

            SSLContext sslContext = SSLContext.getInstance("TLS", jsseProvider);
            sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), secureRandom);
            return sslContext;
        } finally {
            java.util.Arrays.fill(keyStorePassword, '\0');
        }
    }

    private static char[] keyStorePassword(SecureRandom secureRandom) {
        char[] password = new char[32];
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        for (int i = 0; i < password.length; i++) {
            password[i] = alphabet.charAt(secureRandom.nextInt(alphabet.length()));
        }
        return password;
    }

    static void configureApprovedOnlyMode() throws InterruptedException {
        String configured = System.getProperty(APPROVED_ONLY_PROPERTY);
        if (configured != null && !"true".equalsIgnoreCase(configured)) {
            throw new IllegalStateException("FIPS mode requires " + APPROVED_ONLY_PROPERTY + "=true");
        }
        if (configured == null) {
            try {
                System.setProperty(APPROVED_ONLY_PROPERTY, "true");
            } catch (SecurityException e) {
                throw new IllegalStateException(
                        "FIPS mode could not set the BCFIPS approved-only system property", e);
            }
        }
        CryptoServicesRegistrar.setApprovedOnlyMode(true);
        if (!CryptoServicesRegistrar.isInApprovedOnlyMode()) {
            throw new IllegalStateException("BCFIPS approved-only mode could not be enabled");
        }
        AtomicBoolean otherThreadApproved = new AtomicBoolean();
        Thread probe = new Thread(
                () -> otherThreadApproved.set(CryptoServicesRegistrar.isInApprovedOnlyMode()),
                "auditlog-fips-approved-only-check");
        probe.start();
        probe.join();
        if (!otherThreadApproved.get()) {
            throw new IllegalStateException(
                    "BCFIPS approved-only mode is not the process default; configure it before BCFIPS initialization");
        }
    }

    private static Provider installFipsProvider() {
        Provider provider = Security.getProvider(BCFIPS);
        if (provider == null) {
            provider = new BouncyCastleFipsProvider();
            Security.addProvider(provider);
        }
        if (!(provider instanceof BouncyCastleFipsProvider)) {
            throw new IllegalStateException("Provider " + BCFIPS + " is not Bouncy Castle FIPS");
        }
        return provider;
    }

    private static Provider installJsseProvider() {
        Provider provider = Security.getProvider(BCJSSE);
        if (provider == null) {
            provider = new BouncyCastleJsseProvider(true);
            Security.addProvider(provider);
        }
        if (!(provider instanceof BouncyCastleJsseProvider) || !((BouncyCastleJsseProvider) provider).isFipsMode()) {
            throw new IllegalStateException("Provider " + BCJSSE + " is not Bouncy Castle FIPS JSSE");
        }
        return provider;
    }

    private static void rejectStandardBouncyCastle() {
        if (Security.getProvider("BC") != null
                || FipsCryptoSupport.class.getClassLoader().getResource(
                        "org/bouncycastle/jce/provider/BouncyCastleProvider.class") != null) {
            throw new IllegalStateException(
                    "FIPS mode requires an application classpath without standard Bouncy Castle");
        }
    }

    private static X509Certificate[] parseCertificateChain(String certPem, Provider provider) throws Exception {
        List<X509Certificate> certificates = new ArrayList<>();
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider(provider);
        try (PEMParser parser = new PEMParser(new StringReader(certPem))) {
            Object object;
            while ((object = parser.readObject()) != null) {
                if (object instanceof X509CertificateHolder holder) {
                    certificates.add(converter.getCertificate(holder));
                }
            }
        }
        if (certificates.isEmpty()) {
            throw new IllegalArgumentException("No PEM certificate block was found");
        }
        return certificates.toArray(new X509Certificate[0]);
    }

    private static PrivateKey parsePrivateKey(String keyPem, char[] passphrase, Provider provider) throws Exception {
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(provider);
        try (PEMParser parser = new PEMParser(new StringReader(keyPem))) {
            Object object = parser.readObject();
            if (object instanceof PrivateKeyInfo keyInfo) {
                return converter.getPrivateKey(keyInfo);
            }
            if (object instanceof PKCS8EncryptedPrivateKeyInfo encrypted) {
                InputDecryptorProvider decryptor = new JceOpenSSLPKCS8DecryptorProviderBuilder()
                        .setProvider(provider)
                        .build(passphrase == null ? new char[0] : passphrase);
                return converter.getPrivateKey(encrypted.decryptPrivateKeyInfo(decryptor));
            }
            throw new IllegalArgumentException("Expected a PKCS#8 PEM private key");
        }
    }
}

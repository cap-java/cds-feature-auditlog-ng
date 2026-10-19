package com.sap.cds.feature.auditlog.ng;

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.security.KeyPair;

import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.jupiter.api.Test;

class FipsCryptoClientTest {

    @Test
    void createsClientWithExplicitFipsMode() throws Exception {
        KeyPair keyPair = CertificateHttpClientConfigTest.rsaKeyPair();
        String certificate = CertificateHttpClientConfigTest.pem(
                "CERTIFICATE",
                CertificateHttpClientConfigTest.selfSignedCertificate(keyPair, "auditlog-fips-client"));

        try (CloseableHttpClient client = CertificateHttpClientConfig.builder()
                .certPem(certificate)
                .keyPem(CertificateHttpClientConfigTest.pem(
                        "PRIVATE KEY", keyPair.getPrivate().getEncoded()))
                .cryptoMode(CertificateHttpClientConfig.CryptoMode.FIPS)
                .build()
                .getHttpClient()) {
            assertNotNull(client);
        }
    }
}

/*
 * © 2023-2024 SAP SE or an SAP affiliate company. All rights reserved.
 */
package com.sap.cds.feature.auditlog.ng;

import java.io.IOException;
import java.time.Duration;

import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sap.cds.services.utils.CdsErrorStatuses;
import com.sap.cds.services.utils.ErrorStatusException;
import com.sap.cloud.environment.servicebinding.api.ServiceBinding;
import com.sap.cloud.sdk.cloudplatform.resilience.ResilienceConfiguration;
import com.sap.cloud.sdk.cloudplatform.resilience.ResilienceDecorator;
import com.sap.cloud.sdk.cloudplatform.resilience.ResilienceIsolationMode;

public class AuditLogNGCommunicator {

    private static final Logger logger = LoggerFactory.getLogger(AuditLogNGCommunicator.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private static final int NUMBER_RETRIES = 3;
    private static final Duration TIMEOUT_DURATION = Duration.ofMillis(30000);
    private static final String RESILIENCE_CONFIG_NAME = "auditlog";
    private static final String AUDITLOG_EVENTS_ENDPOINT = "/ingestion/v1/events";

    private final ResilienceConfiguration resilienceConfig;
    private final String serviceUrl;
    private final CloseableHttpClient certHttpClient;
    private final String region;
    private final String namespace;

    public AuditLogNGCommunicator(ServiceBinding binding) {
        this.serviceUrl = (String) binding.getCredentials().get("url");
        this.region = (String) binding.getCredentials().get("region");
        this.namespace = (String) binding.getCredentials().get("namespace");

        // Configure resilience patterns
        this.resilienceConfig = ResilienceConfiguration.empty(RESILIENCE_CONFIG_NAME);
        this.resilienceConfig.isolationMode(ResilienceIsolationMode.NO_ISOLATION);
        this.resilienceConfig.timeLimiterConfiguration(
                ResilienceConfiguration.TimeLimiterConfiguration.of().timeoutDuration(TIMEOUT_DURATION));
        this.resilienceConfig.retryConfiguration(
                ResilienceConfiguration.RetryConfiguration.of(NUMBER_RETRIES));

        // Configure HTTP client with certificate authentication
        try {
            this.certHttpClient = CertificateHttpClientConfig.builder()
                    .certPem((String) binding.getCredentials().get("cert"))
                    .keyPem((String) binding.getCredentials().get("key"))
                    .keyPassphrase((String) binding.getCredentials().get("passphrase"))
                    .maxRetries(NUMBER_RETRIES)
                    .timeoutMillis((int) TIMEOUT_DURATION.toMillis())
                    .build().getHttpClient();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to create HttpClient with certificate", e);
        }
    }

    String sendBulkRequest(Object auditLogEvents) throws JsonProcessingException {
        logger.debug("Sending bulk request to audit log service");
        String bulkRequestJson = serializeBulkRequest(auditLogEvents);
        HttpPost request = new HttpPost(serviceUrl + AUDITLOG_EVENTS_ENDPOINT);
        request.setEntity(new StringEntity(bulkRequestJson, ContentType.APPLICATION_JSON));
        try {
            return ResilienceDecorator.executeCallable(() -> executeBulkRequest(request), resilienceConfig);
        } catch (ErrorStatusException ese) {
            logger.error("Audit Log service returned unexpected HTTP status", ese);
            throw ese;
        } catch (JsonProcessingException jpe) {
            logger.error("JSON processing error while serializing bulk request object", jpe);
            throw jpe;
        } catch (Exception e) {
            logger.error("Exception while calling Audit Log service", e);
            throw new ErrorStatusException(CdsErrorStatuses.AUDITLOG_SERVICE_NOT_AVAILABLE, e);
        }
    }

    /**
     * Serializes the audit log events object to JSON.
     */
    private String serializeBulkRequest(Object auditLogEvents) throws JsonProcessingException {
        String json = OBJECT_MAPPER.writeValueAsString(auditLogEvents);
        logger.debug("Bulk request object serialized to JSON: {}", json);
        return json;
    }

    /**
     * Executes the HTTP POST request to the Audit Log service and handles the
     * response.
     */
    private String executeBulkRequest(HttpPost request) throws IOException, ErrorStatusException {
        HttpResponse response = null;
        try {
            response = certHttpClient.execute(request);
            int statusCode = response.getStatusLine().getStatusCode();
            if (statusCode == HttpStatus.SC_OK
                    || statusCode == HttpStatus.SC_CREATED
                    || statusCode == HttpStatus.SC_NO_CONTENT) {
                String resultBody = EntityUtils.toString(response.getEntity());
                logger.info("Bulk request to Audit Log service sent successfully. Status: {}", statusCode);
                logger.debug("Audit Log service response: {}", resultBody);
                return resultBody;
            } else {
                handleHttpError(response, statusCode);
                return null; // unreachable, handleHttpError always throws
            }
        } catch (ErrorStatusException ex) {
            logger.error("Error status received from Audit Log service: {} - {}", ex.getErrorStatus(), ex.getMessage(), ex);
            throw ex;
        } catch (IOException ex) {
            logger.error("Exception during HTTP request to Audit Log service", ex);
            throw ex;
        } finally {
            if (response != null && response.getEntity() != null) {
                EntityUtils.consumeQuietly(response.getEntity());
            }
        }
    }

    /**
     * Handles HTTP error responses from the Audit Log service.
     */
    private void handleHttpError(HttpResponse response, int statusCode) throws ErrorStatusException {
        String errorBody = "<no body>";
        try {
            if (response.getEntity() != null) {
                errorBody = EntityUtils.toString(response.getEntity());
            }
        } catch (IOException e) {
            logger.warn("Failed to read error response body from Audit Log service", e);
        }
        logger.error("Unexpected HTTP status from Audit Log service: {}. Response body: {}", statusCode, errorBody);
        throw new ErrorStatusException(CdsErrorStatuses.AUDITLOG_UNEXPECTED_HTTP_STATUS, statusCode);
    }

    public String getRegion() {
        return region;
    }

    public String getNamespace() {
        return namespace;
    }
}

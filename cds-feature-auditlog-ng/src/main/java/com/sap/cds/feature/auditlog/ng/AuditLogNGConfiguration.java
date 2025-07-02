/*
 * © 2021-2025 SAP SE or an SAP affiliate company. All rights reserved.
 */
package com.sap.cds.feature.auditlog.ng;

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.annotations.VisibleForTesting;
import com.sap.cds.services.mt.TenantProviderService;
import com.sap.cds.services.runtime.CdsRuntime;
import com.sap.cds.services.runtime.CdsRuntimeConfiguration;
import com.sap.cds.services.runtime.CdsRuntimeConfigurer;
import com.sap.cds.services.utils.CdsErrorStatuses;
import com.sap.cds.services.utils.ErrorStatusException;
import com.sap.cds.services.utils.StringUtils;
import com.sap.cds.services.utils.environment.ServiceBindingUtils;
import com.sap.cloud.environment.servicebinding.api.ServiceBinding;

/** CDS runtime configuration for the {@link AuditLogNGHandler}. */
public class AuditLogNGConfiguration implements CdsRuntimeConfiguration {
    private static final Logger LOGGER = LoggerFactory.getLogger(AuditLogNGConfiguration.class);
    static final String AUDITLOG = "auditlog-ng";

    @Override
    public void eventHandlers(CdsRuntimeConfigurer configurer) {
        CdsRuntime runtime = configurer.getCdsRuntime();
        ServiceBinding binding = runtime
            .getEnvironment()
            .getServiceBindings()
            .filter(b -> ServiceBindingUtils.matches(b, AUDITLOG))
            .findFirst()
            .orElse(null);

        if (binding != null) {
            validateBinding(binding);
            LOGGER.info("Using Auditlog NG service to register Auditlog NG event handler.");
            AuditLogNGHandler handler = createHandler(binding, configurer);
            configurer.eventHandler(handler);
        } else {
            LOGGER.info("No Auditlog NG service binding found, NG handler not registered.");
        }
    }

    @VisibleForTesting
    AuditLogNGHandler createHandler(ServiceBinding binding, CdsRuntimeConfigurer configurer) {
        AuditLogNGCommunicator communicator = new AuditLogNGCommunicator(binding);
        TenantProviderService tenantService = configurer
            .getCdsRuntime()
            .getServiceCatalog()
            .getService(TenantProviderService.class, TenantProviderService.DEFAULT_NAME);
        return new AuditLogNGHandler(communicator, tenantService);
    }

    private void validateBinding(ServiceBinding binding) {
        Map<String, Object> cred = binding.getCredentials();
        if (cred.isEmpty()) {
            throw new ErrorStatusException(CdsErrorStatuses.AUDITLOG_SERVICE_INVALID_CONFIG, "credentials");
        }
        String[] requiredFields = {"url", "region", "namespace", "cert", "key"};
        for (String field : requiredFields) {
            if (!cred.containsKey(field) || StringUtils.isEmpty((String) cred.get(field))) {
                throw new ErrorStatusException(CdsErrorStatuses.AUDITLOG_SERVICE_INVALID_CONFIG, "credentials." + field);
            }
        }
    }
}

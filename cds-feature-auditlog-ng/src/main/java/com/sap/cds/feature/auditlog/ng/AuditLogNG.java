package com.sap.cds.feature.auditlog.ng;

/**
 * Constants for the AuditLog NG plugin.
 */
public interface AuditLogNG {
    /**
     * Key name for specifying a custom namespace in the event payload.
     * 
     * <p>Set this key directly in the event payload 
     * (e.g., {@code securityLog.put(AuditLogNG.NAMESPACE_ATTRIBUTE, "my-namespace")}).
     * This approach survives transactional outbox serialization.</p>
     * 
     * <p>Resolution priority: payload &gt; service binding</p>
     */
    String NAMESPACE_ATTRIBUTE = "auditlog.namespace";
}

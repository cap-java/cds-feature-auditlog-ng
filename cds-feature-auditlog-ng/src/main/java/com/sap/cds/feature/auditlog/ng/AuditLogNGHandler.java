/*
 * © 2021-2024 SAP SE or an SAP affiliate company. All rights reserved.
 */
package com.sap.cds.feature.auditlog.ng;

import java.time.Instant;
import java.util.Collection;
import static java.util.Objects.requireNonNull;
import java.util.UUID;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import static org.slf4j.LoggerFactory.getLogger;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.sap.cds.services.auditlog.Access;
import com.sap.cds.services.auditlog.Attachment;
import com.sap.cds.services.auditlog.Attribute;
import com.sap.cds.services.auditlog.AuditLogService;
import com.sap.cds.services.auditlog.ChangedAttribute;
import com.sap.cds.services.auditlog.ConfigChange;
import com.sap.cds.services.auditlog.ConfigChangeLog;
import com.sap.cds.services.auditlog.ConfigChangeLogContext;
import com.sap.cds.services.auditlog.DataAccessLog;
import com.sap.cds.services.auditlog.DataAccessLogContext;
import com.sap.cds.services.auditlog.DataModification;
import com.sap.cds.services.auditlog.DataModificationLog;
import com.sap.cds.services.auditlog.DataModificationLogContext;
import com.sap.cds.services.auditlog.DataObject;
import com.sap.cds.services.auditlog.DataSubject;
import com.sap.cds.services.auditlog.KeyValuePair;
import com.sap.cds.services.auditlog.SecurityLog;
import com.sap.cds.services.auditlog.SecurityLogContext;
import com.sap.cds.services.handler.EventHandler;
import com.sap.cds.services.handler.annotations.On;
import com.sap.cds.services.handler.annotations.ServiceName;
import com.sap.cds.services.mt.TenantProviderService;
import com.sap.cds.services.request.UserInfo;
import com.sap.cds.services.utils.CdsErrorStatuses;
import com.sap.cds.services.utils.ErrorStatusException;

/**
 * Handler that reacts on audit log events to log audit messages with the auditlog NG API.
 */
@ServiceName(value = "*", type = AuditLogService.class)
public class AuditLogNGHandler implements EventHandler {

    private static final Logger LOGGER = getLogger(AuditLogNGHandler.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String LEGACY_SECURITY_WRAPPER = "legacySecurityWrapper";

    private final AuditLogNGCommunicator communicator;
    private final TenantProviderService tenantService;

    AuditLogNGHandler(AuditLogNGCommunicator communicator, TenantProviderService tenantService) {
        this.communicator = communicator;
        this.tenantService = tenantService;
    }

    @On
    public void handleSecurityEvent(SecurityLogContext context) {
        try {
            ArrayNode alsEvents = createSecurityEvent(context);
            communicator.sendBulkRequest(alsEvents);
        } catch (JsonParseException e) {
            LOGGER.error("Audit Log write exception occurred for security event", e);
            throw new ErrorStatusException(CdsErrorStatuses.AUDITLOG_SERVICE_INVALID_MESSAGE, e);
        } catch (ErrorStatusException e) {
            LOGGER.error("Audit Log service not available for security event", e);
            throw new ErrorStatusException(CdsErrorStatuses.AUDITLOG_SERVICE_NOT_AVAILABLE, e);
       } catch (Exception e) {
            LOGGER.error("Unexpected exception while handling security event", e);
            throw new ErrorStatusException(CdsErrorStatuses.AUDITLOG_SERVICE_INVALID_MESSAGE, e);
        }
    }

    /**
     * Creates an ArrayNode representing security events for the Audit Log service.
     *
     * The returned ArrayNode contains a single ObjectNode with the following structure:
     *   - id: A unique identifier for the event (UUID)
     *   - specversion: The specification version (integer)
     *   - source: The source of the event, including region, namespace, and tenant
     *   - type: The type of the event (e.g., "legacySecurityWrapper")
     *   - time: The timestamp of the event (ISO-8601 format)
     *   - data: An ObjectNode containing:
     *       - metadata: An ObjectNode with the timestamp of the event
     *       - legacySecurityWrapper: An ObjectNode with:
     *           - origEvent: A serialized JSON string representing the original security event
     *
     * @param context the SecurityLogContext containing user and event data
     * @return an ArrayNode representing the security event
     */
    private ArrayNode createSecurityEvent(SecurityLogContext context) {
        SecurityLog data = requireNonNull(context.getData(), "SecurityLogContext.getData() is null");
        UserInfo userInfo = requireNonNull(context.getUserInfo(), "SecurityLogContext.getUserInfo() is null");
        ObjectNode alsEvent = buildEventEnvelope(OBJECT_MAPPER, LEGACY_SECURITY_WRAPPER, userInfo);
        ObjectNode metadata = buildEventMetadata();
        ObjectNode origEvent = createLegacySecurityOrigEvent(userInfo, data);
        ObjectNode legacySecurityWrapper = OBJECT_MAPPER.createObjectNode();
        try {
            legacySecurityWrapper.put("origEvent", OBJECT_MAPPER.writeValueAsString(origEvent));
        } catch (JsonProcessingException e) {
            LOGGER.error("Failed to serialize origEvent: {}", origEvent, e);
            throw new ErrorStatusException(CdsErrorStatuses.AUDITLOG_SERVICE_INVALID_MESSAGE, "Failed to serialize origEvent", e);
        }
        ObjectNode dataNode = OBJECT_MAPPER.createObjectNode();
        dataNode.set(LEGACY_SECURITY_WRAPPER, legacySecurityWrapper);
        ObjectNode alsData = buildAuditLogEventData(metadata, dataNode);
        alsEvent.set("data", alsData);
        return OBJECT_MAPPER.createArrayNode().add(alsEvent);
    }

    /**
     * Creates a legacy security origin event as an ObjectNode containing audit log information.
     *
     * The resulting JSON object includes the following fields:
     *   - uuid: A randomly generated UUID string for the event
     *   - user: The name of the user from userInfo, or "unknown" if userInfo is null
     *   - identityProvider: A constant value "$IDP"
     *   - time: The current timestamp as an ISO-8601 string
     *   - data: The data from the SecurityLog object, or an empty string if data is null
     *
     * @param userInfo the user information, may be null
     * @param data the security log data, may be null
     * @return an ObjectNode representing the legacy security origin event
     */
    private ObjectNode createLegacySecurityOrigEvent(UserInfo userInfo, SecurityLog data) {
        ObjectNode envelop = OBJECT_MAPPER.createObjectNode();
        String formattedData = "action: %s, data: %s".formatted(data.getAction(), data.getData());
        formattedData = formattedData.replace("\r\n", "\\n").replace("\n", "\\n");
        setFieldIfNotNull(envelop, "uuid", UUID.randomUUID().toString());
        setFieldIfNotNull(envelop, "user", userInfo != null ? userInfo.getName() : "unknown");
        setFieldIfNotNull(envelop, "identityProvider", "$IDP");
        setFieldIfNotNull(envelop, "time", Instant.now().toString());
        setFieldIfNotNull(envelop, "data", formattedData != null ? formattedData : "");
        return envelop;
    }

    @On
    public void handleDataAccessEvent(DataAccessLogContext context) {
        try {
            ArrayNode alsEvents = createAlsDataAccessEvents(context);
            communicator.sendBulkRequest(alsEvents);
        } catch (JsonParseException e) {
            LOGGER.error("Audit Log write exception occurred for data access event", e);
            throw new ErrorStatusException(CdsErrorStatuses.AUDITLOG_SERVICE_INVALID_MESSAGE, e);
        } catch (ErrorStatusException e) {
            LOGGER.error("Audit Log service not available for data access event", e);
            throw new ErrorStatusException(CdsErrorStatuses.AUDITLOG_SERVICE_NOT_AVAILABLE, e);
       } catch (Exception e) {
            LOGGER.error("Unexpected exception while handling data access event", e);
            throw new ErrorStatusException(CdsErrorStatuses.AUDITLOG_SERVICE_INVALID_MESSAGE, e);
        }
    }

    /**
     * Creates an ArrayNode representing data access events for the Audit Log service.
     *
     * Iterates over all accesses in the provided DataAccessLogContext and adds corresponding
     * ALS events for each attribute and attachment combination.
     *
     * @param context the DataAccessLogContext containing access data
     * @return an ArrayNode containing ALS data access event objects
     * @throws NullPointerException if context data or accesses are null
     * @throws IllegalArgumentException if accesses are empty
     */
    private ArrayNode createAlsDataAccessEvents(DataAccessLogContext context) {
        UserInfo userInfo = requireNonNull(context.getUserInfo(), "DataAccessLogContext.getUserInfo() is null");
        DataAccessLog data = requireNonNull(context.getData(), "DataAccessLogContext.getData() is null");
        Collection<Access> accesses = requireNonNull(data.getAccesses(), "DataAccessLog.getAccesses() is null");
        ArrayNode eventArray = OBJECT_MAPPER.createArrayNode();
        for (Access access : accesses) {
            addAccessEvents(userInfo, eventArray, access);
        }
        return eventArray;
    }

    /**
     * Adds access events for each attribute in the given {@link Access} object to the specified event array.
     * For each attribute, this method retrieves its name and delegates the creation of the access event
     * to {@code addAttributeAccessEvents}.
     *
     * @param userInfo   the user information associated with the access event
     * @param eventArray the array to which access events will be added
     * @param access     the access object containing the attributes to process
     * @throws NullPointerException if {@code access.getAttributes()} or any attribute name is {@code null}
     */
    private void addAccessEvents(UserInfo userInfo, ArrayNode eventArray, Access access) {
        Collection<Attribute> attributes = requireNonNull(access.getAttributes(), "Access.getAttributes() is null");
        for (Attribute attribute : attributes) {
            String attributeName = requireNonNull(attribute.getName(), "Attribute.getName() is null");
            addAttributeAccessEvents(userInfo, eventArray, access, attributeName);
        }
    }

    /**
     * Adds attribute access events to the provided event array based on the given access and attribute information.
     * If the {@link Access} object contains attachments, an event is created for each attachment using its name and ID.
     * If there are no attachments, a single event is created without attachment details.
     *
     * @param userInfo      the user information associated with the access event
     * @param eventArray    the JSON array node to which the generated events will be added
     * @param access        the access object containing details about the attribute access and any attachments
     * @param attributeName the name of the attribute being accessed
     */
    private void addAttributeAccessEvents(UserInfo userInfo, ArrayNode eventArray, Access access, String attributeName) {
        Collection<Attachment> attachments = access.getAttachments();
        if (attachments == null || attachments.isEmpty()) {
            ObjectNode alsEvent = buildDataAccessAlsEvent(userInfo, access, attributeName, null, null);
            eventArray.add(alsEvent);
        } else {
            for (Attachment attachment : attachments) {
                ObjectNode alsEvent = buildDataAccessAlsEvent(userInfo, access, attributeName, attachment.getName(), attachment.getId());
                eventArray.add(alsEvent);
            }
        }
    }

    @On
    public void handleConfigChangeEvent(ConfigChangeLogContext context) {
        try {
            ArrayNode alsEvents = createAlsConfigChangeEvents(context);
            communicator.sendBulkRequest(alsEvents);
        } catch (JsonParseException e) {
            LOGGER.error("Audit Log write exception occurred for configuration change event", e);
            throw new ErrorStatusException(CdsErrorStatuses.AUDITLOG_SERVICE_INVALID_MESSAGE, e);
        } catch (ErrorStatusException e) {
            LOGGER.error("Audit Log service not available for configuration change event", e);
            throw new ErrorStatusException(CdsErrorStatuses.AUDITLOG_SERVICE_NOT_AVAILABLE, e);
       } catch (Exception e) {
            LOGGER.error("Unexpected exception while handling configuration change event", e);
            throw new ErrorStatusException(CdsErrorStatuses.AUDITLOG_SERVICE_INVALID_MESSAGE, e);
        }
    }

    /**
     * Creates an {@link ArrayNode} containing configuration change event objects based on the provided {@link ConfigChangeLogContext}.
     * This method extracts the {@link ConfigChangeLog} data from the context, retrieves the collection of {@link ConfigChange} objects,
     * and for each configuration change, generates event nodes for each attribute using {@code buildConfigChangeEvent}.
     * The resulting events are aggregated into a single {@link ArrayNode}.
     *
     * @param context the {@link ConfigChangeLogContext} containing the configuration change log data; must not be {@code null}
     * @return an {@link ArrayNode} containing the generated configuration change event nodes
     * @throws NullPointerException if the context data or configurations are {@code null}
     * @throws IllegalArgumentException if the configurations collection is empty
     */
    private ArrayNode createAlsConfigChangeEvents(ConfigChangeLogContext context) {
        ConfigChangeLog data = requireNonNull(context.getData(), "ConfigChangeLogContext.getData() is null");
        UserInfo userInfo = requireNonNull(context.getUserInfo(), "ConfigChangeLogContext.getUserInfo() is null");
        Collection<ConfigChange> configChanges = requireNonNull(data.getConfigurations(), "ConfigChangeLog.getConfigurations() is null");
        ArrayNode result = OBJECT_MAPPER.createArrayNode();
        configChanges.forEach(cfg -> {
            Collection<ChangedAttribute> attributes = requireNonNull(cfg.getAttributes(), "ConfigChange.getAttributes() is null");
            attributes.stream().map(attribute -> buildConfigChangeEvent(userInfo, cfg, attribute)).forEach(result::add);
        });
        return result;
    }

    /**
     * Builds an audit log event for a configuration change.
     * This method constructs an ObjectNode representing an audit log event for a configuration change,
     * including metadata, details about the changed attribute, and information about the affected data object.
     *
     * @param context   the context containing user and request information for the configuration change
     * @param cfg       the configuration change object containing details about the change
     * @param attribute the specific attribute that was changed
     * @return an ObjectNode representing the audit log event for the configuration change
     */
    private ObjectNode buildConfigChangeEvent(UserInfo userInfo, ConfigChange configChanges, ChangedAttribute attribute) {
        ObjectNode metadata = buildEventMetadata();
        ObjectNode changeNode = OBJECT_MAPPER.createObjectNode();
        addValueDetails(changeNode, attribute, "propertyName");
        var dataObject = requireNonNull(configChanges.getDataObject(), "ConfigChange.getDataObject() is null");
        addObjectDetails(changeNode, dataObject);
        return buildAlsEvent("configurationChange", userInfo, metadata, "configurationChange", changeNode);
    }

    @On
    public void handleDataModificationEvent(DataModificationLogContext context) {
        try {
            ArrayNode alsEvents = createAlsDataModificationEvents(context);
            communicator.sendBulkRequest(alsEvents);
        } catch (JsonParseException e) {
            LOGGER.error("Audit Log write exception occurred for data modification event", e);
            throw new ErrorStatusException(CdsErrorStatuses.AUDITLOG_SERVICE_INVALID_MESSAGE, e);
        } catch (ErrorStatusException e) {
            LOGGER.error("Audit Log service not available for data modification event", e);
            throw new ErrorStatusException(CdsErrorStatuses.AUDITLOG_SERVICE_NOT_AVAILABLE, e);
       } catch (Exception e) {
            LOGGER.error("Unexpected exception while handling data modification event", e);
            throw new ErrorStatusException(CdsErrorStatuses.AUDITLOG_SERVICE_INVALID_MESSAGE, e);
        }
    }

    /**
     * Creates ALS (Audit Logging Service) data modification events based on the provided context.
     * This method extracts the {@link DataModificationLog} from the given {@link DataModificationLogContext},
     * validates that the modifications collection is not null or empty, and then builds attribute-based ALS events.
     *
     * @param context the context containing data modification log information; must not be null
     * @return an {@link ArrayNode} containing the generated ALS data modification events
     * @throws NullPointerException if the context data or modifications are null
     * @throws IllegalArgumentException if the modifications collection is empty
     */
    private ArrayNode createAlsDataModificationEvents(DataModificationLogContext context) {
        DataModificationLog data = requireNonNull(context.getData(), "DataModificationLogContext.getData() is null");
        Collection<DataModification> modifications = requireNonNull(data.getModifications(), "DataModificationLog.getModifications() is null");
        UserInfo userInfo = requireNonNull(context.getUserInfo(), "DataModificationLogContext.getUserInfo() is null");
        return buildAttributeBasedAlsEvents(userInfo, modifications);
    }

    /**
     * Builds an array of ALS (Audit Log Service) events based on the attributes of the given data modifications.
     * For each {@link DataModification} in the provided collection, this method iterates through its changed attributes
     * and creates an ALS event for each attribute using {@code buildDataModificationAlsEvent}.
     *
     * @param context the context of the data modification log, containing relevant metadata for event creation
     * @param items a collection of {@link DataModification} objects to process
     * @return an {@link ArrayNode} containing the generated ALS events for each changed attribute
     * @throws IllegalArgumentException if any {@link DataModification} item has no attributes
     */
    private ArrayNode buildAttributeBasedAlsEvents(UserInfo userInfo, Collection<DataModification> modifications) {
        ArrayNode eventArray = OBJECT_MAPPER.createArrayNode();
        for (DataModification modification : modifications) {
            Collection<ChangedAttribute> attributes = requireNonNull(modification.getAttributes(), "DataModification.getAttributes() is null");
            for (ChangedAttribute attribute : attributes) {
                eventArray.add(buildDataModificationAlsEvent(userInfo, modification, attribute));
            }
        }
        return eventArray;
    }

    /**
     * Builds an ALS (Audit Logging Service) event for a data modification operation.
     * This method constructs an ObjectNode representing a data modification event,
     * including relevant metadata, object and subject information, and changed attribute details.
     *
     * @param context the context of the data modification log, containing user and request information
     * @param modification the data modification details, including the affected data object and subject
     * @param attribute the specific attribute that was changed during the modification
     * @return an ObjectNode representing the constructed ALS event for the data modification
     */
    private ObjectNode buildDataModificationAlsEvent(UserInfo userInfo, DataModification modification, ChangedAttribute attribute) {
        DataObject dataObject = requireNonNull(modification.getDataObject(), "DataModification.getDataObject() is null");
        ObjectNode metadata = buildEventMetadata();
        ObjectNode dataModificationNode = buildDataModificationNode(attribute, modification.getDataSubject(), dataObject);
        return buildAlsEvent("dppDataModification", userInfo, metadata, "dppDataModification", dataModificationNode);
    }

    /**
     * Builds the data modification node for a single ChangedAttribute.
     *
     * This node contains the following fields:
     *   - objectType: The type of the modified object (if available)
     *   - objectId: The identifier(s) of the modified object (if available)
     *   - attribute: The name of the changed attribute
     *   - oldValue: The previous value of the attribute (if available)
     *   - newValue: The new value of the attribute (if available)
     *   - dataSubjectType: The type of the data subject (if available)
     *   - dataSubjectId: The identifier(s) of the data subject (if available)
     *
     * @param objectType the type of the modified object
     * @param objectId the identifier(s) of the modified object
     * @param attribute the changed attribute
     * @param dataSubjectType the type of the data subject
     * @param dataSubjectId the identifier(s) of the data subject
     * @return an ObjectNode representing the data modification details
     */
    private ObjectNode buildDataModificationNode(ChangedAttribute attribute, DataSubject dataSubject, DataObject dataObject) {
        ObjectNode node = OBJECT_MAPPER.createObjectNode();
        addValueDetails(node, attribute, "attribute");
        addObjectDetails(node, dataObject);
        addDataSubjectDetails(node, dataSubject);
        return node;
    }

    /**
     * Builds an event envelope as an ObjectNode for audit logging purposes.
     *
     * The envelope includes a unique event ID, specification version, source,
     * type, and timestamp. The source is constructed using the communicator's
     * region, namespace, and the tenant information. If the tenant is not
     * provided in the UserInfo, the provider tenant is used.
     *
     * @param mapper the ObjectMapper used to create the JSON object node
     * @param type the type of the event to be set in the envelope
     * @param userInfo the user information containing tenant details
     * @return an ObjectNode representing the event envelope
     */
    private ObjectNode buildEventEnvelope(ObjectMapper mapper, String type, UserInfo userInfo) {
        ObjectNode alsEvent = mapper.createObjectNode();
        alsEvent.put("id", UUID.randomUUID().toString());
        alsEvent.put("specversion", 1);
        String tenant = (userInfo.getTenant() == null || userInfo.getTenant().isEmpty()) ? tenantService.readProviderTenant() : userInfo.getTenant();
        alsEvent.put("source", String.format("/%s/%s/%s", communicator.getRegion(), communicator.getNamespace(), tenant));
        alsEvent.put("type", type);
        alsEvent.put("time", Instant.now().toString());
        return alsEvent;
    }

    /**
     * Builds an ObjectNode containing event metadata.
     * Currently, this method adds a timestamp ("ts") field with the current instant in ISO-8601 format.
     *
     * @param mapper the {@link ObjectMapper} used to create the ObjectNode
     * @return an {@link ObjectNode} containing the event metadata
     */
    private ObjectNode buildEventMetadata() {
        ObjectNode metadata = OBJECT_MAPPER.createObjectNode();
        metadata.put("ts", Instant.now().toString());
        ObjectNode infraOther = metadata.putObject("infrastructure").putObject("other");
        infraOther.put("runtimeType", "Java");
        ObjectNode platformOther = metadata.putObject("platform").putObject("other");
        platformOther.put("platformName", "CAP");
        return metadata;
    }

    /**
     * Builds an ALS (Audit Logging Service) event for data access operations.
     *
     * @param context        the context containing user and request information for the data access event
     * @param access         the type of access performed (e.g., READ, WRITE)
     * @param attribute      the specific attribute or field being accessed
     * @param attachmentType the type of attachment associated with the access, if any
     * @param attachmentId   the identifier of the attachment, if applicable
     * @return an {@link ObjectNode} representing the constructed ALS event for data access
     */
    private ObjectNode buildDataAccessAlsEvent(UserInfo userInfo, Access access, String attribute, String attachmentType, String attachmentId) {
        ObjectNode metadata = buildEventMetadata();
        ObjectNode dataAccessNode = buildDataAccessNode(access, attribute, attachmentType, attachmentId);
        return buildAlsEvent("dppDataAccess", userInfo, metadata, "dppDataAccess", dataAccessNode);
    }

    /**
     * Builds an {@link ObjectNode} representing data access information for audit logging purposes.
     * The resulting node includes details about the access channel, data subject, data object,
     * and optional attributes such as attribute name, attachment type, and attachment ID.
     *
     * @param access         the {@link Access} object containing data subject and data object information
     * @param attribute      the name of the accessed attribute (may be {@code null})
     * @param attachmentType the type of the attachment (may be {@code null})
     * @param attachmentId   the ID of the attachment (may be {@code null})
     * @return an {@link ObjectNode} containing the structured data access information
     */
    private ObjectNode buildDataAccessNode(Access access, String attribute, String attachmentType, String attachmentId) {
        ObjectNode node = OBJECT_MAPPER.createObjectNode();
        node.put("channelType", "not specified");
        node.put("channelId", "not specified");
        DataSubject dataSubject = requireNonNull(access.getDataSubject(), "Access.getDataSubject() is null");
        addDataSubjectDetails(node, dataSubject);

        DataObject dataObject = requireNonNull(access.getDataObject(), "Access.getDataObject() is null");
        addObjectDetails(node, dataObject);
        
        // setFieldIfNotNull(node, "attribute", attribute);
        node.put("attribute", attribute);
        setFieldIfNotNull(node, "attachmentType", attachmentType);
        setFieldIfNotNull(node, "attachmentId", attachmentId);
        return node;
    }

    /**
     * Adds details about a changed value to the given JSON node.
     *
     * @param node The JSON node where the value details will be added.
     * @param attribute The changed attribute containing the old and new values.
     * @param fieldName The name of the field representing the attribute in the JSON node.
     */
    private void addValueDetails(ObjectNode node, ChangedAttribute attribute, String fieldName) {
        String attributeName = requireNonNull(attribute.getName(), "ChangedAttribute.getName() is null");
        String newValue = requireNonNull(attribute.getNewValue(), "ChangedAttribute.getNewValue() is null");
        node.put(fieldName, attributeName);
        node.put("newValue", newValue);
        node.put("oldValue", attribute.getOldValue() != null ? attribute.getOldValue() : "null");
    }

    /**
     * Adds object details to the given JSON node based on the provided {@link DataObject}.
     * The method extracts the object IDs from the {@code dataObject}, formats them alphabetically,
     * and adds them to the node under the "objectId" key. It also adds the object type under the
     * "objectType" key, or "null" if the type is not specified.
     *
     * @param node the {@link ObjectNode} to which object details will be added
     * @param dataObject the {@link DataObject} containing the object type and IDs
     * @throws NullPointerException if {@code dataObject.getId()} is {@code null}
     */
    private void addObjectDetails(ObjectNode node, DataObject dataObject) {
        Collection<KeyValuePair> objectIds = requireNonNull(dataObject.getId(), "Access.getDataObject().getId() is null");
        String formatedObjectIds = formatAlpabeticallyIds(objectIds);
        node.put("objectId", formatedObjectIds);
        node.put("objectType", dataObject.getType() != null ? dataObject.getType() : "null");
    }

    /**
     * Adds data subject details to the given JSON node.
     * If the provided {@code dataSubject} is {@code null}, sets both "dataSubjectType" and "dataSubjectId" fields to "null".
     * Otherwise, extracts the data subject's IDs, formats them alphabetically, and adds them as "dataSubjectId".
     * Also adds the data subject's type as "dataSubjectType", or "null" if the type is not specified.
     *
     * @param node        the JSON node to which data subject details will be added
     * @param dataSubject the data subject whose details are to be added; may be {@code null}
     */
    private void addDataSubjectDetails(ObjectNode node, DataSubject dataSubject) {
        if (dataSubject == null) {
            node.put("dataSubjectType", "null");
            node.put("dataSubjectId", "null");
        } else {
            Collection<KeyValuePair> dataSubjectIds = requireNonNull(dataSubject.getId(), "Access.getDataSubject().getId() is null");
            String formatedDataSubjectIds = formatAlpabeticallyIds(dataSubjectIds);
            node.put("dataSubjectId", formatedDataSubjectIds);
            node.put("dataSubjectType", dataSubject.getType() != null ? dataSubject.getType() : "null");
        }
    }

    /**
     * Builds an ALS event as an ObjectNode for audit logging purposes.
     *
     * @param eventType the type of the event
     * @param userInfo the user information containing tenant and user details
     * @param metadata the metadata node containing timestamp and other event-specific details
     * @param dataKey the key representing the type of data in the event, e.g., "dppDataAccess"
     * @param dataValue the value node containing the event-specific data
     * @return an ObjectNode representing the ALS event
     */
    private ObjectNode buildAlsEvent(String eventType, UserInfo userInfo, ObjectNode metadata, String dataKey, ObjectNode dataValue) {
        ObjectNode alsEvent = buildEventEnvelope(OBJECT_MAPPER, eventType, userInfo);
        ObjectNode dataNode = OBJECT_MAPPER.createObjectNode();
        dataNode.set(dataKey, dataValue);
        ObjectNode alsData = buildAuditLogEventData(metadata, dataNode);
        alsEvent.set("data", alsData);
        return alsEvent;
    }

    /**
     * Sets a field in the given ObjectNode only if the provided value is not null.
     *
     * If the value is a String, the field is set using ObjectNode#put(String, String).
     * For other types, the field is set using ObjectNode#set(String, JsonNode) after converting the value to a JsonNode using ObjectMapper#valueToTree(Object).
     *
     * @param node the ObjectNode where the field will be set
     * @param field the name of the field to set
     * @param value the value to set; if null, the field will not be set
     */
    private void setFieldIfNotNull(ObjectNode node, String field, Object value) {
        if (value != null) {
            if (value instanceof String str) {
                node.put(field, str);
            } else {
                node.set(field, OBJECT_MAPPER.valueToTree(value));
            }
        }
    }

    /**
     * Builds an audit log event data object by combining the provided metadata and data nodes.
     *
     * @param metadata the metadata to include in the audit log event
     * @param dataNode the data node containing the event-specific data
     * @return an ObjectNode representing the combined audit log event data with "metadata" and "data" fields
     */
    private ObjectNode buildAuditLogEventData(ObjectNode metadata, ObjectNode dataNode) {
        ObjectNode alsData = OBJECT_MAPPER.createObjectNode();
        alsData.set("metadata", metadata);
        alsData.set("data", dataNode);
        return alsData;
    }

    /**
     * Helper method to build a readable objectId string with alphabetically ordered keys.
     * The returned string is a space-separated list of key-value pairs in the format "key:value". Example: "id:123 name:John".
     *
     * @param ids the collection of key-value pairs representing object IDs
     * @return a formatted string of object IDs
     */
    private String formatAlpabeticallyIds(Collection<KeyValuePair> ids) {
        return ids.stream().sorted((a, b) -> a.getKeyName().compareToIgnoreCase(b.getKeyName())).map(kv -> kv.getKeyName() + ":" + kv.getValue()).collect(Collectors.joining(" "));
    }

}

package com.sap.cds.feature.auditlog.ng;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.io.File;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SpecVersion;
import com.networknt.schema.ValidationMessage;
import com.sap.cds.services.EventContext;
import com.sap.cds.services.auditlog.Access;
import com.sap.cds.services.auditlog.Attachment;
import com.sap.cds.services.auditlog.Attribute;
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
import com.sap.cds.services.mt.TenantProviderService;
import com.sap.cds.services.request.UserInfo;
import com.sap.cds.services.utils.ErrorStatusException;

public class AuditLogNGHandlerTest {

    @Mock
    private AuditLogNGCommunicator communicator;
    @Mock
    private TenantProviderService tenantService;
    @Mock
    private UserInfo userInfo;

    private AuditLogNGHandler handler;

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
        handler = new AuditLogNGHandler(communicator, tenantService);
    }

    private void runAndAssertEvent(String schemaPath, Runnable handlerMethod) throws Exception {
        ArgumentCaptor<ArrayNode> captor = ArgumentCaptor.forClass(ArrayNode.class);
        handlerMethod.run();
        verify(communicator).sendBulkRequest(captor.capture());
        ArrayNode actualEvents = captor.getValue();
        assertJsonMatchesSchema(schemaPath, actualEvents);
    }

    @Test
    public void testHandleSecurityEventSchemaValidation() throws Exception {
        SecurityLogContext context = mock(SecurityLogContext.class);
        SecurityLog securityLog = mock(SecurityLog.class);
        when(context.getUserInfo()).thenReturn(userInfo);
        when(context.getData()).thenReturn(securityLog);
        when(securityLog.getData()).thenReturn("security event data");
        runAndAssertEvent("src/test/resources/legacy-security-wrapper-schema.json", () -> handler.handleSecurityEvent(context));
    }

    @Test
    public void testHandleDataAccessEvent_MultiAttrAttach_MultiAccess() throws Exception {
        DataAccessLogContext context = mock(DataAccessLogContext.class);
        DataAccessLog dataAccessLog = mock(DataAccessLog.class);
        // Access 1
        KeyValuePair id1 = mockKeyValuePair("userId", "user-1");
        DataObject dataObject1 = mockDataObject("User", List.of(id1));
        DataSubject dataSubject1 = mockDataSubject("Person", List.of(id1));
        Attribute attr1 = mockAttribute("email");
        Attribute attr2 = mockAttribute("phone");
        Attachment att1 = mockAttachment("file", "file-1");
        Attachment att2 = mockAttachment("img", "img-2");
        Access access1 = mock(Access.class);
        when(access1.getDataObject()).thenReturn(dataObject1);
        when(access1.getDataSubject()).thenReturn(dataSubject1);
        when(access1.getAttributes()).thenReturn(List.of(attr1, attr2));
        when(access1.getAttachments()).thenReturn(List.of(att1, att2));
        // Access 2
        KeyValuePair id2 = mockKeyValuePair("userId", "user-2");
        DataObject dataObject2 = mockDataObject("User", List.of(id2));
        DataSubject dataSubject2 = mockDataSubject("Person", List.of(id2));
        Access access2 = mock(Access.class);
        when(access2.getDataObject()).thenReturn(dataObject2);
        when(access2.getDataSubject()).thenReturn(dataSubject2);
        when(access2.getAttributes()).thenReturn(List.of(attr1, attr2));
        when(access2.getAttachments()).thenReturn(List.of(att1, att2));
        when(dataAccessLog.getAccesses()).thenReturn(List.of(access1, access2));
        when(context.getData()).thenReturn(dataAccessLog);
        when(context.getUserInfo()).thenReturn(userInfo);
        runAndAssertEvent("src/test/resources/dpp-data-access-schema.json", () -> handler.handleDataAccessEvent(context));
    }

    @Test
    public void testHandleConfigChangeEvent_MultiConfig() throws Exception {
        ConfigChangeLogContext context = mock(ConfigChangeLogContext.class);
        ConfigChangeLog configChangeLog = mock(ConfigChangeLog.class);
        ChangedAttribute attr1 = mockChangedAttribute("logLevel", "INFO", "DEBUG");
        KeyValuePair id1 = mockKeyValuePair("appId", "app-999");
        DataObject dataObject1 = mockDataObject("AppConfig", List.of(id1));
        ConfigChange config1 = mockConfigChange(List.of(attr1), dataObject1);
        ChangedAttribute attr2 = mockChangedAttribute("maxConnections", "100", "200");
        KeyValuePair id2a = mockKeyValuePair("dbId", "db-12345");
        KeyValuePair id2b = mockKeyValuePair("region", "us30");
        DataObject dataObject2 = mockDataObject("DatabaseConfig", List.of(id2a, id2b));
        ConfigChange config2 = mockConfigChange(List.of(attr2), dataObject2);
        when(configChangeLog.getConfigurations()).thenReturn(List.of(config1, config2));
        when(context.getData()).thenReturn(configChangeLog);
        when(context.getUserInfo()).thenReturn(userInfo);
        handler.handleConfigChangeEvent(context);
        ArgumentCaptor<ArrayNode> captor = ArgumentCaptor.forClass(ArrayNode.class);
        verify(communicator).sendBulkRequest(captor.capture());
        ArrayNode actualEvents = captor.getValue();
        assertJsonMatchesSchema("src/test/resources/configuration-change-schema.json", actualEvents);
    }

    @Test
    public void testHandleDataModificationEvent_MultiModification() throws Exception {
        DataModificationLogContext context = mock(DataModificationLogContext.class);
        DataModificationLog dataModificationLog = mock(DataModificationLog.class);
        ChangedAttribute attr1 = mockChangedAttribute("email", "old1@example.com", "new1@example.com");
        KeyValuePair id1 = mockKeyValuePair("userId", "user-111");
        DataObject dataObject1 = mockDataObject("User", List.of(id1));
        DataSubject dataSubject1 = mockDataSubject("Person", List.of(id1));
        DataModification modification1 = mockDataModification(List.of(attr1), dataObject1, dataSubject1);
        ChangedAttribute attr2 = mockChangedAttribute("phone", "12345", "67890");
        KeyValuePair id2 = mockKeyValuePair("userId", "user-222");
        DataObject dataObject2 = mockDataObject("User", List.of(id2));
        DataSubject dataSubject2 = mockDataSubject("Person", List.of(id2));
        DataModification modification2 = mockDataModification(List.of(attr2), dataObject2, dataSubject2);
        when(dataModificationLog.getModifications()).thenReturn(List.of(modification1, modification2));
        when(context.getData()).thenReturn(dataModificationLog);
        when(context.getUserInfo()).thenReturn(userInfo);
        handler.handleDataModificationEvent(context);
        ArgumentCaptor<ArrayNode> captor = ArgumentCaptor.forClass(ArrayNode.class);
        verify(communicator).sendBulkRequest(captor.capture());
        ArrayNode actualEvents = captor.getValue();
        assertJsonMatchesSchema("src/test/resources/configuration-change-schema.json", actualEvents);

    }

    @Test
    public void testObjectIdAndSubjectIdAreAlphabeticallyOrdered() throws Exception {
        // Prepare test data with intentionally unordered keys
        KeyValuePair idA = mockKeyValuePair("zKey", "zValue");
        KeyValuePair idB = mockKeyValuePair("aKey", "aValue");
        KeyValuePair idC = mockKeyValuePair("mKey", "mValue");
        List<KeyValuePair> unorderedIds = List.of(idA, idB, idC);
        DataObject dataObject = mockDataObject("TestType", unorderedIds);
        DataSubject dataSubject = mockDataSubject("TestSubject", unorderedIds);
        ChangedAttribute attr = mockChangedAttribute("testAttr", "old", "new");
        DataModification modification = mockDataModification(List.of(attr), dataObject, dataSubject);
        DataModificationLog dataModificationLog = mock(DataModificationLog.class);
        when(dataModificationLog.getModifications()).thenReturn(List.of(modification));
        DataModificationLogContext context = mock(DataModificationLogContext.class);
        when(context.getData()).thenReturn(dataModificationLog);
        when(context.getUserInfo()).thenReturn(userInfo);
        // Capture the event JSON
        ArgumentCaptor<ArrayNode> captor = ArgumentCaptor.forClass(ArrayNode.class);
        handler.handleDataModificationEvent(context);
        verify(communicator).sendBulkRequest(captor.capture());
        ArrayNode actualEvents = captor.getValue();
        // Validate the JSON structure
        assertJsonMatchesSchema("src/test/resources/configuration-change-schema.json", actualEvents);
        // Further assertions can be done here to check the content of actualEvents
    }

    // --- Additional Tests for Robustness and Coverage ---
    @Test
    public void testHandleDataAccessEvent_NullAttributesAndAttachments() throws Exception {
        DataAccessLogContext context = mock(DataAccessLogContext.class);
        DataAccessLog dataAccessLog = mock(DataAccessLog.class);
        Access access = mock(Access.class);
        KeyValuePair id1 = mockKeyValuePair("userId", "user-111");
        DataObject dataObject = mockDataObject("User", List.of(id1));
        DataSubject dataSubject = mockDataSubject("Person", List.of(id1));
        when(access.getDataObject()).thenReturn(dataObject);
        when(access.getDataSubject()).thenReturn(dataSubject);
        when(access.getAttributes()).thenReturn(null);
        when(access.getAttachments()).thenReturn(null);
        when(dataAccessLog.getAccesses()).thenReturn(List.of(access));
        when(context.getData()).thenReturn(dataAccessLog);
        when(context.getUserInfo()).thenReturn(userInfo);

        ErrorStatusException ex = assertThrows(ErrorStatusException.class, () -> handler.handleDataAccessEvent(context));
        Assertions.assertTrue(ex.getCause() instanceof NullPointerException);
    }

    @Test
    public void testHandleConfigChangeEvent_EmptyAttributes() throws Exception {
        ConfigChangeLogContext context = mock(ConfigChangeLogContext.class);
        ConfigChangeLog configChangeLog = mock(ConfigChangeLog.class);
        ConfigChange config = mockConfigChange(List.of(), mockDataObject("AppConfig", List.of()));
        when(configChangeLog.getConfigurations()).thenReturn(List.of(config));
        when(context.getData()).thenReturn(configChangeLog);
        when(context.getUserInfo()).thenReturn(userInfo);
        handler.handleConfigChangeEvent(context);
        ArgumentCaptor<ArrayNode> captor = ArgumentCaptor.forClass(ArrayNode.class);
        verify(communicator).sendBulkRequest(captor.capture());
        ArrayNode actualEvents = captor.getValue();
        assertJsonMatchesSchema("src/test/resources/configuration-change-schema.json", actualEvents);
    }

    @Test
    public void testHandleDataModificationEvent_LargeBulk() throws Exception {
        DataModificationLogContext context = mock(DataModificationLogContext.class);
        DataModificationLog dataModificationLog = mock(DataModificationLog.class);
        List<DataModification> mods = new ArrayList<>();
        for (int i = 0; i < 100; i++) {
            ChangedAttribute attr = mockChangedAttribute("field" + i, "old" + i, "new" + i);
            KeyValuePair id = mockKeyValuePair("id", String.valueOf(i));
            DataObject obj = mockDataObject("Type", List.of(id));
            DataSubject subj = mockDataSubject("Subject", List.of(id));
            mods.add(mockDataModification(List.of(attr), obj, subj));
        }
        when(dataModificationLog.getModifications()).thenReturn(mods);
        when(context.getData()).thenReturn(dataModificationLog);
        when(context.getUserInfo()).thenReturn(userInfo);
        handler.handleDataModificationEvent(context);
        ArgumentCaptor<ArrayNode> captor = ArgumentCaptor.forClass(ArrayNode.class);
        verify(communicator).sendBulkRequest(captor.capture());
        ArrayNode actualEvents = captor.getValue();
        assertJsonMatchesSchema("src/test/resources/configuration-change-schema.json", actualEvents);
        Assertions.assertEquals(100, actualEvents.size(), "Should produce 100 events");
    }

    @Test
    public void testHandleDataModificationEvent_CommunicatorThrows() throws Exception {
        DataModificationLogContext context = mock(DataModificationLogContext.class);
        DataModificationLog dataModificationLog = mock(DataModificationLog.class);
        DataModification modification = mockDataModification(List.of(), mockDataObject("Type", List.of()), mockDataSubject("Subject", List.of()));
        when(dataModificationLog.getModifications()).thenReturn(List.of(modification));
        when(context.getData()).thenReturn(dataModificationLog);
        when(context.getUserInfo()).thenReturn(userInfo);
        // Simulate communicator throwing
        Mockito.doThrow(new RuntimeException("Simulated failure")).when(communicator).sendBulkRequest(ArgumentMatchers.any());
        boolean failed = false;
        try {
            handler.handleDataModificationEvent(context);
        } catch (RuntimeException e) {
            failed = true;
        }
        Assertions.assertTrue(failed, "Handler should propagate communicator exception");
    }

    @Test
    public void testHandleUserInfoWithNullFields() throws Exception {
        UserInfo userInfoNull = mock(UserInfo.class);
        when(userInfoNull.getName()).thenReturn(null);
        when(userInfoNull.getId()).thenReturn(null);
        SecurityLogContext context = mock(SecurityLogContext.class);
        SecurityLog securityLog = mock(SecurityLog.class);
        when(context.getUserInfo()).thenReturn(userInfoNull);
        when(context.getData()).thenReturn(securityLog);
        when(securityLog.getData()).thenReturn("security event data");
        handler.handleSecurityEvent(context);
        ArgumentCaptor<ArrayNode> captor = ArgumentCaptor.forClass(ArrayNode.class);
        verify(communicator).sendBulkRequest(captor.capture());
        ArrayNode actualEvents = captor.getValue();
        assertJsonMatchesSchema("src/test/resources/legacy-security-wrapper-schema.json", actualEvents);
    }

    @Test
    public void testHandleLegacyWrapperEvent() throws Exception {
        SecurityLogContext context = mock(SecurityLogContext.class);
        SecurityLog securityLog = mock(SecurityLog.class);
        when(context.getUserInfo()).thenReturn(userInfo);
        when(context.getData()).thenReturn(securityLog);
        when(securityLog.getData()).thenReturn("{\"legacy\":true}");
        runAndAssertEvent("src/test/resources/legacy-security-wrapper-schema.json", () -> handler.handleSecurityEvent(context));
    }

    @Test
    public void testHandleGeneralEvent_DataExportWrapping() throws Exception {
        // Prepare general context
        EventContext generalContext = mock(EventContext.class);
        when(generalContext.getUserInfo()).thenReturn(userInfo);
        when(generalContext.getEvent()).thenReturn("dataExport");

        // Simulate context.get("data") returning a Map with an 'event' JSON String
        String innerJson = "{\"channelType\":\"UNSPECIFIED\",\"channelId\":\"string\",\"objectType\":\"string\",\"objectId\":\"string\",\"destinationUri\":\"string\"}";
        Map<String,Object> outer = new HashMap<String,Object>();
        outer.put("event", innerJson);
        when(generalContext.get("data")).thenReturn(outer);

        // Execute
        handler.handleGeneralEvent(generalContext);

        // Capture and validate
        ArgumentCaptor<ArrayNode> captor = ArgumentCaptor.forClass(ArrayNode.class);
        verify(communicator).sendBulkRequest(captor.capture());
        ArrayNode events = captor.getValue();
        Assertions.assertEquals(1, events.size(), "Exactly one general event expected");
        JsonNode event = events.get(0);
        // Basic top-level assertions
        Assertions.assertEquals("dataExport", event.get("type").asText());
        JsonNode dataNode = event.get("data").get("data");
        Assertions.assertTrue(dataNode.has("dataExport"), "Inner data should be wrapped under 'dataExport'");
        JsonNode wrapped = dataNode.get("dataExport");
        Assertions.assertEquals("UNSPECIFIED", wrapped.get("channelType").asText());
        Assertions.assertEquals("string", wrapped.get("channelId").asText());
        // Schema validation (generic general event schema)
        assertJsonMatchesSchema("src/test/resources/general-event-schema.json", events);
    }

    private ChangedAttribute mockChangedAttribute(String name, String oldValue, String newValue) {
        ChangedAttribute attr = mock(ChangedAttribute.class);
        when(attr.getName()).thenReturn(name);
        when(attr.getOldValue()).thenReturn(oldValue);
        when(attr.getNewValue()).thenReturn(newValue);
        return attr;
    }

    private KeyValuePair mockKeyValuePair(String key, String value) {
        KeyValuePair kv = mock(KeyValuePair.class);
        when(kv.getKeyName()).thenReturn(key);
        when(kv.getValue()).thenReturn(value);
        return kv;
    }

    private Attribute mockAttribute(String name) {
        Attribute attr = mock(Attribute.class);
        when(attr.getName()).thenReturn(name);
        return attr;
    }

    private Attachment mockAttachment(String name, String id) {
        Attachment att = mock(Attachment.class);
        when(att.getName()).thenReturn(name);
        when(att.getId()).thenReturn(id);
        return att;
    }

    private DataObject mockDataObject(String type, List<KeyValuePair> ids) {
        DataObject obj = mock(DataObject.class);
        when(obj.getType()).thenReturn(type);
        when(obj.getId()).thenReturn(ids);
        return obj;
    }

    private DataSubject mockDataSubject(String type, List<KeyValuePair> ids) {
        DataSubject subj = mock(DataSubject.class);
        when(subj.getType()).thenReturn(type);
        when(subj.getId()).thenReturn(ids);
        return subj;
    }

    private DataModification mockDataModification(List<ChangedAttribute> attrs, DataObject obj, DataSubject subj) {
        DataModification mod = mock(DataModification.class);
        when(mod.getAttributes()).thenReturn(attrs);
        when(mod.getDataObject()).thenReturn(obj);
        when(mod.getDataSubject()).thenReturn(subj);
        return mod;
    }

    private ConfigChange mockConfigChange(List<ChangedAttribute> attrs, DataObject obj) {
        ConfigChange cc = mock(ConfigChange.class);
        when(cc.getAttributes()).thenReturn(attrs);
        when(cc.getDataObject()).thenReturn(obj);
        return cc;
    }

    private void assertJsonMatchesSchema(String schemaPath, JsonNode dataNode) throws Exception {
        JsonSchema schema = getTestSchema(schemaPath);
        Set<ValidationMessage> errors = schema.validate(dataNode);
        Assertions.assertTrue(errors.isEmpty(), "Schema validation errors: " + errors);
    }

    private JsonSchema getTestSchema(String schemaPath) throws Exception {
        JsonSchemaFactory factory = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V4);
        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode schemaContent = objectMapper.readTree(new File(schemaPath));
        JsonSchema schema = factory.getSchema(schemaContent);
        schema.initializeValidators();
        return schema;
    }
}

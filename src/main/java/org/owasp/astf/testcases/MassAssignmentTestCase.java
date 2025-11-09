package org.owasp.astf.testcases;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.http.HttpResponse;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.Severity;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Tests for API6:2023 - Mass Assignment.
 * 
 * This test case checks for mass assignment vulnerabilities by sending JSON payloads
 * with unexpected privileged fields to API endpoints. Mass Assignment occurs when
 * APIs allow attackers to update object properties they shouldn't have access to,
 * often leading to privilege escalation or data manipulation.
 * 
 * @see <a href="https://owasp.org/API-Security/editions/2023/en/0xa6-mass-assignment/">OWASP API Security Top 10 2023: API6 Mass Assignment</a>
 */
public class MassAssignmentTestCase implements TestCase {
    private static final Logger logger = LogManager.getLogger(MassAssignmentTestCase.class);

    private ScanConfig config;
    private final ObjectMapper objectMapper = new ObjectMapper(); // ✅ Jackson ObjectMapper

    // ✅ Подозрительные поля, указывающие на массовое присвоение
    private static final List<String> PRIVILEGED_FIELDS = List.of(
        "isAdmin", "role", "permissions", "level", "access", "privilege",
        "owner", "creator", "superuser", "admin", "root", "system",
        "internal", "hidden", "locked", "active", "verified",
        "password", "secret", "token", "session", "auth"
    );

    // ✅ Payloads для тестирования массового присвоения
    private static final List<String> MASS_ASSIGNMENT_PAYLOADS = List.of(
        // JSON с административными полями
        """
        {
          "name": "test user",
          "email": "test@example.com",
          "isAdmin": true,
          "role": "admin",
          "permissions": ["read", "write", "admin"]
        }
        """,
        // JSON с системными полями
        """
        {
          "account_id": "acc-12345",
          "balance": "1000000",
          "owner": "admin",
          "status": "active",
          "internal_id": "sys-99999"
        }
        """,
        // JSON с полями аутентификации
        """
        {
          "username": "hacker",
          "password": "newpass",
          "token": "fake-admin-token",
          "session": "admin-session-id"
        }
        """,
        // JSON с полями привилегий
        """
        {
          "user_id": "123",
          "privilege_level": 99,
          "access_granted": true,
          "locked": false,
          "verified": true
        }
        """
    );

    @Override
    public void init(ScanConfig config) {
        this.config = config;
    }

    @Override
    public String getId() {
        return "API6:2023";
    }

    @Override
    public String getName() {
        return "Mass Assignment (API6:2023)";
    }

    @Override
    public String getDescription() {
        return """
               Tests for mass assignment vulnerabilities by sending JSON payloads with 
               privileged fields that shouldn't be user-controllable.
               """;
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient client) throws IOException {
        List<Finding> findings = new ArrayList<>();

        // ✅ ПРОВЕРКА: Только POST/PUT/PATCH-запросы (где есть тело)
        String method = endpoint.getMethod().toUpperCase();
        if (!("POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method))) {
            logger.debug("⏭️ Skipping non-data endpoint for mass assignment: {}", endpoint.getPath());
            return findings;
        }

        System.out.println("🔧 Testing mass assignment on: " + method + " " + endpoint.getPath());

        // ✅ ИСПОЛЬЗУЕМ АУТЕНТИФИКАЦИОННЫЕ ЗАГОЛОВКИ ИЗ КОНФИГА
        Map<String, String> authHeaders = config.getHeaders() != null ? config.getHeaders() : new HashMap<>();
        authHeaders.put("Content-Type", "application/json");

        // ✅ ТЕСТИРУЕМ РАЗНЫЕ PAYLOAD ДЛЯ МАССОВОГО ПРИСВОЕНИЯ
        for (String payload : MASS_ASSIGNMENT_PAYLOADS) {
            List<Finding> payloadFindings = testMassAssignmentPayload(endpoint, client, payload, authHeaders);
            findings.addAll(payloadFindings);
        }

        if (findings.isEmpty()) {
            System.out.println("✅ Mass assignment protection verified: " + endpoint.getMethod() + " " + endpoint.getPath());
        } else {
            System.out.println("🎯 Mass assignment vulnerabilities found: " + findings.size() + " on " + endpoint.getPath());
        }

        return findings;
    }

    /**
     * ✅ Тестирует один payload на массовое присвоение
     */
    private List<Finding> testMassAssignmentPayload(EndpointInfo endpoint, HttpClient client, String payload, Map<String, String> authHeaders) {
        List<Finding> findings = new ArrayList<>();

        try {
            logger.debug("🧪 Testing mass assignment payload on: {}", endpoint.getFullUrl());

            // ✅ ИСПРАВЛЕНО: Используем post с тремя параметрами
            HttpResponse response = client.post(endpoint.getFullUrl(), authHeaders, payload);

            int statusCode = response.getStatusCode();
            String responseBody = response.getResponseBody(); // ✅ ИСПРАВЛЕНО: getResponseBody()

            // ✅ АНАЛИЗИРУЕМ ОТВЕТ НА ПРИЗНАКИ МАССОВОГО ПРИСВОЕНИЯ
            if (isMassAssignmentVulnerable(responseBody)) {
                findings.add(createMassAssignmentFinding(endpoint, payload, statusCode, responseBody));
                System.out.println("🚨 MASS ASSIGNMENT VULNERABILITY: " + endpoint.getPath());
            } else if (statusCode == 400 || statusCode == 422) {
                // ✅ OK: API отклонил неправильные поля
                logger.debug("✅ Mass assignment protection working: {}", endpoint.getPath());
            } else if (statusCode == 200 || statusCode == 201) {
                // ✅ ПОДОЗРИТЕЛЬНО: 200 OK, но поля не были отклонены
                if (hasPrivilegedFieldsInPayload(payload)) {
                    findings.add(createPotentialMassAssignmentFinding(endpoint, payload, statusCode, responseBody));
                    System.out.println("⚠️ POTENTIAL MASS ASSIGNMENT: " + endpoint.getPath());
                }
            }

        } catch (Exception e) {
            logger.debug("Mass assignment test failed for {}: {}", endpoint.getPath(), e.getMessage());
            // Не считаем ошибку за уязвимость
        }

        return findings;
    }

    /**
     * ✅ Проверяет, уязвим ли эндпоинт к массовому присвоению
     */
    private boolean isMassAssignmentVulnerable(String response) {
        if (response == null || response.trim().isEmpty()) {
            return false;
        }

        try {
            // ✅ ИСПОЛЬЗУЕМ JACKSON ДЛЯ АНАЛИЗА ОТВЕТА
            JsonNode responseJson = objectMapper.readTree(response);

            // ✅ ПРОВЕРЯЕМ, СОДЕРЖИТСЯ ЛИ В ОТВЕТЕ ПРИВИЛЕГИРОВАННЫЕ ПОЛЯ
            for (String privilegedField : PRIVILEGED_FIELDS) {
                if (hasFieldInJson(responseJson, privilegedField)) {
                    logger.warn("🚨 Privileged field '{}' found in response: {}", privilegedField, response);
                    return true;
                }
            }

            // ✅ ПРОВЕРЯЕМ, СОДЕРЖИТСЯ ЛИ В ОТВЕТЕ ADMIN-ПОЛЯ
            String lowerResponse = response.toLowerCase();
            if (lowerResponse.contains("admin") || lowerResponse.contains("isadmin") || 
                lowerResponse.contains("superuser") || lowerResponse.contains("root")) {
                // Проверяем, не является ли это ошибкой
                return !lowerResponse.contains("error") && !lowerResponse.contains("denied");
            }

        } catch (Exception e) {
            // Если JSON не валиден - не уязвимость
            logger.debug("Response is not valid JSON, skipping mass assignment check: {}", response);
        }

        return false;
    }

    /**
     * ✅ Проверяет, содержит ли JSON конкретное поле
     */
    private boolean hasFieldInJson(JsonNode node, String fieldName) {
        if (node.isObject()) {
            if (node.has(fieldName)) {
                return true;
            }
            // Рекурсивно проверяем вложенные объекты
            for (JsonNode child : node) {
                if (hasFieldInJson(child, fieldName)) {
                    return true;
                }
            }
        } else if (node.isArray()) {
            for (JsonNode element : node) {
                if (hasFieldInJson(element, fieldName)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * ✅ Проверяет, содержит ли payload привилегированные поля
     */
    private boolean hasPrivilegedFieldsInPayload(String payload) {
        String lowerPayload = payload.toLowerCase();
        for (String privilegedField : PRIVILEGED_FIELDS) {
            if (lowerPayload.contains(privilegedField.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    /**
     * ✅ Создаёт finding для подтверждённой уязвимости массового присвоения
     */
    private Finding createMassAssignmentFinding(EndpointInfo endpoint, String payload, int statusCode, String response) {
        return new Finding(
            "MASS-ASSIGN-01",
            "Mass Assignment Vulnerability (API6:2023)",
            "🚨 CRITICAL: Mass assignment vulnerability detected!\n\n" +
            "• Endpoint: " + endpoint.getMethod() + " " + endpoint.getPath() + "\n" +
            "• Payload: " + payload.substring(0, Math.min(100, payload.length())) + "..." + "\n" +
            "• Response Status: " + statusCode + "\n" +
            "• Response Contains Privileged Fields: " + findPrivilegedFieldsInResponse(response) + "\n" +
            "• Impact: Attackers can escalate privileges, modify system properties, or gain unauthorized access",
            Severity.CRITICAL,
            getId(),
            endpoint.getFullUrl(),
            "✅ CRITICAL REMEDIATION REQUIRED:\n\n" +
            "1. IMPLEMENT FIELD WHITELISTING\n" +
            "   • Define allowed fields for each endpoint explicitly\n" +
            "   • Reject requests with unexpected fields\n" +
            "   • Use DTOs or view models to control data binding\n\n" +
            "2. USE SECURE DATA BINDING\n" +
            "   • Implement strict data validation\n" +
            "   • Use frameworks with built-in mass assignment protection\n" +
            "   • Validate input against JSON Schema\n\n" +
            "3. APPLY PRINCIPLE OF LEAST PRIVILEGE\n" +
            "   • Don't expose administrative fields to users\n" +
            "   • Separate admin and user endpoints\n" +
            "   • Implement role-based field access\n\n" +
            "4. IMPLEMENT SERVER-SIDE VALIDATION\n" +
            "   • Validate all fields on server-side\n" +
            "   • Never trust client-provided field names\n" +
            "   • Log attempts to set privileged fields"
        );
    }

    /**
     * ✅ Создаёт finding для потенциальной уязвимости массового присвоения
     */
    private Finding createPotentialMassAssignmentFinding(EndpointInfo endpoint, String payload, int statusCode, String response) {
        return new Finding(
            "MASS-ASSIGN-POTENTIAL-01",
            "Potential Mass Assignment (API6:2023)",
            "⚠️ POTENTIAL MASS ASSIGNMENT VULNERABILITY:\n\n" +
            "• Endpoint: " + endpoint.getMethod() + " " + endpoint.getPath() + "\n" +
            "• Payload contained privileged fields: " + findPrivilegedFieldsInPayload(payload) + "\n" +
            "• Response Status: " + statusCode + "\n" +
            "• Response Length: " + response.length() + " chars\n" +
            "• Risk: API may be vulnerable to mass assignment attacks if privileged fields are accepted",
            Severity.HIGH,
            getId(),
            endpoint.getFullUrl(),
            "✅ IMPROVE INPUT VALIDATION:\n\n" +
            "1. REVIEW INPUT FIELDS\n" +
            "   • Check if privileged fields should be user-settable\n" +
            "   • Implement field-level access controls\n" +
            "   • Remove administrative fields from user endpoints\n\n" +
            "2. ENFORCE STRICT VALIDATION\n" +
            "   • Validate input against predefined schemas\n" +
            "   • Reject unknown fields with 400 Bad Request\n" +
            "   • Implement field filtering mechanisms\n\n" +
            "3. CONDUCT MANUAL VERIFICATION\n" +
            "   • Verify that privileged fields don't affect actual data\n" +
            "   • Test with different user roles\n" +
            "   • Confirm field access restrictions are enforced"
        );
    }

    /**
     * ✅ Находит привилегированные поля в ответе
     */
    private String findPrivilegedFieldsInResponse(String response) {
        List<String> foundFields = new ArrayList<>();
        String lowerResponse = response.toLowerCase();
        
        for (String field : PRIVILEGED_FIELDS) {
            if (lowerResponse.contains(field.toLowerCase())) {
                foundFields.add(field);
            }
        }
        
        return String.join(", ", foundFields);
    }

    /**
     * ✅ Находит привилегированные поля в payload
     */
    private String findPrivilegedFieldsInPayload(String payload) {
        List<String> foundFields = new ArrayList<>();
        String lowerPayload = payload.toLowerCase();
        
        for (String field : PRIVILEGED_FIELDS) {
            if (lowerPayload.contains(field.toLowerCase())) {
                foundFields.add(field);
            }
        }
        
        return String.join(", ", foundFields);
    }
}
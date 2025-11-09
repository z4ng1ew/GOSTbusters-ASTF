package org.owasp.astf.testcases;

import org.apache.http.client.methods.HttpGet;
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

/**
 * Tests for Injection vulnerabilities (API7:2023) - SQLi, NoSQLi, SSRF, XPath, etc.
 * 
 * This test case checks for injection vulnerabilities by sending malicious payloads
 * to API endpoints and analyzing responses for signs of successful injection attempts.
 * Injection attacks occur when untrusted data is sent to an interpreter as part of a command
 * or query, tricking the interpreter into executing unintended commands or accessing data
 * without proper authorization.
 * 
 * @see <a href="https://owasp.org/API-Security/editions/2023/en/0xa7-injection/">OWASP API Security Top 10 2023: API7 Injection</a>
 */
public class InjectionTestCase implements TestCase {
    private static final Logger logger = LogManager.getLogger(InjectionTestCase.class);

    private ScanConfig config;

    // ✅ ПОЛЕЗНЫЕ PAYLOADS ДЛЯ РАЗНЫХ ТИПОВ ИНЪЕКЦИЙ
    private static final List<String> INJECTION_PAYLOADS = List.of(
        // SQL Injection
        "' OR 1=1 --",
        "'; DROP TABLE users; --",
        "' UNION SELECT password FROM users --",
        "1' OR '1'='1",
        
        // NoSQL Injection
        "{\"$ne\": null}",
        "{\"$regex\": \".*\"}",
        "{\"$where\": \"this.password\"}",
        
        // XPath Injection
        "' or '1'='1",
        "' or 1=1 or '",
        
        // Command Injection
        "; ls -la",
        "| whoami",
        "&& dir",
        
        // SSRF (Server-Side Request Forgery)
        "http://169.254.169.254/latest/meta-data/",
        "http://localhost:8080/admin",
        "http://internal.service.local:80/",
        
        // XML/XPath Injection
        "<![CDATA[<script>alert(1)</script>]]>",
        "]]><script>alert('XSS')</script>",
        
        // Path Traversal
        "../../../etc/passwd",
        "..\\..\\windows\\system32\\drivers\\etc\\hosts",
        
        // JSON Injection (Mass Assignment)
        "{\"admin\": true}",
        "{\"isActive\": true}"
    );

    @Override
    public void init(ScanConfig config) {
        this.config = config;
    }

    @Override
    public String getId() {
        return "API7:2023";
    }

    @Override
    public String getName() {
        return "Injection Vulnerabilities (API7:2023)";
    }

    @Override
    public String getDescription() {
        return """
               Tests for injection vulnerabilities including SQLi, NoSQLi, SSRF, XPath, and other 
               injection attacks against API endpoints.
               """;
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient client) throws IOException {
        logger.info("Executing {} test on {}", getId(), endpoint);
        List<Finding> findings = new ArrayList<>();

        System.out.println("🧪 Testing injection vulnerabilities on: " + endpoint.getMethod() + " " + endpoint.getPath());

        // ✅ ИСПОЛЬЗУЕМ АУТЕНТИФИКАЦИОННЫЕ ЗАГОЛОВКИ ИЗ КОНФИГА
        Map<String, String> authHeaders = config.getHeaders() != null ? config.getHeaders() : Collections.emptyMap();

        // ✅ ТЕСТИРУЕМ РАЗНЫЕ ТИПЫ PAYLOAD
        for (String payload : INJECTION_PAYLOADS) {
            // ✅ ПРОВЕРЯЕМ, ПОДХОДИТ ЛИ PAYLOAD К ЭНДПОИНТУ
            if (isPayloadRelevant(payload, endpoint)) {
                List<Finding> payloadFindings = testInjectionPayload(endpoint, client, payload, authHeaders);
                findings.addAll(payloadFindings);
            }
        }

        if (findings.isEmpty()) {
            System.out.println("✅ Injection protection verified: " + endpoint.getMethod() + " " + endpoint.getPath());
        } else {
            System.out.println("🎯 Injection vulnerabilities found: " + findings.size() + " on " + endpoint.getPath());
        }

        return findings;
    }

    /**
     * ✅ Проверяет, подходит ли payload к эндпоинту
     */
    private boolean isPayloadRelevant(String payload, EndpointInfo endpoint) {
        String path = endpoint.getPath().toLowerCase();
        String method = endpoint.getMethod().toLowerCase();

        // ✅ SQL Injection для /accounts, /users, /transactions
        if (payload.contains("' OR 1=1") && (path.contains("account") || path.contains("user") || path.contains("transaction"))) {
            return true;
        }

        // ✅ NoSQL Injection для MongoDB API
        if (payload.contains("$ne") && path.contains("nosql")) {
            return true;
        }

        // ✅ SSRF для /proxy, /forward, /redirect, /webhook
        if (payload.contains("http://") && (path.contains("proxy") || path.contains("forward") || 
                                          path.contains("redirect") || path.contains("webhook"))) {
            return true;
        }

        // ✅ Path Traversal для /file, /download, /upload
        if (payload.contains("..") && (path.contains("file") || path.contains("download") || path.contains("upload"))) {
            return true;
        }

        // ✅ JSON Injection для POST/PUT с телом
        if (payload.contains("{") && ("post".equals(method) || "put".equals(method))) {
            return true;
        }

        // ✅ По умолчанию: тестировать все payload
        return true;
    }

    /**
     * ✅ Тестирует один injection payload
     */
    private List<Finding> testInjectionPayload(EndpointInfo endpoint, HttpClient client, String payload, Map<String, String> authHeaders) {
        List<Finding> findings = new ArrayList<>();

        try {
            // ✅ ЗАМЕНЯЕМ {id}, {accountId}, и т.д. на payload
            String testUrl = endpoint.getFullUrl()
                .replace("{id}", payload)
                .replace("{accountId}", payload)
                .replace("{account_id}", payload)
                .replace("{user_id}", payload);

            logger.debug("🧪 Testing injection payload: {} on {}", payload, testUrl);

            // ✅ ИСПРАВЛЕНО: Используем executeRequest с двумя параметрами
            HttpResponse response = client.executeRequest(new HttpGet(testUrl), authHeaders);

            int statusCode = response.getStatusCode();
            String responseBody = response.getResponseBody(); // ✅ ИСПРАВЛЕНО: getResponseBody()

            // ✅ АНАЛИЗИРУЕМ ОТВЕТ НА ПРИЗНАКИ ИНЪЕКЦИИ
            if (isInjectionSuccessful(statusCode, responseBody, payload)) {
                findings.add(createInjectionFinding(endpoint, testUrl, payload, statusCode, responseBody));
                System.out.println("🚨 INJECTION VULNERABILITY: " + payload + " on " + endpoint.getPath());
            } else if (isErrorIndicativeOfVulnerability(responseBody)) {
                // ✅ ПОТЕНЦИАЛЬНАЯ УЯЗВИМОСТЬ: ошибки могут указывать на уязвимость
                findings.add(createPotentialInjectionFinding(endpoint, testUrl, payload, statusCode, responseBody));
                System.out.println("⚠️ POTENTIAL INJECTION: " + payload + " caused error on " + endpoint.getPath());
            } else {
                System.out.println("✅ Injection protection: " + payload + " blocked on " + endpoint.getPath());
            }

        } catch (Exception e) {
            logger.debug("Injection test failed for payload {} on {}: {}", payload, endpoint.getPath(), e.getMessage());
            // Не считаем ошибку за уязвимость
        }

        return findings;
    }

    /**
     * ✅ Проверяет, успешна ли инъекция по ответу
     */
    private boolean isInjectionSuccessful(int statusCode, String responseBody, String payload) {
        if (responseBody == null || responseBody.trim().isEmpty()) {
            return false;
        }

        String lowerBody = responseBody.toLowerCase();

        // ✅ ПРИЗНАКИ SQL/NoSQL ИНЪЕКЦИИ
        if (payload.contains("' OR 1=1") || payload.contains("$ne") || payload.contains("$regex")) {
            return (statusCode == 200 || statusCode == 302) && // ✅ Успешный ответ при инъекции
                   (lowerBody.contains("error") || lowerBody.contains("exception") || 
                    lowerBody.contains("sql") || lowerBody.contains("database") ||
                    lowerBody.contains("syntax") || lowerBody.contains("malformed"));
        }

        // ✅ ПРИЗНАКИ SSRF
        if (payload.contains("http://169.254.169.254")) {
            return statusCode == 200 && // ✅ Успешный доступ к внутреннему сервису
                   (lowerBody.contains("instance-id") || lowerBody.contains("ami-id") ||
                    lowerBody.contains("hostname") || lowerBody.contains("metadata"));
        }

        // ✅ ПРИЗНАКИ PATH TRAVERSAL
        if (payload.contains("../../../") || payload.contains("..\\..\\")) {
            return statusCode == 200 && // ✅ Успешный доступ к файлу
                   (lowerBody.contains("root:") || lowerBody.contains("[boot]") ||
                    lowerBody.contains("localhost") || lowerBody.length() > 50);
        }

        // ✅ ПРИЗНАКИ COMMAND INJECTION
        if (payload.contains(";") || payload.contains("|") || payload.contains("&&")) {
            return statusCode == 200 && // ✅ Успешное выполнение команды
                   (lowerBody.contains("uid=") || lowerBody.contains("Directory of") ||
                    lowerBody.contains("C:\\") || lowerBody.contains("/home/") ||
                    lowerBody.contains("total ") && lowerBody.contains("drwx")); // ls output
        }

        // ✅ ПО УМОЛЧАНИЮ: если статус 200 и длинный ответ - подозрительно
        return statusCode == 200 && lowerBody.length() > 200 && 
               (lowerBody.contains("error") || lowerBody.contains("exception"));
    }

    /**
     * ✅ Проверяет, содержит ли ответ признаки уязвимости (ошибки)
     */
    private boolean isErrorIndicativeOfVulnerability(String responseBody) {
        if (responseBody == null) return false;

        String lowerBody = responseBody.toLowerCase();
        return lowerBody.contains("error") && 
               (lowerBody.contains("sql") || lowerBody.contains("database") || 
                lowerBody.contains("syntax") || lowerBody.contains("malformed"));
    }

    /**
     * ✅ Создает finding для подтверждённой инъекции
     */
    private Finding createInjectionFinding(EndpointInfo endpoint, String url, String payload, int statusCode, String response) {
        String injectionType = getInjectionType(payload);
        
        return new Finding(
            "INJECTION-" + injectionType.toUpperCase().replace(" ", ""),
            injectionType + " Injection Detected (API7:2023)",
            "🚨 CRITICAL: Successful " + injectionType + " injection detected!\n\n" +
            "• Payload: " + payload + "\n" +
            "• Endpoint: " + endpoint.getMethod() + " " + endpoint.getPath() + "\n" +
            "• Request URL: " + url + "\n" +
            "• Response Status: " + statusCode + "\n" +
            "• Response Length: " + (response != null ? response.length() : 0) + " chars\n" +
            "• Impact: Attackers can execute arbitrary queries, access internal systems, or manipulate data",
            Severity.CRITICAL,
            getId(),
            endpoint.getFullUrl(),
            "✅ CRITICAL REMEDIATION REQUIRED:\n\n" +
            "1. INPUT VALIDATION & SANITIZATION\n" +
            "   • Validate all input parameters strictly\n" +
            "   • Sanitize user input using whitelisting\n" +
            "   • Reject suspicious characters early\n\n" +
            "2. PARAMETERIZED QUERIES\n" +
            "   • Use prepared statements for database queries\n" +
            "   • Avoid dynamic query construction\n" +
            "   • Implement ORM query builders safely\n\n" +
            "3. OUTPUT ENCODING\n" +
            "   • Encode output before returning to clients\n" +
            "   • Prevent script execution in responses\n\n" +
            "4. IMPLEMENT RUNTIME PROTECTION\n" +
            "   • Deploy WAF with injection detection rules\n" +
            "   • Monitor for injection patterns in logs\n" +
            "   • Implement intrusion detection systems"
        );
    }

    /**
     * ✅ Создает finding для потенциальной инъекции (ошибки)
     */
    private Finding createPotentialInjectionFinding(EndpointInfo endpoint, String url, String payload, int statusCode, String response) {
        String injectionType = getInjectionType(payload);
        
        return new Finding(
            "INJECTION-POTENTIAL-" + injectionType.toUpperCase().replace(" ", ""),
            "Potential " + injectionType + " Injection (API7:2023)",
            "⚠️ POTENTIAL " + injectionType.toUpperCase() + " INJECTION:\n\n" +
            "• Payload: " + payload + "\n" +
            "• Endpoint: " + endpoint.getMethod() + " " + endpoint.getPath() + "\n" +
            "• Request URL: " + url + "\n" +
            "• Response Status: " + statusCode + "\n" +
            "• Error Keywords Found: " + findErrorKeywords(response) + "\n" +
            "• Risk: May indicate insufficient input validation or error handling",
            Severity.HIGH,
            getId(),
            endpoint.getFullUrl(),
            "✅ IMPROVE INPUT VALIDATION:\n\n" +
            "1. ENHANCE ERROR HANDLING\n" +
            "   • Don't expose detailed error messages to clients\n" +
            "   • Log errors server-side for analysis\n" +
            "   • Return generic error responses\n\n" +
            "2. STRENGTHEN INPUT VALIDATION\n" +
            "   • Implement strict type checking\n" +
            "   • Use JSON Schema validation\n" +
            "   • Apply size and format constraints\n\n" +
            "3. CONDUCT PENETRATION TESTING\n" +
            "   • Test with more sophisticated payloads\n" +
            "   • Validate all API parameters\n" +
            "   • Review database query construction"
        );
    }

    /**
     * ✅ Определяет тип инъекции по payload
     */
    private String getInjectionType(String payload) {
        if (payload.contains("' OR 1=1") || payload.contains("DROP TABLE") || payload.contains("UNION SELECT")) {
            return "SQL";
        } else if (payload.contains("$ne") || payload.contains("$regex") || payload.contains("$where")) {
            return "NoSQL";
        } else if (payload.contains("http://")) {
            return "SSRF";
        } else if (payload.contains("../../../") || payload.contains("..\\..\\")) {
            return "Path Traversal";
        } else if (payload.contains(";") || payload.contains("|") || payload.contains("&&")) {
            return "Command";
        } else if (payload.contains("<![CDATA[") || payload.contains("]]>")) {
            return "XPath";
        } else if (payload.contains("{") && payload.contains("admin")) {
            return "JSON/Mass Assignment";
        } else {
            return "Generic Injection";
        }
    }

    /**
     * ✅ Находит ключевые слова ошибок в ответе
     */
    private String findErrorKeywords(String response) {
        if (response == null) return "none";
        
        List<String> keywords = new ArrayList<>();
        String lower = response.toLowerCase();
        
        if (lower.contains("sql")) keywords.add("SQL");
        if (lower.contains("database")) keywords.add("Database");
        if (lower.contains("syntax")) keywords.add("Syntax");
        if (lower.contains("malformed")) keywords.add("Malformed");
        if (lower.contains("error")) keywords.add("Error");
        if (lower.contains("exception")) keywords.add("Exception");
        if (lower.contains("access denied")) keywords.add("Access Denied");
        if (lower.contains("forbidden")) keywords.add("Forbidden");
        
        return String.join(", ", keywords);
    }
}
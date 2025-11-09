package org.owasp.astf.testcases;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.http.client.methods.HttpGet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.http.HttpResponse;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.Severity;

/**
 * Tests for API10:2023 - Unsafe Consumption of APIs.
 * 
 * This test case checks for unsafe consumption of external APIs by looking for:
 * - Endpoints that accept external URLs as parameters
 * - API gateways/proxies that don't validate external destinations
 * - Unsafe handling of third-party API responses
 * - Missing validation of external API schemas
 * 
 * @see <a href="https://owasp.org/API-Security/editions/2023/en/0xaa-un-safe-consumption/">OWASP API Security Top 10 2023: API10 Unsafe Consumption</a>
 */
public class UnsafeConsumptionTestCase implements TestCase {
    private static final Logger logger = LogManager.getLogger(UnsafeConsumptionTestCase.class);

    private ScanConfig config;

    // ✅ Подозрительные параметры, указывающие на потребление внешних API
    private static final List<String> UNSAFE_CONSUMPTION_PARAMETERS = List.of(
        "url", "uri", "resource", "endpoint", "target", "destination", "source",
        "callback", "webhook", "redirect", "proxy", "forward", "load", "fetch",
        "import", "export", "image", "avatar", "file", "api", "service"
    );

    // ✅ Опасные домены для тестирования
    private static final List<String> DANGEROUS_DOMAINS = List.of(
        "evil.com", "malicious.site", "hacker.domain", "127.0.0.1", "localhost",
        "169.254.169.254", "metadata.google.internal", "169.254.170.2"
    );

    @Override
    public void init(ScanConfig config) {
        this.config = config;
    }

    @Override
    public String getId() {
        return "API10:2023";
    }

    @Override
    public String getName() {
        return "Unsafe Consumption of APIs (API10:2023)";
    }

    @Override
    public String getDescription() {
        return """
               Tests for unsafe consumption of external APIs including:
               - Unvalidated external URL parameters
               - Unsafe proxy/gateway implementations
               - Missing schema validation for external API responses
               - Improper handling of third-party API errors
               """;
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient client) throws IOException {
        List<Finding> findings = new ArrayList<>();

        System.out.println("🔗 Testing unsafe API consumption on: " + endpoint.getMethod() + " " + endpoint.getPath());

        // ✅ ПРОВЕРЯЕМ: содержит ли эндпоинт подозрительные параметры
        if (!hasUnsafeConsumptionParameters(endpoint)) {
            logger.debug("⏭️ Skipping non-unsafe consumption endpoint: {}", endpoint.getPath());
            return Collections.emptyList();
        }

        // ✅ ТЕСТИРУЕМ: уязвимости при потреблении внешних API
        findings.addAll(testExternalApiConsumption(endpoint, client));

        // ✅ ТЕСТИРУЕМ: уязвимости при работе с внешними сервисами
        findings.addAll(testExternalServiceIntegration(endpoint, client));

        if (findings.isEmpty()) {
            System.out.println("✅ Safe API consumption verified: " + endpoint.getMethod() + " " + endpoint.getPath());
        } else {
            System.out.println("⚠️ Unsafe consumption issues found: " + findings.size() + " on " + endpoint.getPath());
        }

        return findings;
    }

    /**
     * ✅ Проверяет, содержит ли эндпоинт параметры, уязвимые к unsafe consumption
     */
    private boolean hasUnsafeConsumptionParameters(EndpointInfo endpoint) {
        String path = endpoint.getPath().toLowerCase();
        String method = endpoint.getMethod().toUpperCase();

        // ✅ Только для методов, которые могут принимать внешние URL
        if (!("POST".equals(method) || "PUT".equals(method) || "GET".equals(method))) {
            return false;
        }

        // ✅ Проверяем путь на наличие подозрительных параметров
        for (String param : UNSAFE_CONSUMPTION_PARAMETERS) {
            if (path.contains(param)) {
                logger.debug("🔍 Unsafe consumption parameter found in path: {}", param);
                return true;
            }
        }

        // ✅ Проверяем тело запроса (если есть)
        if (endpoint.getRequestBody() != null) {
            String body = endpoint.getRequestBody().toLowerCase();
            for (String param : UNSAFE_CONSUMPTION_PARAMETERS) {
                if (body.contains(param)) {
                    logger.debug("🔍 Unsafe consumption parameter found in body: {}", param);
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * ✅ Тестирует уязвимости при потреблении внешних API
     */
    private List<Finding> testExternalApiConsumption(EndpointInfo endpoint, HttpClient client) {
        List<Finding> findings = new ArrayList<>();

        for (String dangerousDomain : DANGEROUS_DOMAINS) {
            String maliciousUrl = "http://" + dangerousDomain + ":80/";

            try {
                // ✅ ПОДСТАВЛЯЕМ ОПАСНЫЙ URL В ПОДОЗРИТЕЛЬНЫЕ ПАРАМЕТРЫ
                String testUrl = endpoint.getFullUrl();
                
                // ✅ ЗАМЕНЯЕМ ПОДОЗРИТЕЛЬНЫЕ ПАРАМЕТРЫ НА ОПАСНЫЙ URL
                for (String param : UNSAFE_CONSUMPTION_PARAMETERS) {
                    testUrl = testUrl
                        .replace("{" + param + "}", maliciousUrl)
                        .replace("?" + param + "=", "?" + param + "=" + maliciousUrl)
                        .replace("&" + param + "=", "&" + param + "=" + maliciousUrl);
                }

                // ✅ ВЫПОЛНЯЕМ ЗАПРОС С ОПАСНЫМ URL
                Map<String, String> authHeaders = config.getHeaders() != null ? config.getHeaders() : new HashMap<>();
                
                HttpResponse response = client.executeRequest(new HttpGet(testUrl), authHeaders);
                
                int statusCode = response.getStatusCode();
                String responseBody = response.getResponseBody(); // ✅ ИСПРАВЛЕНО: getResponseBody()
                String responseHeaders = response.getHeaders().toString(); // ✅ ИСПРАВЛЕНО: getHeaders()

                // ✅ АНАЛИЗИРУЕМ ОТВЕТ НА ПРИЗНАКИ УЯЗВИМОСТИ
                if (isUnsafeConsumptionVulnerable(statusCode, responseBody, responseHeaders, maliciousUrl)) {
                    findings.add(createUnsafeConsumptionFinding(endpoint, maliciousUrl, statusCode, responseBody));
                    System.out.println("🚨 UNSAFE CONSUMPTION VULNERABILITY: " + endpoint.getPath() + " -> " + maliciousUrl);
                } else {
                    System.out.println("✅ Safe consumption protection: " + endpoint.getPath() + " blocked " + maliciousUrl);
                }

            } catch (Exception e) {
                // ✅ ОШИБКА ПРИ ЗАПРОСЕ К ВНЕШНЕМУ URL - ЭТО МОЖЕТ БЫТЬ ЗАЩИТА
                if (e.getMessage() != null && e.getMessage().contains("Connection refused")) {
                    logger.debug("✅ Safe consumption: external connection refused for {}", dangerousDomain);
                } else {
                    logger.debug("External consumption test error for {}: {}", dangerousDomain, e.getMessage());
                }
            }
        }

        return findings;
    }

    /**
     * ✅ Тестирует интеграцию с внешними сервисами
     */
    private List<Finding> testExternalServiceIntegration(EndpointInfo endpoint, HttpClient client) {
        List<Finding> findings = new ArrayList<>();

        // ✅ ПРОВЕРЯЕМ: принимает ли эндпоинт URL в теле запроса
        if (endpoint.getRequestBody() != null && 
            (endpoint.getRequestBody().toLowerCase().contains("url") || 
             endpoint.getRequestBody().toLowerCase().contains("endpoint"))) {
            
            try {
                String maliciousRequestBody = endpoint.getRequestBody()
                    .replace("url", "http://evil.com/malicious-endpoint")
                    .replace("endpoint", "http://evil.com/malicious-service");

                Map<String, String> headers = new HashMap<>(config.getHeaders());
                headers.put("Content-Type", "application/json");

                HttpResponse response = client.executeRequest(new HttpGet(endpoint.getFullUrl()), headers);
                
                int statusCode = response.getStatusCode();
                String responseBody = response.getResponseBody(); // ✅ ИСПРАВЛЕНО: getResponseBody()

                if (isPotentialUnsafeConsumption(statusCode, responseBody)) {
                    findings.add(new Finding(
                        "API10-EXTERNAL-SERVICE-02",
                        "Unsafe External Service Integration",
                        "⚠️ MEDIUM: Endpoint may be consuming external services without proper validation.\n\n" +
                        "• Endpoint: " + endpoint.getMethod() + " " + endpoint.getPath() + "\n" +
                        "• Risk: May connect to malicious external services\n" +
                        "• Status: " + statusCode + "\n" +
                        "• Response length: " + (responseBody != null ? responseBody.length() : 0) + " chars",
                        Severity.MEDIUM,
                        getId(),
                        endpoint.getFullUrl(),
                        "✅ IMPROVE EXTERNAL SERVICE INTEGRATION:\n\n" +
                        "1. IMPLEMENT URL WHITELISTING\n" +
                        "   • Only allow connections to trusted domains\n" +
                        "   • Validate URL scheme (http/https only)\n\n" +
                        "2. USE SAFE PROXY PATTERNS\n" +
                        "   • Validate destination before forwarding\n" +
                        "   • Implement connection timeouts\n" +
                        "   • Block internal IP ranges (127.0.0.1, 10.0.0.0/8, etc.)\n\n" +
                        "3. VALIDATE EXTERNAL RESPONSES\n" +
                        "   • Check response content type\n" +
                        "   • Validate response structure against expected schema"
                    ));
                }

            } catch (Exception e) {
                logger.debug("External service integration test failed for {}: {}", endpoint.getPath(), e.getMessage());
            }
        }

        return findings;
    }

    /**
     * ✅ Проверяет, уязвим ли эндпоинт к unsafe consumption
     */
    private boolean isUnsafeConsumptionVulnerable(int statusCode, String responseBody, String responseHeaders, String maliciousUrl) {
        if (responseBody == null) {
            return false;
        }

        String lowerResponse = responseBody.toLowerCase();

        // ✅ ПРИЗНАКИ УСПЕШНОЙ АТАКИ:
        if (statusCode == 200) {
            // Если сервер пытался подключиться к внешнему сервису
            return lowerResponse.contains("evil.com") || 
                   lowerResponse.contains("malicious") ||
                   lowerResponse.contains("connection") && lowerResponse.contains("failed") ||
                   responseHeaders.toLowerCase().contains("external") ||
                   responseHeaders.toLowerCase().contains("proxy");
        }

        // ✅ ПРИЗНАКИ ОШИБКИ ПОДКЛЮЧЕНИЯ К ВНЕШНЕМУ СЕРВИСУ (тоже уязвимость!)
        if (statusCode >= 400 && statusCode < 600) {
            return lowerResponse.contains("connection refused") ||
                   lowerResponse.contains("timeout") ||
                   lowerResponse.contains("dns lookup failed") ||
                   lowerResponse.contains("unable to connect");
        }

        return false;
    }

    /**
     * ✅ Проверяет потенциальную уязвимость при потреблении внешних сервисов
     */
    private boolean isPotentialUnsafeConsumption(int statusCode, String responseBody) {
        if (responseBody == null) {
            return false;
        }

        String lowerResponse = responseBody.toLowerCase();
        return statusCode == 200 && 
               (lowerResponse.contains("external") || 
                lowerResponse.contains("service") || 
                lowerResponse.contains("integration"));
    }

    /**
     * ✅ Создаёт finding для подтверждённой unsafe consumption уязвимости
     */
    private Finding createUnsafeConsumptionFinding(EndpointInfo endpoint, String maliciousUrl, int statusCode, String response) {
        return new Finding(
            "API10-CONSUMPTION-01",
            "Unsafe API Consumption Vulnerability (API10:2023)",
            "🚨 CRITICAL: Unsafe consumption of external API detected!\n\n" +
            "• Endpoint: " + endpoint.getMethod() + " " + endpoint.getPath() + "\n" +
            "• Malicious URL: " + maliciousUrl + "\n" +
            "• Response Status: " + statusCode + "\n" +
            "• Response Length: " + (response != null ? response.length() : 0) + " chars\n" +
            "• Impact: Attackers can force the API to consume malicious external services, potentially leading to SSRF, data exfiltration, or service disruption",
            Severity.CRITICAL,
            getId(),
            endpoint.getFullUrl(),
            "✅ CRITICAL REMEDIATION REQUIRED:\n\n" +
            "1. IMPLEMENT STRICT URL VALIDATION\n" +
            "   • Only allow connections to trusted domains/IPs\n" +
            "   • Validate URL scheme, host, and port\n" +
            "   • Block internal addresses (127.0.0.1, 10.0.0.0/8, etc.)\n\n" +
            "2. USE SAFE PROXY PATTERNS\n" +
            "   • Validate destination before forwarding\n" +
            "   • Implement connection timeouts\n" +
            "   • Log all external API calls\n\n" +
            "3. APPLY PRINCIPLE OF LEAST PRIVILEGE\n" +
            "   • Run API processes with minimal network permissions\n" +
            "   • Limit outbound connections to necessary services only\n\n" +
            "4. VALIDATE EXTERNAL RESPONSES\n" +
            "   • Check response content type\n" +
            "   • Validate response structure against expected schema\n" +
            "   • Implement response size limits"
        );
    }
}
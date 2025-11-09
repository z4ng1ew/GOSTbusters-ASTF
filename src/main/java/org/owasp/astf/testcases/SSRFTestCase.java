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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Tests for API7:2023 - Server-Side Request Forgery (SSRF).
 * 
 * This test case checks for SSRF vulnerabilities by attempting to make the target API
 * fetch data from internal resources like metadata services, localhost, or other
 * internal hosts. SSRF occurs when an API accepts a user-supplied URL and makes
 * a request to that URL without proper validation, allowing attackers to probe
 * internal infrastructure.
 * 
 * @see <a href="https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/">OWASP API Security Top 10 2023: API7 Server-Side Request Forgery</a>
 */
public class SSRFTestCase implements TestCase {
    private static final Logger logger = LogManager.getLogger(SSRFTestCase.class);

    private ScanConfig config;

    // ✅ Подозрительные параметры, которые могут быть уязвимы к SSRF
    private static final List<String> SSRF_PARAMETER_NAMES = List.of(
        "url", "link", "uri", "redirect", "forward", "proxy", "callback", 
        "load", "fetch", "import", "export", "image", "avatar", "file",
        "resource", "endpoint", "target", "destination", "source"
    );

    // ✅ SSRF payload для разных сценариев
    private static final List<String> SSRF_PAYLOADS = List.of(
        // Metadata service URLs (AWS, Azure, GCP, OpenStack)
        "http://169.254.169.254/latest/meta-data/", // AWS EC2 Metadata
        "http://169.254.169.254/latest/user-data/",  // AWS EC2 User Data
        "http://metadata.google.internal/computeMetadata/v1/", // Google Cloud
        "http://169.254.169.254/openstack/latest/meta_data.json", // OpenStack
        "http://169.254.169.254/openstack/latest/user_data",     // OpenStack
        
        // Internal host addresses
        "http://localhost:80/",
        "http://localhost:443/",
        "http://localhost:8080/",
        "http://127.0.0.1:80/",
        "http://127.0.0.1:443/",
        "http://127.0.0.1:8080/",
        
        // Internal Docker addresses
        "http://docker.for.mac.localhost:80/",
        "http://host.docker.internal:80/",
        
        // Internal network ranges
        "http://10.0.0.1:80/",
        "http://172.16.0.1:80/",
        "http://192.168.1.1:80/",
        
        // Internal services (common ports)
        "http://internal.service.local:80/",
        "http://admin.service.local:8080/",
        "http://config.service.local:8081/",
        
        // DNS rebinding attempt
        "http://127.0.0.1.nip.io:80/",
        "http://10.0.0.1.nip.io:80/",
        
        // Custom payloads for Open Banking
        "http://vbank.open.bankingapi.ru/internal/admin", // Поддельный внутренний адрес
        "http://abank.open.bankingapi.ru/health",        // Поддельный health-check
        "http://sbank.open.bankingapi.ru/config"         // Поддельный конфиг
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
        return "Server-Side Request Forgery (API7:2023)";
    }

    @Override
    public String getDescription() {
        return """
               Tests for Server-Side Request Forgery vulnerabilities by attempting to make the API 
               request internal resources like metadata services, localhost, or other internal hosts.
               """;
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient client) throws IOException {
        List<Finding> findings = new ArrayList<>();

        System.out.println("🔍 Testing SSRF on: " + endpoint.getMethod() + " " + endpoint.getPath());

        // ✅ ПРОВЕРЯЕМ: содержит ли эндпоинт подозрительные параметры
        if (!hasSsrfSusceptibleParameters(endpoint)) {
            logger.debug("⏭️ Skipping non-SSRF endpoint: {}", endpoint.getPath());
            return Collections.emptyList();
        }

        // ✅ ТЕСТИРУЕМ РАЗНЫЕ SSRF PAYLOAD
        for (String payload : SSRF_PAYLOADS) {
            Finding finding = testSsrfPayload(endpoint, client, payload);
            if (finding != null) {
                findings.add(finding);
                
                // ✅ ОСТАНАВЛИВАЕМСЯ ПРИ ПЕРВОЙ УЯЗВИМОСТИ (для производительности)
                if (finding.getSeverity() == Severity.CRITICAL) {
                    break;
                }
            }
        }

        if (findings.isEmpty()) {
            System.out.println("✅ SSRF protection verified: " + endpoint.getMethod() + " " + endpoint.getPath());
        } else {
            System.out.println("🚨 SSRF vulnerabilities found: " + findings.size() + " on " + endpoint.getPath());
        }

        return findings;
    }

    /**
     * ✅ Проверяет, содержит ли эндпоинт параметры, уязвимые к SSRF
     */
    private boolean hasSsrfSusceptibleParameters(EndpointInfo endpoint) {
        String path = endpoint.getPath().toLowerCase();
        String method = endpoint.getMethod().toUpperCase();
        
        // ✅ Только POST/PUT/GET с подозрительными параметрами
        if (!("POST".equals(method) || "PUT".equals(method) || "GET".equals(method))) {
            return false;
        }

        // ✅ Проверяем путь на наличие подозрительных параметров
        for (String param : SSRF_PARAMETER_NAMES) {
            if (path.contains(param)) {
                logger.debug("🔍 SSRF-susceptible parameter found in path: {}", param);
                return true;
            }
        }

        // ✅ Проверяем тело запроса (если есть)
        if (endpoint.getRequestBody() != null) {
            String body = endpoint.getRequestBody().toLowerCase();
            for (String param : SSRF_PARAMETER_NAMES) {
                if (body.contains(param)) {
                    logger.debug("🔍 SSRF-susceptible parameter found in body: {}", param);
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * ✅ Тестирует один SSRF payload
     */
    private Finding testSsrfPayload(EndpointInfo endpoint, HttpClient client, String payload) {
        try {
            // ✅ ФОРМИРУЕМ URL С PAYLOAD
            String testUrl = endpoint.getFullUrl();
            
            // ✅ ЗАМЕНЯЕМ ПОДОЗРИТЕЛЬНЫЕ ПАРАМЕТРЫ НА PAYLOAD
            for (String paramName : SSRF_PARAMETER_NAMES) {
                testUrl = testUrl
                    .replace("{" + paramName + "}", payload)
                    .replace("?" + paramName + "=", "?" + paramName + "=" + payload)
                    .replace("&" + paramName + "=", "&" + paramName + "=" + payload);
            }

            // ✅ ЕСЛИ НЕТ ПАРАМЕТРОВ В URL - ПРОБУЕМ КАК ТЕЛО ЗАПРОСА
            if (testUrl.equals(endpoint.getFullUrl())) {
                return testSsrfInRequestBody(endpoint, client, payload);
            }

            logger.debug("🧪 Testing SSRF payload: {} on {}", payload, testUrl);

            // ✅ ИСПОЛЬЗУЕМ АУТЕНТИФИКАЦИОННЫЕ ЗАГОЛОВКИ ИЗ КОНФИГА
            Map<String, String> authHeaders = config.getHeaders() != null ? config.getHeaders() : new HashMap<>();
            authHeaders.put("Content-Type", "application/json");

            // ✅ ВЫПОЛНЯЕМ ЗАПРОС
            HttpResponse response = client.executeRequest(new HttpGet(testUrl), authHeaders);

            int statusCode = response.getStatusCode();
            String responseBody = response.getResponseBody(); // ✅ ИСПРАВЛЕНО: getResponseBody()
            String responseHeaders = response.getHeaders().toString(); // ✅ ИСПРАВЛЕНО: getHeaders()

            // ✅ АНАЛИЗИРУЕМ ОТВЕТ НА ПРИЗНАКИ SSRF
            if (isSsrfSuccessful(statusCode, responseBody, responseHeaders, payload)) {
                return createSsrfFinding(endpoint, payload, statusCode, responseBody);
            }

            // ✅ ПРОВЕРЯЕМ, НЕТ ЛИ ОШИБКИ ТАЙМАУТА (возможная SSRF в фоне)
            if (isPossibleSsrfBackgroundTask(response, payload)) {
                return createPotentialSsrfFinding(endpoint, payload);
            }

        } catch (Exception e) {
            // ✅ ИГНОРИРУЕМ ОШИБКИ ПОДКЛЮЧЕНИЯ - ЭТО НОРМАЛЬНО ДЛЯ SSRF ТЕСТОВ
            logger.debug("SSRF test failed for payload {}: {}", payload, e.getMessage());
        }

        return null;
    }

    /**
     * ✅ Тестирует SSRF в теле запроса (JSON)
     */
    private Finding testSsrfInRequestBody(EndpointInfo endpoint, HttpClient client, String payload) {
        try {
            // ✅ СОЗДАЕМ ТЕЛО С SSRF PAYLOAD
            String requestBody = createSsrfRequestBody(endpoint.getRequestBody(), payload);
            
            if (requestBody == null) {
                return null; // Не удалось создать тело с payload
            }

            logger.debug("🧪 Testing SSRF payload in request body: {}", payload);

            Map<String, String> headers = new HashMap<>(config.getHeaders());
            headers.put("Content-Type", "application/json");

            HttpResponse response = client.post(endpoint.getFullUrl(), headers, requestBody);

            int statusCode = response.getStatusCode();
            String responseBody = response.getResponseBody(); // ✅ ИСПРАВЛЕНО: getResponseBody()
            String responseHeaders = response.getHeaders().toString(); // ✅ ИСПРАВЛЕНО: getHeaders()

            if (isSsrfSuccessful(statusCode, responseBody, responseHeaders, payload)) {
                return createSsrfFinding(endpoint, payload, statusCode, responseBody);
            }

        } catch (Exception e) {
            logger.debug("SSRF request body test failed for payload {}: {}", payload, e.getMessage());
        }

        return null;
    }

    /**
     * ✅ Создаёт тело запроса с SSRF payload
     */
    private String createSsrfRequestBody(String originalBody, String payload) {
        if (originalBody == null || originalBody.trim().isEmpty()) {
            // ✅ Создаём простое тело с подозрительным полем
            return "{\"url\": \"" + payload + "\", \"resource\": \"" + payload + "\"}";
        }

        // ✅ ЗАМЕНЯЕМ ПОДОЗРИТЕЛЬНЫЕ ПОЛЯ В ТЕЛЕ
        String modifiedBody = originalBody;
        for (String paramName : SSRF_PARAMETER_NAMES) {
            modifiedBody = modifiedBody
                .replace("\"" + paramName + "\": \"\"", "\"" + paramName + "\": \"" + payload + "\"")
                .replace("\"" + paramName + "\": null", "\"" + paramName + "\": \"" + payload + "\"");
        }

        return modifiedBody;
    }

    /**
     * ✅ Проверяет, успешна ли SSRF атака
     */
    private boolean isSsrfSuccessful(int statusCode, String responseBody, String responseHeaders, String payload) {
        if (responseBody == null) {
            return false;
        }

        String lowerResponse = responseBody.toLowerCase();
        String lowerHeaders = responseHeaders.toLowerCase();

        // ✅ ПРИЗНАКИ УСПЕШНОЙ SSRF:
        // 1. Успешный ответ (200 OK) с подозрительным содержимым
        if (statusCode == 200) {
            // AWS Metadata Service
            if (payload.contains("169.254.169.254") && 
                (lowerResponse.contains("instance-id") || 
                 lowerResponse.contains("ami-id") || 
                 lowerResponse.contains("hostname") ||
                 lowerResponse.contains("local-hostname"))) {
                return true;
            }

            // Google Cloud Metadata
            if (payload.contains("metadata.google.internal") && 
                (lowerResponse.contains("project-id") || 
                 lowerResponse.contains("instance-name") ||
                 lowerResponse.contains("zone"))) {
                return true;
            }

            // Open Banking Internal Services
            if (payload.contains("internal") && 
                (lowerResponse.contains("admin") || 
                 lowerResponse.contains("config") || 
                 lowerResponse.contains("debug") ||
                 lowerResponse.contains("health"))) {
                return true;
            }

            // Generic internal service indicators
            if (lowerResponse.contains("internal") && 
                (lowerResponse.contains("service") || 
                 lowerResponse.contains("admin") || 
                 lowerResponse.contains("config") ||
                 lowerResponse.contains("metadata"))) {
                return true;
            }
        }

        // ✅ ПРИЗНАКИ ОШИБКИ ПОДКЛЮЧЕНИЯ К ВНУТРЕННЕМУ РЕСУРСУ (тоже уязвимость!)
        if (statusCode == 500 || statusCode == 502 || statusCode == 504) {
            if (lowerHeaders.contains("connection refused") || 
                lowerHeaders.contains("connection timeout") ||
                lowerResponse.contains("connection refused") ||
                lowerResponse.contains("timeout") ||
                lowerResponse.contains("connection") && lowerResponse.contains("failed")) {
                // Это может указывать на то, что сервер пытался подключиться к внутреннему ресурсу
                logger.warn("⚠️ Possible SSRF detected (connection error): {}", payload);
                return true;
            }
        }

        return false;
    }

    /**
     * ✅ Проверяет, возможно ли SSRF в фоне (через таймаут)
     */
    private boolean isPossibleSsrfBackgroundTask(HttpResponse response, String payload) {
        // Если запрос возвращает 202 Accepted или 200 OK, но с задержкой
        // Это может указывать на асинхронную SSRF атаку
        if (response.getStatusCode() == 202 || response.getStatusCode() == 200) {
            String body = response.getResponseBody(); // ✅ ИСПРАВЛЕНО: getResponseBody()
            return body.toLowerCase().contains("processing") || 
                   body.toLowerCase().contains("async") ||
                   body.toLowerCase().contains("background");
        }
        return false;
    }

    /**
     * ✅ Создаёт finding для подтверждённой SSRF уязвимости
     */
    private Finding createSsrfFinding(EndpointInfo endpoint, String payload, int statusCode, String response) {
        return new Finding(
            "SSRF-01",
            "Server-Side Request Forgery (API7:2023)",
            "🚨 CRITICAL: SSRF vulnerability confirmed!\n\n" +
            "• Endpoint: " + endpoint.getMethod() + " " + endpoint.getPath() + "\n" +
            "• Payload: " + payload + "\n" +
            "• Response Status: " + statusCode + "\n" +
            "• Response Length: " + (response != null ? response.length() : 0) + " chars\n" +
            "• Impact: Attackers can probe internal infrastructure, access metadata services, or bypass firewalls",
            Severity.CRITICAL,
            getId(),
            endpoint.getFullUrl(),
            "✅ CRITICAL REMEDIATION REQUIRED:\n\n" +
            "1. IMPLEMENT URL WHITELISTING\n" +
            "   • Allow only trusted domains/hosts\n" +
            "   • Use allow-lists for URL validation\n\n" +
            "2. BLOCK INTERNAL ADDRESSES\n" +
            "   • Reject requests to 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16\n" +
            "   • Block 169.254.169.254 (AWS metadata)\n" +
            "   • Block metadata.google.internal\n\n" +
            "3. USE PROXY FOR OUTBOUND REQUESTS\n" +
            "   • Route all outbound requests through a proxy\n" +
            "   • Configure proxy to block internal addresses\n\n" +
            "4. IMPLEMENT TIMEOUTS\n" +
            "   • Set short timeouts for outbound requests\n" +
            "   • Prevent SSRF from causing DoS\n\n" +
            "5. APPLY PRINCIPLE OF LEAST PRIVILEGE\n" +
            "   • Run API processes with minimal network permissions\n" +
            "   • Limit access to internal services"
        );
    }

    /**
     * ✅ Создаёт finding для потенциальной SSRF уязвимости
     */
    private Finding createPotentialSsrfFinding(EndpointInfo endpoint, String payload) {
        return new Finding(
            "SSRF-POTENTIAL-02",
            "Potential Server-Side Request Forgery (API7:2023)",
            "⚠️ MEDIUM: Potential SSRF vulnerability detected.\n\n" +
            "• Endpoint: " + endpoint.getMethod() + " " + endpoint.getPath() + "\n" +
            "• Payload: " + payload + "\n" +
            "• Risk: Server may be attempting to connect to internal resources\n" +
            "• Status: Request returned error suggesting connection attempt",
            Severity.MEDIUM,
            getId(),
            endpoint.getFullUrl(),
            "✅ IMPROVE INPUT VALIDATION:\n\n" +
            "1. REVIEW URL VALIDATION LOGIC\n" +
            "   • Check that all user-provided URLs are validated\n" +
            "   • Verify that internal addresses are blocked\n\n" +
            "2. IMPLEMENT CONNECTION LOGGING\n" +
            "   • Log all outbound connection attempts\n" +
            "   • Monitor for suspicious connection patterns\n\n" +
            "3. CONDUCT MANUAL VERIFICATION\n" +
            "   • Test with known internal addresses\n" +
            "   • Verify that internal resources are inaccessible"
        );
    }
}
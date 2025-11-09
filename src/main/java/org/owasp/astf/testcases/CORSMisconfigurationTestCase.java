package org.owasp.astf.testcases;

import org.apache.http.client.methods.HttpOptions;
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
import java.util.List;
import java.util.Map;

/**
 * Tests for CORS Misconfiguration (API6:2023).
 * <p>
 * This test case checks for insecure Cross-Origin Resource Sharing (CORS) configurations
 * that could allow unauthorized domains to access the API. Proper CORS configuration is
 * crucial for protecting against cross-site request forgery and data theft attacks.
 * </p>
 */
public class CORSMisconfigurationTestCase implements TestCase {
    private static final Logger logger = LogManager.getLogger(CORSMisconfigurationTestCase.class);

    private ScanConfig config;

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
        return "CORS Misconfiguration (API6:2023)";
    }

    @Override
    public String getDescription() {
        return """
               Tests for insecure CORS configuration that allows unauthorized cross-origin access.
               Checks for wildcards, overly permissive origins, and missing security headers.
               """;
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient client) throws IOException {
        logger.info("Executing {} test on {}", getId(), endpoint);
        List<Finding> findings = new ArrayList<>();

        System.out.println("🌐 Testing CORS configuration on: " + endpoint.getMethod() + " " + endpoint.getPath());

        // ✅ Проверяем CORS заголовки с поддельного Origin
        findings.addAll(testCORSConfiguration(endpoint, client));

        // ✅ Проверяем, что endpoint поддерживает OPTIONS (CORS preflight)
        findings.addAll(testOptionSupport(endpoint, client));

        if (findings.isEmpty()) {
            System.out.println("✅ CORS protection verified: " + endpoint.getMethod() + " " + endpoint.getPath());
        } else {
            System.out.println("🚨 CORS vulnerabilities found: " + findings.size() + " on " + endpoint.getPath());
        }

        return findings;
    }

    /**
     * ✅ Проверяет настройки CORS для уязвимостей
     */
    private List<Finding> testCORSConfiguration(EndpointInfo endpoint, HttpClient client) throws IOException {
        List<Finding> findings = new ArrayList<>();

        // ✅ ИСПРАВЛЕНО: Используем поддельный Origin для проверки уязвимости
        Map<String, String> corsHeaders = Map.of(
            "Origin", "https://evil.com", // ✅ Поддельный домен
            "Access-Control-Request-Method", "GET",
            "Access-Control-Request-Headers", "Authorization, Content-Type"
        );

        try {
            // ✅ ИСПРАВЛЕНО: Используем executeRequest и получаем HttpResponse
            HttpResponse response = client.executeRequest(
                new HttpOptions(endpoint.getFullUrl()),
                corsHeaders
            );

            // ✅ ПРОВЕРЯЕМ CORS ЗАГОЛОВКИ В ОТВЕТЕ
            Map<String, List<String>> responseHeaders = response.getHeaders();

            // ✅ Проверяем, есть ли уязвимые CORS заголовки
            String allowOrigin = getHeaderIgnoreCase(responseHeaders, "Access-Control-Allow-Origin");
            String allowCredentials = getHeaderIgnoreCase(responseHeaders, "Access-Control-Allow-Credentials");
            String allowMethods = getHeaderIgnoreCase(responseHeaders, "Access-Control-Allow-Methods");
            String allowHeaders = getHeaderIgnoreCase(responseHeaders, "Access-Control-Allow-Headers");

            // ✅ Проверка 1: Разрешён любой Origin (*)
            if ("*".equals(allowOrigin)) {
                findings.add(createCORSFinding(
                    "Wildcard Origin Allowed",
                    "CORS allows access from ANY origin via wildcard (*) - Critical security risk",
                    Severity.CRITICAL,
                    endpoint,
                    "Restrict Access-Control-Allow-Origin to specific trusted domains only"
                ));
            }

            // ✅ Проверка 2: Разрешён поддельный Origin (https://evil.com)
            if ("https://evil.com".equals(allowOrigin)) {
                findings.add(createCORSFinding(
                    "Evil Origin Trusted",
                    "CORS trusts malicious origin 'https://evil.com' - Complete domain takeover risk",
                    Severity.CRITICAL,
                    endpoint,
                    "Remove 'https://evil.com' from allowed origins list"
                ));
            }

            // ✅ Проверка 3: Разрешены.credentials при wildcard origin
            if ("*".equals(allowOrigin) && "true".equalsIgnoreCase(allowCredentials)) {
                findings.add(createCORSFinding(
                    "Wildcard + Credentials",
                    "CORS allows credentials with wildcard origin - Session hijacking possible",
                    Severity.CRITICAL,
                    endpoint,
                    "Never combine Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true"
                ));
            }

            // ✅ Проверка 4: Поддержка опасных методов
            if (allowMethods != null && (allowMethods.contains("PUT") || allowMethods.contains("DELETE"))) {
                findings.add(createCORSFinding(
                    "Dangerous Methods Allowed",
                    "CORS allows dangerous HTTP methods: " + allowMethods,
                    Severity.MEDIUM,
                    endpoint,
                    "Limit Access-Control-Allow-Methods to safe methods (GET, POST, HEAD)"
                ));
            }

            // ✅ Проверка 5: Поддержка чувствительных заголовков
            if (allowHeaders != null && (allowHeaders.toLowerCase().contains("authorization") || 
                                       allowHeaders.toLowerCase().contains("cookie"))) {
                findings.add(createCORSFinding(
                    "Sensitive Headers Allowed",
                    "CORS allows sensitive headers: " + allowHeaders,
                    Severity.HIGH,
                    endpoint,
                    "Restrict Access-Control-Allow-Headers to only necessary headers"
                ));
            }

            // ✅ Вывод найденных CORS заголовков для отладки
            if (config.isVerbose()) {
                System.out.println("🔍 CORS Headers found:");
                if (allowOrigin != null) System.out.println("   Access-Control-Allow-Origin: " + allowOrigin);
                if (allowCredentials != null) System.out.println("   Access-Control-Allow-Credentials: " + allowCredentials);
                if (allowMethods != null) System.out.println("   Access-Control-Allow-Methods: " + allowMethods);
                if (allowHeaders != null) System.out.println("   Access-Control-Allow-Headers: " + allowHeaders);
            }

        } catch (Exception e) {
            logger.debug("CORS test failed for endpoint {}: {}", endpoint.getPath(), e.getMessage());
        }

        return findings;
    }

    /**
     * ✅ Проверяет, поддерживает ли endpoint OPTIONS запросы
     */
    private List<Finding> testOptionSupport(EndpointInfo endpoint, HttpClient client) throws IOException {
        List<Finding> findings = new ArrayList<>();

        try {
            HttpResponse response = client.executeRequest(
                new HttpOptions(endpoint.getFullUrl()),
                Map.of() // Пустые заголовки для проверки поддержки
            );

            // Если endpoint не поддерживает OPTIONS - это может быть уязвимостью (CORS preflight)
            if (response.getStatusCode() != 200 && response.getStatusCode() != 204) {
                findings.add(new Finding(
                    "CORS-PREFLIGHT-01",
                    "Missing CORS Preflight Support",
                    "Endpoint does not support OPTIONS requests required for CORS preflight.\n" +
                    "This may indicate incomplete CORS implementation or potential bypass.",
                    Severity.LOW,
                    getId(),
                    endpoint.getFullUrl(),
                    "Implement proper OPTIONS support for CORS preflight requests:\n" +
                    "- Return 200/204 for valid preflight requests\n" +
                    "- Include required CORS headers in preflight response\n" +
                    "- Validate Origin, Method, and Headers in preflight"
                ));
            }

        } catch (Exception e) {
            logger.debug("OPTIONS support check failed for endpoint {}: {}", endpoint.getPath(), e.getMessage());
        }

        return findings;
    }

    /**
     * ✅ Вспомогательный метод: получает заголовок без учета регистра
     */
    private String getHeaderIgnoreCase(Map<String, List<String>> headers, String headerName) {
        for (Map.Entry<String, List<String>> entry : headers.entrySet()) {
            if (entry.getKey().equalsIgnoreCase(headerName) && !entry.getValue().isEmpty()) {
                return entry.getValue().get(0);
            }
        }
        return null;
    }

    /**
     * ✅ Вспомогательный метод: создает finding для CORS уязвимости
     */
    private Finding createCORSFinding(String title, String description, Severity severity, 
                                   EndpointInfo endpoint, String remediation) {
        return new Finding(
            "CORS-VULN-" + severity.name(),
            title,
            "🌐 CORS MISCONFIGURATION DETECTED:\n\n" +
            "• Vulnerability: " + description + "\n" +
            "• Endpoint: " + endpoint.getMethod() + " " + endpoint.getPath() + "\n" +
            "• Impact: Cross-site request forgery, data theft, session hijacking",
            severity,
            getId(),
            endpoint.getFullUrl(),
            "✅ CRITICAL REMEDIATION:\n\n" +
            remediation + "\n\n" +
            "STANDARD COMPLIANCE:\n" +
            "- Follow OWASP CORS Security Guidelines\n" +
            "- Implement strict origin validation\n" +
            "- Use secure-by-default CORS policies"
        );
    }
}
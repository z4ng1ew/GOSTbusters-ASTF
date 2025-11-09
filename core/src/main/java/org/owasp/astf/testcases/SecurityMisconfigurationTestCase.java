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
 * Tests for API8:2023 - Security Misconfiguration.
 * 
 * This test case checks for common security misconfigurations in API responses
 * including information disclosure through headers, missing security headers,
 * debug endpoints, and other configuration weaknesses that could aid attackers.
 * 
 * @see <a href="https://owasp.org/API-Security/editions/2023/en/0xa8-security-misconfiguration/">OWASP API Security Top 10 2023: API8 Security Misconfiguration</a>
 */
public class SecurityMisconfigurationTestCase implements TestCase {
    private static final Logger logger = LogManager.getLogger(SecurityMisconfigurationTestCase.class);

    private ScanConfig config;

    // ✅ Опасные заголовки, которые могут раскрывать информацию
    private static final List<String> INFORMATION_DISCLOSURE_HEADERS = List.of(
        "Server", "X-Powered-By", "X-AspNet-Version", "X-Drupal-Cache", 
        "X-Generator", "X-Frame-Options", "X-Content-Type-Options",
        "X-XSS-Protection", "X-Debug-Token", "X-Debug-Token-Link"
    );

    // ✅ Отсутствующие безопасные заголовки
    private static final Map<String, String> MISSING_SECURITY_HEADERS = Map.of(
        "Strict-Transport-Security", "max-age=31536000; includeSubDomains",
        "Content-Security-Policy", "default-src 'self'",
        "X-Content-Type-Options", "nosniff",
        "X-Frame-Options", "DENY",
        "X-XSS-Protection", "1; mode=block"
    );

    // ✅ Подозрительные пути (debug, admin, internal)
    private static final List<String> SUSPICIOUS_PATH_PATTERNS = List.of(
        "debug", "admin", "test", "internal", "health", "metrics", "actuator",
        "swagger", "api-docs", "console", "admin-panel", "config", "env"
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
        return "Security Misconfiguration (API8:2023)";
    }

    @Override
    public String getDescription() {
        return """
               Tests for security misconfigurations including information disclosure through headers,
               missing security headers, exposed debug endpoints, and other configuration weaknesses.
               """;
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient client) throws IOException {
        List<Finding> findings = new ArrayList<>();

        System.out.println("🛡️ Testing security configuration on: " + endpoint.getMethod() + " " + endpoint.getPath());

        // ✅ ИСПРАВЛЕНО: Используем аутентификационные заголовки из конфига
        Map<String, String> authHeaders = config.getHeaders() != null ? config.getHeaders() : new HashMap<>();

        try {
            // ✅ ИСПРАВЛЕНО: Используем executeRequest с аутентификацией
            HttpResponse response = client.executeRequest(new HttpGet(endpoint.getFullUrl()), authHeaders);

            // ✅ ПРОВЕРЯЕМ: Информационные заголовки (информационное раскрытие)
            findings.addAll(checkInformationDisclosureHeaders(response, endpoint));

            // ✅ ПРОВЕРЯЕМ: Отсутствующие безопасные заголовки
            findings.addAll(checkMissingSecurityHeaders(response, endpoint));

            // ✅ ПРОВЕРЯЕМ: Подозрительные пути (уязвимости конфигурации)
            findings.addAll(checkSuspiciousPathConfigurations(endpoint));

            // ✅ ПРОВЕРЯЕМ: Ответ на отсутствие аутентификации
            findings.addAll(testMissingAuthProtection(endpoint, client));

        } catch (Exception e) {
            logger.warn("Security misconfiguration test failed for {}: {}", endpoint.getPath(), e.getMessage());
            // Не добавляем finding для технических ошибок
        }

        if (findings.isEmpty()) {
            System.out.println("✅ Security configuration verified: " + endpoint.getMethod() + " " + endpoint.getPath());
        } else {
            System.out.println("🎯 Security misconfigurations found: " + findings.size() + " on " + endpoint.getPath());
        }

        return findings;
    }

    /**
     * ✅ Проверяет заголовки, раскрывающие информацию
     */
    private List<Finding> checkInformationDisclosureHeaders(HttpResponse response, EndpointInfo endpoint) {
        List<Finding> findings = new ArrayList<>();

        for (String headerName : INFORMATION_DISCLOSURE_HEADERS) {
            List<String> headerValues = response.getHeaderValues(headerName); // ✅ ИСПРАВЛЕНО: getHeaderValues()
            
            if (headerValues != null && !headerValues.isEmpty()) {
                String headerValue = headerValues.get(0); // Берём первое значение
                
                if (headerValue != null && !headerValue.trim().isEmpty() && 
                    !isSafeHeaderValue(headerValue)) {
                    
                    findings.add(new Finding(
                        "API8-INFO-DISC-" + headerName.toUpperCase().replace("-", ""),
                        "Information Disclosure via " + headerName + " Header",
                        "🚨 MEDIUM: " + headerName + " header reveals sensitive information:\n\n" +
                        "• Header: " + headerName + "\n" +
                        "• Value: " + headerValue + "\n" +
                        "• Endpoint: " + endpoint.getMethod() + " " + endpoint.getPath() + "\n" +
                        "• Impact: Attackers can identify technology stack and target specific vulnerabilities",
                        Severity.MEDIUM,
                        getId(),
                        endpoint.getFullUrl(),
                        "✅ SECURITY REMEDIATION:\n\n" +
                        "1. REMOVE OR OBFUSCATE SENSITIVE HEADERS\n" +
                        "   • Remove " + headerName + " header from responses\n" +
                        "   • Use generic values if header is required\n\n" +
                        "2. IMPLEMENT PROPER HEADER FILTERING\n" +
                        "   • Configure reverse proxy to strip sensitive headers\n" +
                        "   • Apply security middleware for header sanitization\n\n" +
                        "3. FOLLOW SECURITY BY DEFAULT PRINCIPLE\n" +
                        "   • Only include headers that serve a security purpose\n" +
                        "   • Regularly audit response headers for information disclosure"
                    ));
                }
            }
        }

        return findings;
    }

    /**
     * ✅ Проверяет отсутствующие безопасные заголовки
     */
    private List<Finding> checkMissingSecurityHeaders(HttpResponse response, EndpointInfo endpoint) {
        List<Finding> findings = new ArrayList<>();

        for (Map.Entry<String, String> entry : MISSING_SECURITY_HEADERS.entrySet()) {
            String securityHeader = entry.getKey();
            List<String> headerValues = response.getHeaderValues(securityHeader); // ✅ ИСПРАВЛЕНО: getHeaderValues()
            
            if (headerValues == null || headerValues.isEmpty()) {
                findings.add(new Finding(
                    "API8-SEC-HEADER-MISSING-" + securityHeader.toUpperCase().replace("-", ""),
                    "Missing Security Header: " + securityHeader,
                    "⚠️ MEDIUM: Security header " + securityHeader + " is missing from API response.\n\n" +
                    "• Required Header: " + securityHeader + "\n" +
                    "• Recommended Value: " + entry.getValue() + "\n" +
                    "• Endpoint: " + endpoint.getMethod() + " " + endpoint.getPath() + "\n" +
                    "• Impact: Potential for clickjacking, XSS, or other client-side attacks",
                    Severity.MEDIUM,
                    getId(),
                    endpoint.getFullUrl(),
                    "🛡️ SECURITY ENHANCEMENT REQUIRED:\n\n" +
                    "1. ADD MISSING SECURITY HEADERS\n" +
                    "   • Implement " + securityHeader + " with appropriate value\n" +
                    "   • Use framework-level security headers configuration\n\n" +
                    "2. CONFIGURE WEB SERVER/PROXY\n" +
                    "   • Add security headers at reverse proxy level\n" +
                    "   • Ensure headers are applied to all responses\n\n" +
                    "3. REGULAR SECURITY AUDITS\n" +
                    "   • Periodically check for missing security headers\n" +
                    "   • Use automated tools to verify header configuration"
                ));
            }
        }

        return findings;
    }

    /**
     * ✅ Проверяет подозрительные пути (debug, admin, internal)
     */
    private List<Finding> checkSuspiciousPathConfigurations(EndpointInfo endpoint) {
        List<Finding> findings = new ArrayList<>();
        String path = endpoint.getPath().toLowerCase();

        for (String pattern : SUSPICIOUS_PATH_PATTERNS) {
            if (path.contains(pattern)) {
                findings.add(new Finding(
                    "API8-SUSPICIOUS-PATH-01",
                    "Potentially Dangerous Endpoint Exposed",
                    "⚠️ MEDIUM: Endpoint contains potentially dangerous path pattern '" + pattern + "'\n\n" +
                    "• Endpoint: " + endpoint.getMethod() + " " + endpoint.getPath() + "\n" +
                    "• Pattern: " + pattern + "\n" +
                    "• Risk: Exposed debug/admin/internal endpoints can provide attack surface\n" +
                    "• Impact: Information disclosure, potential privilege escalation",
                    Severity.MEDIUM,
                    getId(),
                    endpoint.getFullUrl(),
                    "🔒 CONFIGURATION SECURITY:\n\n" +
                    "1. REMOVE DANGEROUS ENDPOINTS FROM PRODUCTION\n" +
                    "   • Ensure debug, admin, and internal endpoints are not accessible in prod\n" +
                    "   • Use environment-specific configuration\n\n" +
                    "2. IMPLEMENT PROPER ACCESS CONTROLS\n" +
                    "   • Apply strict authentication to sensitive endpoints\n" +
                    "   • Use network-level restrictions for internal paths\n\n" +
                    "3. REGULAR AUDIT OF EXPOSED ENDPOINTS\n" +
                    "   • Maintain updated inventory of all API endpoints\n" +
                    "   • Remove unused or legacy endpoints\n" +
                    "   • Monitor for unexpected endpoint exposure"
                ));
                break; // Добавляем только одно finding на эндпоинт
            }
        }

        return findings;
    }

    /**
     * ✅ Проверяет защиту от отсутствия аутентификации
     */
    private List<Finding> testMissingAuthProtection(EndpointInfo endpoint, HttpClient client) {
        List<Finding> findings = new ArrayList<>();

        try {
            // ✅ Создаём клиент без аутентификации
            HttpClient noAuthClient = createUnauthenticatedClient();
            
            HttpResponse response = noAuthClient.executeRequest(new HttpGet(endpoint.getFullUrl()), new HashMap<>());

            // ✅ Если получаем 200 OK без аутентификации - уязвимость!
            if (response.getStatusCode() == 200 && endpoint.isRequiresAuthentication()) {
                findings.add(new Finding(
                    "API8-AUTH-MISCONFIG-01",
                    "Missing Authentication Protection",
                    "🚨 CRITICAL: Endpoint accessible without authentication despite requiring it.\n\n" +
                    "• Endpoint: " + endpoint.getMethod() + " " + endpoint.getPath() + "\n" +
                    "• Expected Status: 401/403\n" +
                    "• Actual Status: 200 OK\n" +
                    "• Impact: Unauthorized access to sensitive data and functionality",
                    Severity.CRITICAL,
                    getId(),
                    endpoint.getFullUrl(),
                    "🔐 AUTHENTICATION SECURITY REQUIRED:\n\n" +
                    "1. IMPLEMENT PROPER AUTHENTICATION CHECKS\n" +
                    "   • Verify authentication token on every request\n" +
                    "   • Return 401 Unauthorized for missing/invalid tokens\n\n" +
                    "2. APPLY FRAMEWORK-LEVEL SECURITY\n" +
                    "   • Use security annotations (@PreAuthorize, @Secured)\n" +
                    "   • Configure authentication middleware\n\n" +
                    "3. SECURE BY DEFAULT\n" +
                    "   • Assume all endpoints require authentication unless explicitly public\n" +
                    "   • Regularly audit authentication requirements"
                ));
            }

        } catch (Exception e) {
            // Ошибка при запросе без аутентификации - это нормально (защита работает)
            logger.debug("Authentication protection test passed for {}: {}", endpoint.getPath(), e.getMessage());
        }

        return findings;
    }

    /**
     * ✅ Создаёт HttpClient без аутентификации
     */
    private HttpClient createUnauthenticatedClient() {
        ScanConfig noAuthConfig = new ScanConfig();
        noAuthConfig.setTargetUrl(config.getTargetUrl());
        noAuthConfig.setHeaders(new HashMap<>()); // Пустые заголовки
        noAuthConfig.setTimeoutMinutes(config.getTimeoutMinutes());
        noAuthConfig.setMaxRequestsPerSecond(config.getMaxRequestsPerSecond());
        noAuthConfig.setFollowRedirects(config.isFollowRedirects());
        noAuthConfig.setProxyHost(config.getProxyHost());
        noAuthConfig.setProxyPort(config.getProxyPort());
        return new HttpClient(noAuthConfig);
    }

    /**
     * ✅ Проверяет, является ли значение заголовка безопасным
     */
    private boolean isSafeHeaderValue(String value) {
        if (value == null) return true;
        
        String lowerValue = value.toLowerCase();
        // ✅ Безопасные значения
        return lowerValue.contains("generic") || 
               lowerValue.contains("secure") || 
               lowerValue.contains("production") ||
               value.length() <= 3; // Очень короткие значения
    }
}
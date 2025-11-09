package org.owasp.astf.testcases;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import org.apache.http.client.methods.HttpGet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.http.HttpResponse;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.Severity;
import org.owasp.astf.testcases.validation.AuthenticationValidator; // ✅ ИМПОРТ ДОБАВЛЕН

/**
 * Tests for API2:2023 Broken Authentication.
 *
 * This test case checks for weak authentication mechanisms, mishandling of tokens,
 * and other authentication-related vulnerabilities according to the OWASP API Security
 * Top 10 2023. Broken Authentication occurs when APIs implement authentication mechanisms
 * incorrectly, allowing attackers to compromise authentication tokens or exploit
 * implementation flaws to assume other users' identities temporarily or permanently.
 *
 * @see <a href="https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/">OWASP API Security Top 10 2023: API2 Broken Authentication</a>
 */
public class BrokenAuthenticationTestCase implements TestCase {
    private static final Logger logger = LogManager.getLogger(BrokenAuthenticationTestCase.class);

    // Common authentication-related paths for endpoint detection
    private static final List<String> AUTH_PATH_PATTERNS = List.of(
            "login", "auth", "token", "signin", "oauth", "session"
    );

    private ScanConfig config;

    @Override
    public void init(ScanConfig config) {
        this.config = config;
    }

    @Override
    public String getId() {
        return "API2:2023";
    }

    @Override
    public String getName() {
        return "Broken Authentication (API2:2023)";
    }

    @Override
    public String getDescription() {
        return """
               Tests for authentication weaknesses such as weak passwords, improper 
               token validation, missing or inconsistent authentication checks, and 
               credential exposure in URLs.
               """;
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient httpClient) throws IOException {
        logger.info("Executing {} test on {}", getId(), endpoint);
        List<Finding> findings = new ArrayList<>();

        System.out.println("🔐 Testing authentication on: " + endpoint.getMethod() + " " + endpoint.getPath());

        // ✅ ПРОВЕРЯЕМ: требует ли эндпоинт аутентификации
        if (endpoint.isRequiresAuthentication()) {
            // ✅ ИСПРАВЛЕНО: Используем AuthenticationValidator
            if (AuthenticationValidator.isUnauthenticatedAccessAllowed(endpoint, httpClient, config)) {
                findings.add(createAuthBypassFinding(endpoint));
                System.out.println("🚨 AUTH BYPASS: " + endpoint.getMethod() + " " + endpoint.getPath());
            } else {
                System.out.println("✅ Auth protected: " + endpoint.getMethod() + " " + endpoint.getPath());
            }
        }

        // ✅ Проверяем уязвимости токенов для всех endpoint'ов
        findings.addAll(testTokenVulnerabilities(endpoint, httpClient));

        // ✅ Проверяем authentication endpoints на слабые механизмы
        if (isAuthEndpoint(endpoint)) {
            findings.addAll(testWeakAuthentication(endpoint, httpClient));
        }

        // ✅ ДОБАВЛЕНО: Информационный вывод о результате проверки
        if (findings.isEmpty()) {
            System.out.println("✅ Authentication check passed: " + endpoint.getMethod() + " " + endpoint.getPath());
        } else {
            System.out.println("🚨 Authentication issues found: " + findings.size() + " on " + endpoint.getPath());
        }

        return findings;
    }

    /**
     * Checks if this is an authentication-related endpoint by examining path patterns.
     *
     * @param endpoint The endpoint to check
     * @return true if this appears to be an authentication-related endpoint
     */
    private boolean isAuthEndpoint(EndpointInfo endpoint) {
        String path = endpoint.getPath().toLowerCase();

        // Check against common authentication path patterns
        return AUTH_PATH_PATTERNS.stream().anyMatch(path::contains);
    }

    /**
     * ✅ УПРОЩЕННАЯ И УЛУЧШЕННАЯ ЛОГИКА: Проверяет отсутствие аутентификации
     * (ЗАМЕНЕНО: теперь используем AuthenticationValidator)
     */
    private List<Finding> testMissingAuthentication(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();

        // ✅ ИСПОЛЬЗУЕМ ВАЛИДАТОР (вместо встроенной логики)
        if (AuthenticationValidator.isUnauthenticatedAccessAllowed(endpoint, httpClient, config)) {
            findings.add(createAuthBypassFinding(endpoint));
            System.out.println("🚨 AUTH BYPASS: " + endpoint.getMethod() + " " + endpoint.getPath());
        } else {
            System.out.println("✅ Auth protected: " + endpoint.getMethod() + " " + endpoint.getPath());
        }

        return findings;
    }

    /**
     * ✅ ДОБАВЛЕНО: Проверяет, разрешен ли доступ без аутентификации
     * (МЕТОД УДАЛЕН - теперь используем AuthenticationValidator)
     */
    // ✅ УДАЛЕНО: isUnauthenticatedAccessAllowed() - теперь в AuthenticationValidator

    /**
     * ✅ ДОБАВЛЕНО: Создает finding для обхода аутентификации
     */
    private Finding createAuthBypassFinding(EndpointInfo endpoint) {
        String httpMethod = endpoint.getMethod().toUpperCase();
        String operationType = getOperationType(httpMethod);
        
        return new Finding(
            "AUTH-BYPASS-01",
            "Missing Authentication Controls",
            "🚨 CRITICAL: " + operationType + " endpoint accessible without authentication.\n\n" +
            "• Endpoint: " + endpoint.getMethod() + " " + endpoint.getPath() + "\n" +
            "• Expected: 401 Unauthorized for unauthenticated requests\n" +
            "• Actual: 200 OK without authentication token\n" +
            "• Impact: Attackers can access sensitive data/modify resources without authentication",
            Severity.CRITICAL,
            getId(),
            endpoint.getFullUrl(),
            "✅ CRITICAL REMEDIATION REQUIRED:\n\n" +
            "1. IMPLEMENT AUTHENTICATION MIDDLEWARE\n" +
            "   • Validate authentication tokens on every request\n" +
            "   • Return 401 Unauthorized for missing/invalid tokens\n\n" +
            "2. ENFORCE ACCESS CONTROL\n" +
            "   • Apply authentication consistently across all endpoints\n" +
            "   • Use framework-level security controls\n\n" +
            "3. SECURE BY DEFAULT\n" +
            "   • Assume all endpoints require authentication unless explicitly public\n" +
            "   • Conduct regular security reviews of authentication logic"
        );
    }

    /**
     * ✅ ДОБАВЛЕНО: Возвращает тип операции для HTTP метода
     */
    private String getOperationType(String httpMethod) {
        return switch (httpMethod) {
            case "GET" -> "Data retrieval";
            case "POST" -> "Data creation";
            case "PUT" -> "Data update";
            case "DELETE" -> "Data deletion";
            case "PATCH" -> "Data modification";
            default -> "API operation";
        };
    }

    /**
     * ✅ УЛУЧШЕННЫЙ МЕТОД: Тестирует уязвимости токенов
     */
    private List<Finding> testTokenVulnerabilities(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();

        System.out.println("🔐 Testing token validation on: " + endpoint.getPath());

        // Test 1: Empty token
        if (testEmptyToken(endpoint, httpClient)) {
            findings.add(createTokenFinding("Empty token accepted", "TOKEN-EMPTY-01", endpoint));
        }

        // Test 2: Malformed token
        if (testMalformedToken(endpoint, httpClient)) {
            findings.add(createTokenFinding("Malformed token accepted", "TOKEN-INVALID-01", endpoint));
        }

        // Test 3: Token in URL parameters
        if (testTokenInUrl(endpoint, httpClient)) {
            findings.add(createTokenFinding("Token accepted in URL parameters", "TOKEN-URL-01", endpoint));
        }

        // Test 4: Test without any authentication headers
        if (testNoAuthHeaders(endpoint, httpClient)) {
            findings.add(createTokenFinding("Request accepted without any authentication headers", "TOKEN-MISSING-01", endpoint));
        }

        return findings;
    }

    /**
     * ✅ ДОБАВЛЕНО: Тестирует пустой токен
     */
    private boolean testEmptyToken(EndpointInfo endpoint, HttpClient httpClient) {
        try {
            Map<String, String> emptyTokenHeaders = new HashMap<>();
            emptyTokenHeaders.put("Authorization", "");
            
            // ✅ ИСПРАВЛЕНО: Используем executeRequest и получаем HttpResponse
            HttpResponse response = httpClient.executeRequest(
                new HttpGet(endpoint.getFullUrl()),
                emptyTokenHeaders
            );
            
            return response.getStatusCode() == 200;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * ✅ ДОБАВЛЕНО: Тестирует некорректный токен
     */
    private boolean testMalformedToken(EndpointInfo endpoint, HttpClient httpClient) {
        try {
            Map<String, String> malformedTokenHeaders = new HashMap<>();
            malformedTokenHeaders.put("Authorization", "Bearer invalid_token_12345");
            
            // ✅ ИСПРАВЛЕНО: Используем executeRequest и получаем HttpResponse
            HttpResponse response = httpClient.executeRequest(
                new HttpGet(endpoint.getFullUrl()),
                malformedTokenHeaders
            );
            
            return response.getStatusCode() == 200;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * ✅ ДОБАВЛЕНО: Тестирует токен в URL параметрах
     */
    private boolean testTokenInUrl(EndpointInfo endpoint, HttpClient httpClient) {
        try {
            String urlWithToken = endpoint.getFullUrl() + 
                (endpoint.getFullUrl().contains("?") ? "&" : "?") + "token=test123";
            
            // ✅ ИСПРАВЛЕНО: Используем executeRequest и получаем HttpResponse
            HttpResponse response = httpClient.executeRequest(
                new HttpGet(urlWithToken),
                new HashMap<>() // Пустые заголовки
            );
            
            return response.getStatusCode() == 200;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * ✅ ДОБАВЛЕНО: Тестирует запрос без заголовков аутентификации
     */
    private boolean testNoAuthHeaders(EndpointInfo endpoint, HttpClient httpClient) {
        try {
            // ✅ ИСПРАВЛЕНО: Используем executeRequest и получаем HttpResponse
            HttpResponse response = httpClient.executeRequest(
                new HttpGet(endpoint.getFullUrl()),
                new HashMap<>() // Пустые заголовки
            );
            
            return response.getStatusCode() == 200;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * ✅ УЛУЧШЕННЫЙ МЕТОД: Создает finding для уязвимостей токенов
     */
    private Finding createTokenFinding(String issue, String findingId, EndpointInfo endpoint) {
        return new Finding(
            findingId,
            "Token Validation Vulnerability",
            "🔐 " + issue + " - Authentication token validation is weak or missing\n\n" +
            "• Vulnerability: " + issue + "\n" +
            "• Endpoint: " + endpoint.getMethod() + " " + endpoint.getPath() + "\n" +
            "• Impact: Potential unauthorized access through token manipulation",
            Severity.MEDIUM,
            getId(),
            endpoint.getFullUrl(),
            "✅ IMPROVE TOKEN VALIDATION:\n\n" +
            "1. STRICT TOKEN VALIDATION\n" +
            "   • Reject empty, malformed, or invalid tokens\n" +
            "   • Validate token signature and expiration\n\n" +
            "2. SECURE TOKEN HANDLING\n" +
            "   • Never accept tokens in URL parameters\n" +
            "   • Use Authorization header exclusively\n" +
            "   • Implement proper token revocation\n\n" +
            "3. DEFENSE IN DEPTH\n" +
            "   • Log authentication attempts\n" +
            "   • Monitor for suspicious token usage\n" +
            "   • Regular security testing of authentication flows"
        );
    }

    /**
     * ✅ УПРОЩЕННАЯ ЛОГИКА: Тестирует слабые механизмы аутентификации
     */
    private List<Finding> testWeakAuthentication(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();

        // Only test POST methods for login endpoints
        if (!endpoint.getMethod().equalsIgnoreCase("POST")) {
            return findings;
        }

        System.out.println("🔑 Testing authentication endpoint: " + endpoint.getPath());

        // ✅ ДОБАВЛЕНО: Проверка common security headers
        try {
            Map<String, String> headers = new HashMap<>();
            // ✅ ИСПРАВЛЕНО: Используем executeRequest и получаем HttpResponse
            HttpResponse response = httpClient.executeRequest(
                new HttpGet(endpoint.getFullUrl()),
                headers
            );
            
            // Проверяем наличие security headers
            Map<String, List<String>> responseHeaders = response.getHeaders();
            boolean hasRateLimiting = responseHeaders.containsKey("X-RateLimit-Limit") || 
                                    responseHeaders.containsKey("RateLimit-Limit") ||
                                    responseHeaders.containsKey("X-Rate-Limit");
            boolean hasLockoutMechanism = responseHeaders.containsKey("X-Account-Lockout") ||
                                        responseHeaders.containsKey("X-Brute-Force-Protection");
            
            if (!hasRateLimiting && !hasLockoutMechanism) {
                Finding finding = new Finding(
                    "AUTH-WEAK-01",
                    "Weak Authentication Mechanisms",
                    "🔐 Authentication endpoint may lack brute force protection mechanisms:\n" +
                    "• No rate limiting detected\n" + 
                    "• No account lockout mechanisms visible\n" +
                    "• Consider implementing additional security controls",
                    Severity.MEDIUM,
                    getId(),
                    endpoint.getFullUrl(),
                    "✅ IMPROVE AUTHENTICATION SECURITY:\n" +
                    "• Implement rate limiting (max attempts per minute)\n" +
                    "• Add account lockout after 5-10 failed attempts\n" +
                    "• Use strong password policies\n" +
                    "• Consider multi-factor authentication"
                );
                findings.add(finding);
            }
        } catch (Exception e) {
            // Expected for authentication endpoints
            logger.debug("Authentication endpoint may not support GET: {}", e.getMessage());
        }

        return findings;
    }
}
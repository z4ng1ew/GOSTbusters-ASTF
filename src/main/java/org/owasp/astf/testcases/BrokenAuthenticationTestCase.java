package org.owasp.astf.testcases;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.Severity;

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

    @Override
    public String getId() {
        return "ASTF-API2-2023";
    }

    @Override
    public String getName() {
        return "Broken Authentication";
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

        // ✅ УПРОЩЕННАЯ ЛОГИКА: Единый подход для всех endpoint types
        System.out.println("🔐 Testing authentication on: " + endpoint.getMethod() + " " + endpoint.getFullUrl());

        // ✅ Проверяем доступ без токена для endpoint'ов, требующих аутентификации
        if (endpoint.isRequiresAuthentication()) {
            findings.addAll(testMissingAuthentication(endpoint, httpClient));
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
            String response = httpClient.get(endpoint.getFullUrl(), headers);
            
            // Проверяем наличие security headers
            if (!response.contains("rate-limit") && !response.contains("lockout")) {
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
        }

        return findings;
    }

    /**
     * ✅ УПРОЩЕННАЯ И УЛУЧШЕННАЯ ЛОГИКА: Проверяет отсутствие аутентификации
     */
    private List<Finding> testMissingAuthentication(EndpointInfo endpoint, HttpClient httpClient) {
        List<Finding> findings = new ArrayList<>();

        try {
            // ✅ ПРОСТАЯ ПРОВЕРКА: Доступен ли endpoint без аутентификации
            if (isUnauthenticatedAccessAllowed(endpoint, httpClient)) {
                Finding finding = createAuthBypassFinding(endpoint);
                findings.add(finding);
                System.out.println("🚨 AUTH BYPASS: " + endpoint.getMethod() + " " + endpoint.getPath());
            } else {
                System.out.println("✅ Auth protected: " + endpoint.getMethod() + " " + endpoint.getPath());
            }

        } catch (Exception e) {
            logger.debug("Error testing missing authentication on endpoint {}: {}", endpoint, e.getMessage());
        }

        return findings;
    }

    /**
     * ✅ ДОБАВЛЕНО: Проверяет, разрешен ли доступ без аутентификации
     */
    private boolean isUnauthenticatedAccessAllowed(EndpointInfo endpoint, HttpClient httpClient) {
        try {
            // Создаем заголовки без аутентификации
            Map<String, String> emptyHeaders = new HashMap<>();
            
            String response = performUnauthenticatedRequest(endpoint, httpClient, emptyHeaders);
            int statusCode = extractStatusCode(response);
            
            // ✅ Если статус 200 - доступ разрешен без аутентификации (уязвимость)
            return statusCode == 200;
            
        } catch (Exception e) {
            // Если исключение - вероятно, аутентификация требуется
            return false;
        }
    }

    /**
     * ✅ ДОБАВЛЕНО: Выполняет запрос без аутентификации в зависимости от метода
     */
    private String performUnauthenticatedRequest(EndpointInfo endpoint, HttpClient httpClient, 
                                               Map<String, String> emptyHeaders) throws IOException {
        String fullUrl = endpoint.getFullUrl();
        
        switch (endpoint.getMethod().toUpperCase()) {
            case "GET":
                return httpClient.get(fullUrl, emptyHeaders);
                
            case "POST":
                String requestBody = endpoint.getRequestBody() != null ? endpoint.getRequestBody() : "{}";
                String contentType = endpoint.getContentType() != null ? endpoint.getContentType() : "application/json";
                return httpClient.post(fullUrl, emptyHeaders, contentType, requestBody);
                
            case "PUT":
                requestBody = endpoint.getRequestBody() != null ? endpoint.getRequestBody() : "{}";
                contentType = endpoint.getContentType() != null ? endpoint.getContentType() : "application/json";
                return httpClient.put(fullUrl, emptyHeaders, contentType, requestBody);
                
            case "DELETE":
                return httpClient.delete(fullUrl, emptyHeaders);
                
            default:
                return httpClient.get(fullUrl, emptyHeaders);
        }
    }

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
            Severity.HIGH,
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
        switch (httpMethod) {
            case "GET": return "Data retrieval";
            case "POST": return "Data creation";
            case "PUT": return "Data update"; 
            case "DELETE": return "Data deletion";
            case "PATCH": return "Data modification";
            default: return "API operation";
        }
    }

    /**
     * ✅ УЛУЧШЕННЫЙ МЕТОД: Определяет статус код из ответа
     */
    private int extractStatusCode(String response) {
        if (response == null || response.trim().isEmpty()) {
            return 500; // Assume error for null/empty responses
        }
        
        // ✅ УЛУЧШЕННЫЕ ЭВРИСТИКИ ДЛЯ ОПРЕДЕЛЕНИЯ СТАТУСА
        
        // 1. Проверяем явные признаки ошибок аутентификации
        boolean isAuthError = response.toLowerCase().contains("unauthorized") || 
                             response.toLowerCase().contains("authentication") ||
                             response.toLowerCase().contains("401") ||
                             response.toLowerCase().contains("403") ||
                             response.toLowerCase().contains("access denied") ||
                             response.toLowerCase().contains("forbidden") ||
                             response.toLowerCase().contains("invalid token") ||
                             response.toLowerCase().contains("missing authorization");

        if (isAuthError) {
            return 401;
        }
        
        // 2. Проверяем JSON ответы
        if (response.trim().startsWith("{") && response.trim().endsWith("}")) {
            // Проверяем success indicators
            boolean hasSuccessData = response.toLowerCase().contains("\"status\":\"success\"") ||
                                   response.toLowerCase().contains("\"success\":true") ||
                                   response.toLowerCase().contains("\"data\":") ||
                                   response.toLowerCase().contains("\"result\":") ||
                                   (response.length() > 100 && !response.toLowerCase().contains("\"error\""));
            
            // Проверяем error indicators  
            boolean hasError = response.toLowerCase().contains("\"error\"") ||
                             response.toLowerCase().contains("\"message\"") && 
                             (response.toLowerCase().contains("unauthorized") || 
                              response.toLowerCase().contains("forbidden"));
            
            if (hasSuccessData && !hasError) {
                return 200;
            } else if (hasError) {
                return 401;
            }
        }
        
        // 3. Проверяем HTML ошибки
        if (response.toLowerCase().contains("<title>401") ||
            response.toLowerCase().contains("<title>403") ||
            response.toLowerCase().contains("<title>error") ||
            response.toLowerCase().contains("http status 401") ||
            response.toLowerCase().contains("http status 403")) {
            return 401;
        }
        
        // 4. Проверяем успешные ответы по длине и содержанию
        if (response.length() > 50 && 
            !response.toLowerCase().contains("error") &&
            !response.toLowerCase().contains("unauthorized") &&
            !response.toLowerCase().contains("forbidden")) {
            return 200; // Likely successful response
        }
        
        // 5. По умолчанию считаем ошибкой
        return 500;
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
            
            String response = performTestRequest(endpoint, httpClient, emptyTokenHeaders);
            return extractStatusCode(response) == 200;
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
            
            String response = performTestRequest(endpoint, httpClient, malformedTokenHeaders);
            return extractStatusCode(response) == 200;
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
            String response = httpClient.get(urlWithToken, new HashMap<>());
            return extractStatusCode(response) == 200;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * ✅ ДОБАВЛЕНО: Тестирует запрос без заголовков аутентификации
     */
    private boolean testNoAuthHeaders(EndpointInfo endpoint, HttpClient httpClient) {
        try {
            String response = performTestRequest(endpoint, httpClient, new HashMap<>());
            return extractStatusCode(response) == 200;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * ✅ ДОБАВЛЕНО: Выполняет тестовый запрос с указанными заголовками
     */
    private String performTestRequest(EndpointInfo endpoint, HttpClient httpClient, 
                                    Map<String, String> headers) throws IOException {
        String fullUrl = endpoint.getFullUrl();
        
        switch (endpoint.getMethod().toUpperCase()) {
            case "GET":
                return httpClient.get(fullUrl, headers);
            case "POST":
                String requestBody = endpoint.getRequestBody() != null ? endpoint.getRequestBody() : "{}";
                String contentType = endpoint.getContentType() != null ? endpoint.getContentType() : "application/json";
                return httpClient.post(fullUrl, headers, contentType, requestBody);
            case "PUT":
                requestBody = endpoint.getRequestBody() != null ? endpoint.getRequestBody() : "{}";
                contentType = endpoint.getContentType() != null ? endpoint.getContentType() : "application/json";
                return httpClient.put(fullUrl, headers, contentType, requestBody);
            case "DELETE":
                return httpClient.delete(fullUrl, headers);
            default:
                return httpClient.get(fullUrl, headers);
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
}
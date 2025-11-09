package org.owasp.astf.testcases.validation;

import org.apache.http.client.methods.HttpGet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.http.HttpResponse;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * Validator for authentication mechanisms in API endpoints.
 * <p>
 * This class provides utilities for checking authentication strength and 
 * identifying endpoints that may be accessible without proper authentication.
 * </p>
 */
public class AuthenticationValidator {
    private static final Logger logger = LogManager.getLogger(AuthenticationValidator.class);

    /**
     * Checks if an endpoint is accessible without authentication.
     * 
     * @param endpoint The endpoint to test
     * @param client The HTTP client to use
     * @param config The scan configuration containing auth headers
     * @return true if the endpoint is accessible without authentication (vulnerable)
     */
    public static boolean isUnauthenticatedAccessAllowed(EndpointInfo endpoint, HttpClient client, ScanConfig config) {
        try {
            // ✅ ИСПРАВЛЕНО: Создаем клиент без аутентификации
            HttpClient noAuthClient = createUnauthenticatedClient(config);
            
            // ✅ ИСПРАВЛЕНО: Используем executeRequest с двумя параметрами
            HttpResponse response = noAuthClient.executeRequest(
                new HttpGet(endpoint.getFullUrl()),
                Collections.emptyMap() // Пустые заголовки = без аутентификации
            );

            int statusCode = response.getStatusCode(); // ✅ ИСПРАВЛЕНО: используем getStatusCode()
            String responseBody = response.getResponseBody(); // ✅ ИСПРАВЛЕНО: используем getResponseBody()

            logger.debug("🔍 Auth validation: {} {} -> Status: {}, Body length: {}", 
                endpoint.getMethod(), endpoint.getPath(), statusCode, responseBody.length());

            // ✅ УЯЗВИМОСТЬ: 200 OK без аутентификации
            boolean isVulnerable = statusCode == 200;
            
            if (isVulnerable) {
                logger.warn("🚨 AUTH BYPASS DETECTED: {} {} returned 200 OK without authentication", 
                    endpoint.getMethod(), endpoint.getPath());
            }

            return isVulnerable;

        } catch (Exception e) {
            // ✅ ОШИБКА ПРИ ЗАПРОСЕ = АУТЕНТИФИКАЦИЯ РАБОТАЕТ (не уязвимость)
            logger.debug("✅ Auth validation: {} {} -> Error (protected): {}", 
                endpoint.getMethod(), endpoint.getPath(), e.getMessage());
            return false; // Аутентификация работает
        }
    }

    /**
     * Checks if authentication can be bypassed using common techniques.
     * 
     * @param endpoint The endpoint to test
     * @param client The HTTP client to use
     * @param config The scan configuration
     * @return true if authentication bypass is possible
     */
    public static boolean isAuthenticationBypassPossible(EndpointInfo endpoint, HttpClient client, ScanConfig config) {
        try {
            // ✅ ТЕСТИРУЕМ РАЗНЫЕ МЕТОДЫ ОБХОДА АУТЕНТИФИКАЦИИ
            boolean isBypassed = testNullToken(endpoint, client, config) ||
                               testEmptyToken(endpoint, client, config) ||
                               testMalformedToken(endpoint, client, config) ||
                               testExpiredToken(endpoint, client, config);

            if (isBypassed) {
                logger.warn("⚠️ AUTH BYPASS TECHNIQUE SUCCESSFUL on: {} {}", 
                    endpoint.getMethod(), endpoint.getPath());
            }

            return isBypassed;

        } catch (Exception e) {
            logger.debug("Auth bypass test failed for {}: {}", endpoint.getPath(), e.getMessage());
            return false; // Ошибка = защита работает
        }
    }

    /**
     * ✅ Тестирует обход через пустой токен
     */
    private static boolean testNullToken(EndpointInfo endpoint, HttpClient client, ScanConfig config) {
        try {
            Map<String, String> nullTokenHeaders = new HashMap<>();
            nullTokenHeaders.put("Authorization", ""); // Пустой токен
            nullTokenHeaders.put("X-Consent-Id", "");
            nullTokenHeaders.put("X-Requesting-Bank", config.getClientId());

            HttpResponse response = client.executeRequest(new HttpGet(endpoint.getFullUrl()), nullTokenHeaders);
            return response.getStatusCode() == 200;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * ✅ Тестирует обход через фейковый токен
     */
    private static boolean testMalformedToken(EndpointInfo endpoint, HttpClient client, ScanConfig config) {
        try {
            Map<String, String> fakeTokenHeaders = new HashMap<>();
            fakeTokenHeaders.put("Authorization", "Bearer invalid_token_12345_fake");
            fakeTokenHeaders.put("X-Consent-Id", "consent-invalid-123");
            fakeTokenHeaders.put("X-Requesting-Bank", config.getClientId());

            HttpResponse response = client.executeRequest(new HttpGet(endpoint.getFullUrl()), fakeTokenHeaders);
            return response.getStatusCode() == 200;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * ✅ Тестирует обход через истёкший токен
     */
    private static boolean testExpiredToken(EndpointInfo endpoint, HttpClient client, ScanConfig config) {
        try {
            Map<String, String> expiredTokenHeaders = new HashMap<>();
            expiredTokenHeaders.put("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjEwMDAwMDB9.InvalidSignature");
            expiredTokenHeaders.put("X-Consent-Id", "consent-expired-123");
            expiredTokenHeaders.put("X-Requesting-Bank", config.getClientId());

            HttpResponse response = client.executeRequest(new HttpGet(endpoint.getFullUrl()), expiredTokenHeaders);
            return response.getStatusCode() == 200;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * ✅ Тестирует обход через пустые заголовки аутентификации
     */
    private static boolean testEmptyToken(EndpointInfo endpoint, HttpClient client, ScanConfig config) {
        try {
            // Удаляем аутентификационные заголовки
            Map<String, String> noAuthHeaders = new HashMap<>();
            noAuthHeaders.put("X-Requesting-Bank", config.getClientId()); // Только банк, без токена

            HttpResponse response = client.executeRequest(new HttpGet(endpoint.getFullUrl()), noAuthHeaders);
            return response.getStatusCode() == 200;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * ✅ Создает HttpClient без аутентификации для тестирования
     */
    private static HttpClient createUnauthenticatedClient(ScanConfig config) {
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
     * ✅ Проверяет, требует ли эндпоинт аутентификации
     */
    public static boolean requiresAuthentication(EndpointInfo endpoint) {
        // ✅ Проверяем по пути и методу
        String path = endpoint.getPath().toLowerCase();
        String method = endpoint.getMethod().toUpperCase();

        // ✅ Эти эндпоинты обычно требуют аутентификации
        if (path.contains("account") || path.contains("user") || path.contains("balance") || 
            path.contains("transaction") || path.contains("payment")) {
            return true;
        }

        // ✅ Эти методы обычно требуют аутентификации
        return "POST".equals(method) || "PUT".equals(method) || "DELETE".equals(method) || "PATCH".equals(method);
    }

    /**
     * ✅ Проверяет качество токена (для анализа безопасности)
     */
    public static boolean isTokenSecure(String token) {
        if (token == null || token.length() < 32) {
            return false; // Слишком короткий
        }

        // ✅ Проверяем, похож ли токен на JWT
        if (token.contains(".")) {
            String[] parts = token.split("\\.");
            return parts.length == 3 && parts[0].length() > 10 && parts[1].length() > 10;
        }

        // ✅ Для других токенов проверяем сложность
        return token.matches("^[a-zA-Z0-9_-]+$") && !token.toLowerCase().contains("test");
    }
}
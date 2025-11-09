package org.owasp.astf.core;

import java.util.Objects;

/**
 * Represents information about an API endpoint to be tested.
 * <p>
 * This class encapsulates all relevant information about an API endpoint
 * including path, method, content type, request body, and authentication requirements.
 * </p>
 */
public class EndpointInfo {
    private final String baseUrl;       // ✅ Базовый URL (например, https://vbank.open.bankingapi.ru)
    private final String path;          // ✅ Путь (например, /accounts/{id}/balances)
    private final String method;        // ✅ HTTP метод (GET, POST, PUT, DELETE, etc.)
    private final String contentType;   // ✅ Content-Type заголовок (application/json, etc.)
    private String requestBody;         // ✅ Тело запроса (для POST/PUT)
    private final boolean requiresAuthentication; // ✅ Требуется ли аутентификация

    /**
     * Creates a new endpoint info with minimal parameters.
     * 
     * @param baseUrl The base URL (e.g., https://vbank.open.bankingapi.ru)
     * @param path The endpoint path (e.g., /accounts/{id})
     * @param method The HTTP method (GET, POST, etc.)
     */
    public EndpointInfo(String baseUrl, String path, String method) {
        this.baseUrl = baseUrl;
        this.path = path;
        this.method = method != null ? method.toUpperCase() : "GET";
        this.contentType = "application/json";
        this.requestBody = null;
        this.requiresAuthentication = true;
    }

    /**
     * Creates a new endpoint info with all parameters.
     * 
     * @param baseUrl The base URL (e.g., https://vbank.open.bankingapi.ru)
     * @param path The endpoint path (e.g., /accounts/{id})
     * @param method The HTTP method (GET, POST, etc.)
     * @param contentType The content type (application/json, etc.)
     * @param requestBody The request body (for POST/PUT)
     * @param requiresAuthentication Whether authentication is required
     */
    public EndpointInfo(String baseUrl, String path, String method, String contentType, String requestBody, boolean requiresAuthentication) {
        this.baseUrl = baseUrl;
        this.path = path;
        this.method = method != null ? method.toUpperCase() : "GET";
        this.contentType = contentType != null ? contentType : "application/json";
        this.requestBody = requestBody;
        this.requiresAuthentication = requiresAuthentication;
    }

    // ✅ Конструкторы для обратной совместимости (удобно для старых тестов)
    public EndpointInfo(String path, String method) {
        this("http://localhost", path, method);
    }

    public EndpointInfo(String path, String method, String contentType, String requestBody, boolean requiresAuthentication) {
        this("http://localhost", path, method, contentType, requestBody, requiresAuthentication);
    }

    /**
     * Gets the full URL by combining baseUrl and path.
     * 
     * @return The full URL string (e.g., https://vbank.open.bankingapi.ru/accounts/{id})
     */
    public String getFullUrl() {
        if (baseUrl == null || baseUrl.isEmpty()) {
            return path;
        }
        
        // ✅ Убираем дублирование слешей
        String base = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        String p = path.startsWith("/") ? path : "/" + path;
        return base + p;
    }

    // Getters (immutable)
    public String getBaseUrl() { return baseUrl; }
    public String getPath() { return path; }
    public String getMethod() { return method; }
    public String getContentType() { return contentType; }
    public String getRequestBody() { return requestBody; }
    public boolean isRequiresAuthentication() { return requiresAuthentication; }

    @Override
    public String toString() {
        return method + " " + getFullUrl();
    }

    // ✅ Добавлено: equals() и hashCode() для использования в коллекциях
    @Override
    public boolean equals(Object obj) {
        if (this == obj) return true;
        if (obj == null || getClass() != obj.getClass()) return false;
        EndpointInfo that = (EndpointInfo) obj;
        return requiresAuthentication == that.requiresAuthentication &&
               Objects.equals(baseUrl, that.baseUrl) &&
               Objects.equals(path, that.path) &&
               Objects.equals(method, that.method) &&
               Objects.equals(contentType, that.contentType);
    }

    @Override
    public int hashCode() {
        return Objects.hash(baseUrl, path, method, contentType, requiresAuthentication);
    }
}
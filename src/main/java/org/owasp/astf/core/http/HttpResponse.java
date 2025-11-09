package org.owasp.astf.core.http;

import java.util.List;
import java.util.Map;

/**
 * Represents an HTTP response with status code, headers, and body.
 * <p>
 * This class provides a unified interface for HTTP response data that works with both
 * Apache HttpClient and OkHttp3, abstracting the underlying implementation differences.
 * </p>
 */
public class HttpResponse {
    private final int statusCode;
    private final Map<String, List<String>> headers; // ✅ ИСПРАВЛЕНО: List<String> для значений заголовков
    private final String body; // ✅ ИСПРАВЛЕНО: responseBody -> body

    public HttpResponse(int statusCode, Map<String, List<String>> headers, String body) {
        this.statusCode = statusCode;
        this.headers = headers;
        this.body = body;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public Map<String, List<String>> getHeaders() {
        return headers;
    }

    /**
     * Gets the response body as a string.
     *
     * @return The response body
     */
    public String getBody() { // ✅ ИСПРАВЛЕНО: getResponseBody() -> getBody()
        return body;
    }

    /**
     * Gets the value of a specific header.
     * Since headers can have multiple values, this returns the first one.
     *
     * @param headerName The name of the header
     * @return The header value, or null if not found
     */
    public String getHeader(String headerName) {
        List<String> values = headers.get(headerName);
        if (values != null && !values.isEmpty()) {
            return values.get(0); // Return first value
        }
        return null;
    }

    /**
     * Gets all values for a specific header.
     *
     * @param headerName The name of the header
     * @return List of header values, or empty list if not found
     */
    public List<String> getHeaderValues(String headerName) {
        List<String> values = headers.get(headerName);
        return values != null ? values : java.util.Collections.emptyList();
    }

    /**
     * Checks if the response was successful (2xx status code).
     *
     * @return true if status code is 200-299
     */
    public boolean isSuccessful() {
        return statusCode >= 200 && statusCode < 300;
    }

    /**
     * Checks if the response indicates a redirect (3xx status code).
     *
     * @return true if status code is 300-399
     */
    public boolean isRedirect() {
        return statusCode >= 300 && statusCode < 400;
    }

    /**
     * Checks if the response indicates a client error (4xx status code).
     *
     * @return true if status code is 400-499
     */
    public boolean isClientError() {
        return statusCode >= 400 && statusCode < 500;
    }

    /**
     * Checks if the response indicates a server error (5xx status code).
     *
     * @return true if status code is 500-599
     */
    public boolean isServerError() {
        return statusCode >= 500 && statusCode < 600;
    }

    /**
     * Returns a string representation of the response status.
     *
     * @return Status string in format "StatusCode (Description)"
     */
    public String getStatusText() {
        return switch (statusCode) {
            case 200 -> "OK";
            case 201 -> "Created";
            case 204 -> "No Content";
            case 400 -> "Bad Request";
            case 401 -> "Unauthorized";
            case 403 -> "Forbidden";
            case 404 -> "Not Found";
            case 429 -> "Too Many Requests";
            case 500 -> "Internal Server Error";
            case 502 -> "Bad Gateway";
            case 503 -> "Service Unavailable";
            default -> "Unknown Status";
        };
    }
}
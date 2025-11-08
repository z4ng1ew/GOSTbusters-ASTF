package org.owasp.astf.core.http;

import java.util.Map;

/**
 * Represents an HTTP response with status code, headers, and body.
 */
public class HttpResponse {
    private final int statusCode;
    private final Map<String, String> headers;
    private final String responseBody;

    public HttpResponse(int statusCode, Map<String, String> headers, String responseBody) {
        this.statusCode = statusCode;
        this.headers = headers;
        this.responseBody = responseBody;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public Map<String, String> getHeaders() {
        return headers;
    }

    public String getResponseBody() {
        return responseBody;
    }

    public String getHeader(String headerName) {
        return headers.get(headerName);
    }
}
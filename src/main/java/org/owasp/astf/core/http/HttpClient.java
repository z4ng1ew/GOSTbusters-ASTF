package org.owasp.astf.core.http;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.config.ScanConfig;

import okhttp3.Authenticator;
import okhttp3.Call;
import okhttp3.Callback;
import okhttp3.ConnectionPool;
import okhttp3.Cookie;
import okhttp3.CookieJar;
import okhttp3.Credentials;
import okhttp3.HttpUrl;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;

/**
 * HTTP client wrapper for making API requests.
 * <p>
 * This class provides a robust HTTP client implementation that supports:
 * <ul>
 * <li>All common HTTP methods (GET, POST, PUT, DELETE, OPTIONS, PATCH, HEAD)</li>
 * <li>Various authentication methods</li>
 * <li>Cookie handling</li>
 * <li>Proxy configuration</li>
 * <li>Connection pooling and timeout management</li>
 * <li>Response processing with headers</li>
 * </ul>
 * </p>
 */
public class HttpClient {
    private static final Logger logger = LogManager.getLogger(HttpClient.class);

    private final OkHttpClient client;
    private final ScanConfig config;
    private final Map<String, String> defaultHeaders;
    private final Map<String, List<Cookie>> cookieStore = new HashMap<>();

    // ✅ ДОБАВЛЕНО: Поле для хранения последнего статус-кода
    private int lastStatusCode = 0;

    /**
     * Creates a new HTTP client with the specified configuration.
     *
     * @param config The scan configuration
     */
    public HttpClient(ScanConfig config) {
        this.config = config;
        this.defaultHeaders = new HashMap<>(config.getHeaders());

        OkHttpClient.Builder builder = new OkHttpClient.Builder()
                .connectTimeout(Duration.ofSeconds(30))
                .readTimeout(Duration.ofSeconds(30))
                .writeTimeout(Duration.ofSeconds(30))
                .connectionPool(new ConnectionPool(20, 5, TimeUnit.MINUTES))
                .cookieJar(new InMemoryCookieJar())
                .followRedirects(true)
                .followSslRedirects(true);

        // Configure proxy if specified
        if (config.getProxyHost() != null && !config.getProxyHost().isEmpty()) {
            configureProxy(builder);
        }

        // Configure basic authentication if specified
        if (config.getBasicAuthUsername() != null && !config.getBasicAuthUsername().isEmpty()) {
            configureBasicAuth(builder);
        }

        this.client = builder.build();
    }

    /**
     * ✅ ДОБАВЛЕНО: Метод получения последнего статус-кода
     * * @return Последний HTTP статус-код, полученный в результате выполнения запроса
     */
    public int getLastStatusCode() {
        return lastStatusCode;
    }

    /**
     * Makes a GET request to the specified URL.
     *
     * @param url The target URL
     * @param headers Additional headers to include
     * @return The full response object (HttpResponse)
     * @throws IOException If the request fails
     */
    public HttpResponse get(String url, Map<String, String> headers) throws IOException {
        Request request = createRequest(url, "GET", headers, null, null);
        // ✅ ПРАВКА 2: Явное присвоение и возврат
        HttpResponse response = executeRequest(request); 
        return response;
    }

    /**
     * Makes a POST request to the specified URL.
     *
     * @param url The target URL
     * @param headers Additional headers to include
     * @param contentType The content type of the request
     * @param body The request body
     * @return The full response object (HttpResponse)
     * @throws IOException If the request fails
     */
    public HttpResponse post(String url, Map<String, String> headers, String contentType, String body) throws IOException {
        MediaType mediaType = MediaType.parse(contentType);
        RequestBody requestBody = RequestBody.create(body, mediaType);
        Request request = createRequest(url, "POST", headers, mediaType, requestBody);
        return executeRequest(request);
    }

    /**
     * Makes a PUT request to the specified URL.
     *
     * @param url The target URL
     * @param headers Additional headers to include
     * @param contentType The content type of the request
     * @param body The request body
     * @return The full response object (HttpResponse)
     * @throws IOException If the request fails
     */
    public HttpResponse put(String url, Map<String, String> headers, String contentType, String body) throws IOException {
        MediaType mediaType = MediaType.parse(contentType);
        RequestBody requestBody = RequestBody.create(body, mediaType);
        Request request = createRequest(url, "PUT", headers, mediaType, requestBody);
        return executeRequest(request);
    }

    /**
     * Makes a DELETE request to the specified URL.
     *
     * @param url The target URL
     * @param headers Additional headers to include
     * @return The full response object (HttpResponse)
     * @throws IOException If the request fails
     */
    public HttpResponse delete(String url, Map<String, String> headers) throws IOException {
        Request request = createRequest(url, "DELETE", headers, null, null);
        return executeRequest(request);
    }

    /**
     * Makes an OPTIONS request to the specified URL.
     *
     * @param url The target URL
     * @param headers Additional headers to include
     * @return The full response object (HttpResponse)
     * @throws IOException If the request fails
     */
    public HttpResponse options(String url, Map<String, String> headers) throws IOException {
        Request request = createRequest(url, "OPTIONS", headers, null, null);
        return executeRequest(request);
    }

    /**
     * Makes a PATCH request to the specified URL.
     *
     * @param url The target URL
     * @param headers Additional headers to include
     * @param contentType The content type of the request
     * @param body The request body
     * @return The full response object (HttpResponse)
     * @throws IOException If the request fails
     */
    public HttpResponse patch(String url, Map<String, String> headers, String contentType, String body) throws IOException {
        MediaType mediaType = MediaType.parse(contentType);
        RequestBody requestBody = RequestBody.create(body, mediaType);
        Request request = createRequest(url, "PATCH", headers, mediaType, requestBody);
        return executeRequest(request);
    }

    /**
     * Makes a HEAD request to the specified URL.
     *
     * @param url The target URL
     * @param headers Additional headers to include
     * @return The full response object (HttpResponse)
     * @throws IOException If the request fails
     */
    public HttpResponse head(String url, Map<String, String> headers) throws IOException {
        Request request = createRequest(url, "HEAD", headers, null, null);
        return executeRequest(request);
    }

    /**
     * ✅ ОБНОВЛЕНО: Универсальный метод для выполнения HTTP запросов
     */
    public HttpResponse request(String method, String url, Map<String, String> headers,
                               String contentType, String body) throws IOException {
        MediaType mediaType = contentType != null ? MediaType.parse(contentType) : null;
        RequestBody requestBody = null;

        if (body != null && mediaType != null) {
            requestBody = RequestBody.create(body, mediaType);
        }

        Request request = createRequest(url, method, headers, mediaType, requestBody);
        return executeRequest(request);
    }

    /*
     * ❌ ПРАВКА 1: МЕТОД getStatusCode УДАЛЕН.
     * Его функциональность заменяется вызовом getFullResponse(..).getStatusCode().
     */

    /**
     * Метод для получения полного ответа (код + заголовки + тело)
     */
    public HttpResponse getFullResponse(String url, Map<String, String> headers) throws IOException {
        Request request = createRequest(url, "GET", headers, null, null);
        return executeRequest(request);
    }

    /**
     * ✅ НОВЫЙ МЕТОД: Преобразует okhttp3.Response в наш внутренний HttpResponse
     */
    public HttpResponse convertResponse(okhttp3.Response okHttpResponse) throws IOException {
        int statusCode = okHttpResponse.code();
        String body = okHttpResponse.body() != null ? okHttpResponse.body().string() : "";

        // Извлекаем заголовки
        Map<String, List<String>> headers = new HashMap<>();
        for (String name : okHttpResponse.headers().names()) {
            headers.put(name, okHttpResponse.headers(name));
        }

        // ✅ ОБНОВЛЕНО: Сохраняем статус-код
        this.lastStatusCode = statusCode;

        return new HttpResponse(statusCode, headers, body);
    }

    /**
     * Makes an asynchronous request to the specified URL.
     *
     * @param url The target URL
     * @param method The HTTP method
     * @param headers Additional headers to include
     * @param contentType The content type of the request (null for GET, HEAD, DELETE)
     * @param body The request body (null for GET, HEAD, DELETE)
     * @param callback The callback to handle the response
     */
    public void asyncRequest(String url, String method, Map<String, String> headers,
                             String contentType, String body, HttpResponseCallback callback) {
        try {
            MediaType mediaType = contentType != null ? MediaType.parse(contentType) : null;
            RequestBody requestBody = null;

            if (body != null && mediaType != null) {
                requestBody = RequestBody.create(body, mediaType);
            }

            Request request = createRequest(url, method, headers, mediaType, requestBody);

            client.newCall(request).enqueue(new Callback() {
                @Override
                public void onFailure(Call call, IOException e) {
                    callback.onFailure(e);
                }

                @Override
                public void onResponse(Call call, Response response) throws IOException {
                    try (ResponseBody responseBody = response.body()) {
                        // ✅ ОБНОВЛЕНО: Сохраняем статус-код для асинхронных запросов
                        lastStatusCode = response.code();
                        String body = responseBody != null ? responseBody.string() : "";
                        Map<String, List<String>> headers = extractHeaders(response);
                        int statusCode = response.code();

                        callback.onSuccess(statusCode, headers, body);
                    }
                }
            });
        } catch (Exception e) {
            callback.onFailure(e);
        }
    }

    /**
     * Creates an HTTP request with the specified parameters.
     *
     * @param url The target URL
     * @param method The HTTP method
     * @param additionalHeaders Additional headers to include
     * @param mediaType The media type of the request (null for GET, HEAD, DELETE)
     * @param body The request body (null for GET, HEAD, DELETE)
     * @return The HTTP request
     */
    private Request createRequest(String url, String method, Map<String, String> additionalHeaders,
                                  MediaType mediaType, RequestBody body) {
        Request.Builder requestBuilder = new Request.Builder()
                .url(url);

        // Set the appropriate method and body
        switch (method.toUpperCase()) {
            case "GET" -> requestBuilder.get();
            case "HEAD" -> requestBuilder.head();
            case "DELETE" -> requestBuilder.delete();
            case "OPTIONS" -> requestBuilder.method("OPTIONS", null); // ✅ ДОБАВЛЕНО: OPTIONS method
            case "POST" -> requestBuilder.post(body);
            case "PUT" -> requestBuilder.put(body);
            case "PATCH" -> requestBuilder.patch(body);
            default -> {
                if (body != null) {
                    requestBuilder.method(method, body);
                } else {
                    requestBuilder.method(method, null);
                }
            }
        }

        // Add default headers from config
        for (Map.Entry<String, String> entry : defaultHeaders.entrySet()) {
            requestBuilder.header(entry.getKey(), entry.getValue());
        }

        // Add request-specific headers
        if (additionalHeaders != null) {
            for (Map.Entry<String, String> entry : additionalHeaders.entrySet()) {
                requestBuilder.header(entry.getKey(), entry.getValue());
            }
        }

        return requestBuilder.build();
    }

    /**
     * ✅ ОБНОВЛЕНО: Executes a request and returns the full HttpResponse object.
     *
     * @param request The HTTP request to execute
     * @return The full response object (HttpResponse)
     * @throws IOException If the request fails
     */
    private HttpResponse executeRequest(Request request) throws IOException {
        try (okhttp3.Response response = client.newCall(request).execute()) {
            // ✅ СОХРАНЯЕМ статус-код
            this.lastStatusCode = response.code();

            String body = response.body() != null ? response.body().string() : "";

            // Извлекаем заголовки
            Map<String, List<String>> headers = extractHeaders(response);

            return new HttpResponse(response.code(), headers, body);
        }
    }

    /**
     * Extracts headers from a response.
     *
     * @param response The HTTP response
     * @return A map of header names to values
     */
    private Map<String, List<String>> extractHeaders(Response response) {
        Map<String, List<String>> headers = new HashMap<>();

        for (String name : response.headers().names()) {
            headers.put(name, response.headers(name));
        }

        return headers;
    }

    /**
     * Configures proxy settings for the HTTP client.
     *
     * @param builder The OkHttpClient builder
     */
    private void configureProxy(OkHttpClient.Builder builder) {
        Proxy proxy = new Proxy(
                Proxy.Type.HTTP,
                new InetSocketAddress(config.getProxyHost(), config.getProxyPort())
        );

        builder.proxy(proxy);

        // Configure proxy authentication if needed
        if (config.getProxyUsername() != null && !config.getProxyUsername().isEmpty()) {
            Authenticator proxyAuthenticator = (route, response) -> {
                String credential = Credentials.basic(config.getProxyUsername(), config.getProxyPassword());
                return response.request().newBuilder()
                        .header("Proxy-Authorization", credential)
                        .build();
            };

            builder.proxyAuthenticator(proxyAuthenticator);
        }
    }

    /**
     * Configures basic authentication for the HTTP client.
     *
     * @param builder The OkHttpClient builder
     */
    private void configureBasicAuth(OkHttpClient.Builder builder) {
        Authenticator authenticator = (route, response) -> {
            String credential = Credentials.basic(config.getBasicAuthUsername(), config.getBasicAuthPassword());
            return response.request().newBuilder()
                    .header("Authorization", credential)
                    .build();
        };

        builder.authenticator(authenticator);
    }

    /**
     * Класс для представления полного HTTP ответа
     */
    public static class HttpResponse {
        private final int statusCode;
        private final Map<String, List<String>> headers;
        private final String body;

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

        public String getBody() {
            return body;
        }

        public boolean isSuccessful() {
            return statusCode >= 200 && statusCode < 300;
        }

        public boolean isRedirect() {
            return statusCode >= 300 && statusCode < 400;
        }

        public boolean isClientError() {
            return statusCode >= 400 && statusCode < 500;
        }

        public boolean isServerError() {
            return statusCode >= 500 && statusCode < 600;
        }
    }

    /**
     * In-memory cookie jar implementation for cookie management.
     */
    private class InMemoryCookieJar implements CookieJar {
        @Override
        public void saveFromResponse(HttpUrl url, List<Cookie> cookies) {
            String domain = url.host();

            if (!cookieStore.containsKey(domain)) {
                cookieStore.put(domain, new ArrayList<>());
            }

            // Replace existing cookies with the same name
            List<Cookie> domainCookies = cookieStore.get(domain);
            for (Cookie cookie : cookies) {
                // Remove existing cookie with same name if present
                domainCookies.removeIf(existingCookie -> existingCookie.name().equals(cookie.name()));

                // Add the new cookie
                domainCookies.add(cookie);
            }

            logger.debug("Cookies for {}: {}", domain, domainCookies.size());
        }

        @Override
        public List<Cookie> loadForRequest(HttpUrl url) {
            String domain = url.host();
            List<Cookie> validCookies = new ArrayList<>();

            if (cookieStore.containsKey(domain)) {
                List<Cookie> domainCookies = cookieStore.get(domain);
                for (Cookie cookie : domainCookies) {
                    if (cookie.matches(url)) {
                        validCookies.add(cookie);
                    }
                }
            }

            return validCookies;
        }
    }

    /**
     * Callback interface for asynchronous HTTP requests.
     */
    public interface HttpResponseCallback {
        /**
         * Called when the request is successful.
         *
         * @param statusCode The HTTP status code
         * @param headers The response headers
         * @param body The response body
         */
        void onSuccess(int statusCode, Map<String, List<String>> headers, String body);

        /**
         * Called when the request fails.
         *
         * @param e The exception that caused the failure
         */
        void onFailure(IOException e);

        void onFailure(Exception e);
    }
}
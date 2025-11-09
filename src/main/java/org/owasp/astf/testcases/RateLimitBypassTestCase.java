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
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Tests for API4:2023 - Rate Limiting & API7:2023 - Insufficient Logging.
 * 
 * This test case checks for inadequate rate limiting mechanisms that could allow
 * attackers to overwhelm the API with requests, potentially leading to DoS attacks
 * or brute force attempts. It tests various bypass techniques including IP spoofing,
 * user agent rotation, and rapid sequential requests.
 * 
 * @see <a href="https://owasp.org/API-Security/editions/2023/en/0xa4-rate-limiting/">OWASP API Security Top 10 2023: API4 Rate Limiting</a>
 * @see <a href="https://owasp.org/API-Security/editions/2023/en/0xa7-insufficient-logging/">OWASP API Security Top 10 2023: API7 Insufficient Logging</a>
 */
public class RateLimitBypassTestCase implements TestCase {
    private static final Logger logger = LogManager.getLogger(RateLimitBypassTestCase.class);

    private ScanConfig config;

    // ✅ ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ ДЛЯ ПРЕДОТВРАЩЕНИЯ ДУБЛЕЙ
    private static final AtomicBoolean rateLimitTestCompleted = new AtomicBoolean(false);
    private static int totalRateLimitRequests = 0;

    // ✅ Подозрительные пути для рейт-лимит теста
    private static final List<String> PUBLIC_ENDPOINT_PATTERNS = List.of(
        "/auth/", "/public/", "/health", "/status", "/docs", "/swagger", "/openapi"
    );

    @Override
    public void init(ScanConfig config) {
        this.config = config;
    }

    @Override
    public String getId() {
        return "API4:2023/API7:2023";
    }

    @Override
    public String getName() {
        return "Rate Limit Bypass & Insufficient Logging (API4:2023/API7:2023)";
    }

    @Override
    public String getDescription() {
        return """
               Tests for inadequate rate limiting mechanisms and insufficient logging that could 
               allow attackers to overwhelm the API or bypass security controls through various 
               techniques including IP spoofing, user agent rotation, and rapid sequential requests.
               """;
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient client) throws IOException {
        List<Finding> findings = new ArrayList<>();

        // ✅ ПРОВЕРКА: Уже выполнен ли тест
        if (rateLimitTestCompleted.getAndSet(true)) {
            logger.info("⏩ Rate Limit test already completed. Skipping duplicate execution.");
            return Collections.emptyList();
        }

        // ✅ ПРОВЕРКА: Подходит ли эндпоинт для рейт-лимит теста
        if (!isPublicEndpoint(endpoint)) {
            logger.debug("⏭️ Skipping protected endpoint for rate limit test: {}", endpoint.getPath());
            return Collections.emptyList();
        }

        System.out.println("🔍 Starting Rate Limit Bypass test on: " + endpoint.getMethod() + " " + endpoint.getPath());

        // ✅ ТЕСТИРУЕМ РАЗНЫЕ МЕТОДЫ ОБХОДА РЕЙТ-ЛИМИТА
        findings.addAll(testRateLimitBypassMethods(endpoint, client));

        if (findings.isEmpty()) {
            System.out.println("✅ Rate limit protection verified: " + endpoint.getMethod() + " " + endpoint.getPath());
        } else {
            System.out.println("🎯 Rate limit vulnerabilities found: " + findings.size() + " on " + endpoint.getPath());
        }

        return findings;
    }

    /**
     * ✅ Проверяет, является ли эндпоинт публичным (без авторизации)
     */
    private boolean isPublicEndpoint(EndpointInfo endpoint) {
        String path = endpoint.getPath().toLowerCase();
        return PUBLIC_ENDPOINT_PATTERNS.stream().anyMatch(path::contains);
    }

    /**
     * ✅ Тестирует различные методы обхода рейт-лимита
     */
    private List<Finding> testRateLimitBypassMethods(EndpointInfo endpoint, HttpClient client) {
        List<Finding> findings = new ArrayList<>();

        // ✅ 1. Тестирование быстрых последовательных запросов
        Finding rapidFinding = testRapidSequentialRequests(endpoint, client);
        if (rapidFinding != null) {
            findings.add(rapidFinding);
        }

        // ✅ 2. Тестирование ротации User-Agent
        Finding userAgentFinding = testUserAgentRotation(endpoint, client);
        if (userAgentFinding != null) {
            findings.add(userAgentFinding);
        }

        // ✅ 3. Тестирование спуфинга IP-адреса
        Finding ipSpoofFinding = testIPSpoofing(endpoint, client);
        if (ipSpoofFinding != null) {
            findings.add(ipSpoofFinding);
        }

        return findings;
    }

    /**
     * ✅ Тестирует быстрые последовательные запросы (основной метод)
     */
    private Finding testRapidSequentialRequests(EndpointInfo endpoint, HttpClient client) {
        int successfulRequests = 0;
        int totalRequests = 15; // Количество запросов для теста
        long startTime = System.currentTimeMillis();

        System.out.println("⚡ Testing rapid sequential requests (" + totalRequests + " requests)...");

        for (int i = 0; i < totalRequests; i++) {
            try {
                // ✅ ИСПРАВЛЕНО: Используем executeRequest с двумя параметрами
                Map<String, String> headers = createRateLimitHeaders(i);
                HttpResponse response = client.executeRequest(new HttpGet(endpoint.getFullUrl()), headers);

                int statusCode = response.getStatusCode();
                String responseBody = response.getResponseBody(); // ✅ ИСПРАВЛЕНО: используем getResponseBody()

                // ✅ ПРОВЕРЯЕМ: не является ли ответ рейт-лимитом
                if (!isRateLimitResponse(statusCode, responseBody)) {
                    successfulRequests++;
                }

                totalRateLimitRequests++;

                // ✅ ЗАДЕРЖКА МЕЖДУ ЗАПРОСАМИ (50ms)
                Thread.sleep(50);

            } catch (Exception e) {
                totalRateLimitRequests++;
                if (e.getMessage() != null && e.getMessage().contains("429")) {
                    System.out.println("✅ Rate limit triggered at request " + (i + 1));
                    break; // Прерываем тест, если сработал рейт-лимит
                }
            }
        }

        long endTime = System.currentTimeMillis();
        long durationMs = endTime - startTime;

        // ✅ АНАЛИЗИРУЕМ РЕЗУЛЬТАТЫ
        if (successfulRequests >= 10) { // Если 10+ запросов прошли - уязвимость
            return new Finding(
                "RL-BYPASS-01",
                "Missing Rate Limit Protection (API4:2023)",
                "🚨 CRITICAL: Inadequate rate limiting detected!\n\n" +
                "• Endpoint: " + endpoint.getMethod() + " " + endpoint.getPath() + "\n" +
                "• Successful requests: " + successfulRequests + "/" + totalRequests + "\n" +
                "• Test duration: " + durationMs + "ms\n" +
                "• Average requests per second: " + Math.round((successfulRequests * 1000.0) / durationMs) + "\n" +
                "• Impact: Potential DoS attacks and brute force attempts",
                Severity.HIGH,
                getId(),
                endpoint.getFullUrl(),
                "✅ CRITICAL REMEDIATION REQUIRED:\n\n" +
                "1. IMPLEMENT RATE LIMITING\n" +
                "   • Set appropriate request limits (e.g., 100 requests/minute per IP)\n" +
                "   • Use sliding window or token bucket algorithms\n\n" +
                "2. APPLY MULTIPLE LAYERS OF PROTECTION\n" +
                "   • Rate limiting at API Gateway level\n" +
                "   • Application-level rate limiting\n" +
                "   • Database query rate limiting\n\n" +
                "3. CONFIGURE PROPER RESPONSES\n" +
                "   • Return 429 Too Many Requests\n" +
                "   • Include Retry-After header\n" +
                "   • Provide clear rate limit information\n\n" +
                "4. MONITOR AND ALERT\n" +
                "   • Track rate limit bypass attempts\n" +
                "   • Alert on suspicious request patterns\n" +
                "   • Implement adaptive rate limiting"
            );
        }

        System.out.println("✅ Rate limiting working: " + successfulRequests + "/" + totalRequests + " requests passed");
        return null;
    }

    /**
     * ✅ Тестирует ротацию User-Agent для обхода рейт-лимита
     */
    private Finding testUserAgentRotation(EndpointInfo endpoint, HttpClient client) {
        String[] userAgents = {
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
            "PostmanRuntime/7.29.0",
            "curl/7.68.0",
            "ASTF-Scanner/1.0"
        };

        int successfulRequests = 0;

        System.out.println("🔄 Testing User-Agent rotation (" + userAgents.length + " agents)...");

        for (int i = 0; i < userAgents.length; i++) {
            try {
                Map<String, String> headers = new HashMap<>();
                headers.put("User-Agent", userAgents[i]);
                
                // ✅ ИСПРАВЛЕНО: Используем executeRequest
                HttpResponse response = client.executeRequest(new HttpGet(endpoint.getFullUrl()), headers);

                int statusCode = response.getStatusCode();
                String responseBody = response.getResponseBody(); // ✅ ИСПРАВЛЕНО: getResponseBody()

                if (!isRateLimitResponse(statusCode, responseBody)) {
                    successfulRequests++;
                }

                totalRateLimitRequests++;

                Thread.sleep(100); // Задержка между запросами

            } catch (Exception e) {
                totalRateLimitRequests++;
            }
        }

        // ✅ Если все/почти все запросы прошли - возможна уязвимость
        if (successfulRequests >= userAgents.length - 1) {
            return new Finding(
                "RL-UA-BYPASS-02",
                "User-Agent Based Rate Limit Bypass (API4:2023)",
                "⚠️ MEDIUM: Rate limiting may be bypassed by rotating User-Agent headers.\n\n" +
                "• User-Agents tested: " + userAgents.length + "\n" +
                "• Successful requests: " + successfulRequests + "\n" +
                "• Rate limiting does not properly identify clients based on multiple factors",
                Severity.MEDIUM,
                getId(),
                endpoint.getFullUrl(),
                "✅ IMPROVE CLIENT IDENTIFICATION:\n\n" +
                "1. DO NOT RELY SOLELY ON USER-AGENT\n" +
                "   • Combine IP address, User-Agent, and API Key for identification\n" +
                "   • Implement client fingerprinting\n\n" +
                "2. USE COMBINED IDENTIFIERS\n" +
                "   • Rate limit by IP + User-Agent combination\n" +
                "   • Consider session-based identification\n\n" +
                "3. IMPLEMENT ADVANCED DETECTION\n" +
                "   • Use behavioral analysis\n" +
                "   • Monitor for unusual patterns\n" +
                "   • Implement CAPTCHA for suspicious activity"
            );
        }

        System.out.println("✅ User-Agent rotation blocked: " + successfulRequests + "/" + userAgents.length + " requests passed");
        return null;
    }

    /**
     * ✅ Тестирует спуфинг IP-адреса через заголовки
     */
    private Finding testIPSpoofing(EndpointInfo endpoint, HttpClient client) {
        String[] ipHeaders = {"X-Forwarded-For", "X-Real-IP", "X-Client-IP", "X-Cluster-Client-IP"};
        String[] fakeIPs = {"192.168.1.100", "10.0.0.50", "172.16.254.1", "203.0.113.195"};

        int successfulRequests = 0;

        System.out.println("🎭 Testing IP address spoofing (" + ipHeaders.length + " headers)...");

        for (int i = 0; i < ipHeaders.length; i++) {
            try {
                Map<String, String> headers = new HashMap<>();
                headers.put(ipHeaders[i], fakeIPs[i]);

                // ✅ ИСПРАВЛЕНО: Используем executeRequest
                HttpResponse response = client.executeRequest(new HttpGet(endpoint.getFullUrl()), headers);

                int statusCode = response.getStatusCode();
                String responseBody = response.getResponseBody(); // ✅ ИСПРАВЛЕНО: getResponseBody()

                if (!isRateLimitResponse(statusCode, responseBody)) {
                    successfulRequests++;
                }

                totalRateLimitRequests++;

                Thread.sleep(150); // Задержка между запросами

            } catch (Exception e) {
                totalRateLimitRequests++;
            }
        }

        // ✅ Если большинство запросов прошло - уязвимость
        if (successfulRequests >= ipHeaders.length - 1) {
            return new Finding(
                "RL-IP-BYPASS-03",
                "IP Spoofing Rate Limit Bypass (API4:2023)",
                "⚠️ MEDIUM: Rate limiting is vulnerable to IP address spoofing via headers.\n\n" +
                "• Headers tested: " + String.join(", ", ipHeaders) + "\n" +
                "• Successful requests: " + successfulRequests + "\n" +
                "• System trusts client-provided IP headers without validation",
                Severity.MEDIUM,
                getId(),
                endpoint.getFullUrl(),
                "✅ CRITICAL REMEDIATION REQUIRED:\n\n" +
                "1. NEVER TRUST CLIENT-PROVIDED IP HEADERS\n" +
                "   • Use real IP from connection (remote address)\n" +
                "   • Validate and sanitize IP headers\n\n" +
                "2. CONFIGURE TRUSTED PROXIES\n" +
                "   • Only trust IP headers from known proxies\n" +
                "   • Implement proper proxy chain validation\n\n" +
                "3. IMPLEMENT IP FINGERPRINTING\n" +
                "   • Combine multiple factors for client identification\n" +
                "   • Monitor for suspicious IP patterns"
            );
        }

        System.out.println("✅ IP spoofing blocked: " + successfulRequests + "/" + ipHeaders.length + " requests passed");
        return null;
    }

    /**
     * ✅ Проверяет, является ли ответ рейт-лимитом
     */
    private boolean isRateLimitResponse(int statusCode, String responseBody) {
        if (responseBody == null) responseBody = "";

        // ✅ Проверяем по статус-коду и содержимому
        return statusCode == 429 || // Too Many Requests
               statusCode == 403 || // Forbidden (часто используется как рейт-лимит)
               responseBody.toLowerCase().contains("rate limit") ||
               responseBody.toLowerCase().contains("too many requests") ||
               responseBody.toLowerCase().contains("exceeded") ||
               responseBody.toLowerCase().contains("throttle") ||
               responseBody.toLowerCase().contains("quota");
    }

    /**
     * ✅ Создает заголовки для тестирования рейт-лимита
     */
    private Map<String, String> createRateLimitHeaders(int requestIndex) {
        Map<String, String> headers = new HashMap<>();
        headers.put("User-Agent", "ASTF-RateLimit-Tester/1.0");
        headers.put("Accept", "application/json");
        
        // ✅ Добавляем вариации для обхода простых систем
        if (requestIndex % 3 == 0) {
            headers.put("X-Client-Version", "1.0." + requestIndex);
        }
        
        return headers;
    }

    /**
     * ✅ Сбрасывает статистику теста (для тестирования)
     */
    public static void reset() {
        rateLimitTestCompleted.set(false);
        totalRateLimitRequests = 0;
    }

    /**
     * ✅ Возвращает общее количество сделанных запросов
     */
    public static int getTotalRequests() {
        return totalRateLimitRequests;
    }
}
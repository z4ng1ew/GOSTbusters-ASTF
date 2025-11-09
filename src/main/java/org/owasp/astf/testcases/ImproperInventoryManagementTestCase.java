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
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Tests for API9:2023 - Improper Inventory Management.
 * 
 * This test case checks for exposed debug endpoints, old API versions, internal endpoints,
 * and other undocumented API paths that shouldn't be accessible in production.
 * Improper Inventory Management occurs when APIs expose unnecessary endpoints that
 * can provide attackers with additional attack surface, internal information, or
 * undocumented functionality.
 * 
 * @see <a href="https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory/">OWASP API Security Top 10 2023: API9 Improper Inventory Management</a>
 */
public class ImproperInventoryManagementTestCase implements TestCase {
    private static final Logger logger = LogManager.getLogger(ImproperInventoryManagementTestCase.class);

    private ScanConfig config;

    // Patterns for suspicious endpoint paths
    private static final List<Pattern> SUSPICIOUS_PATH_PATTERNS = List.of(
        Pattern.compile(".*debug.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*admin.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*test.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*internal.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*health.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*metrics.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*actuator.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*monitoring.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*management.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*swagger.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*api-docs.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*.old.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*.bak.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*.backup.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*.dev.*", Pattern.CASE_INSENSITIVE),
        Pattern.compile(".*.temp.*", Pattern.CASE_INSENSITIVE)
    );

    @Override
    public void init(ScanConfig config) {
        this.config = config;
    }

    @Override
    public String getId() {
        return "API9:2023";
    }

    @Override
    public String getName() {
        return "Improper Inventory Management (API9:2023)";
    }

    @Override
    public String getDescription() {
        return """
               Tests for exposed debug endpoints, old API versions, internal paths, and other 
               undocumented API functionality that shouldn't be accessible in production.
               """;
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient client) throws IOException {
        List<Finding> findings = new ArrayList<>();

        String path = endpoint.getPath().toLowerCase();
        System.out.println("🔍 Testing inventory management on: " + endpoint.getMethod() + " " + endpoint.getPath());

        // ✅ ПРОВЕРЯЕМ: является ли эндпоинт подозрительным
        boolean isSuspicious = SUSPICIOUS_PATH_PATTERNS.stream()
            .anyMatch(pattern -> pattern.matcher(path).matches());

        if (!isSuspicious) {
            logger.debug("⏭️ Skipping non-suspicious endpoint: {}", endpoint.getPath());
            return findings;
        }

        // ✅ ИСПРАВЛЕНО: Используем аутентификационные заголовки из конфига
        Map<String, String> authHeaders = config.getHeaders() != null ? config.getHeaders() : Collections.emptyMap();

        try {
            // ✅ ПРОБУЕМ ПОЛУЧИТЬ ДОСТУП К ПОДОЗРИТЕЛЬНОМУ ЭНДПОИНТУ
            HttpResponse response = client.executeRequest(
                new HttpGet(endpoint.getFullUrl()),
                authHeaders // ✅ ИСПОЛЬЗУЕМ АУТЕНТИФИКАЦИОННЫЕ ЗАГОЛОВКИ
            );

            int statusCode = response.getStatusCode();
            String responseBody = response.getResponseBody(); // ✅ ИСПРАВЛЕНО: getResponseBody()

            // ✅ АНАЛИЗИРУЕМ ОТВЕТ
            if (statusCode == 200) {
                // ✅ УЯЗВИМОСТЬ: подозрительный эндпоинт доступен!
                findings.add(createInventoryFinding(endpoint, statusCode, responseBody));
                System.out.println("🚨 INVENTORY VULNERABILITY: " + endpoint.getPath() + " returned 200 OK");
            } else if (statusCode == 403 || statusCode == 404) {
                // ✅ OK: эндпоинт защищён или не существует
                logger.debug("✅ Inventory protection working: {} on {}", statusCode, endpoint.getPath());
            } else {
                // ✅ ПОДОЗРИТЕЛЬНО: другой статус
                logger.debug("⚠️ Suspicious response: {} on {}", statusCode, endpoint.getPath());
            }

        } catch (Exception e) {
            logger.debug("Inventory test failed for {}: {}", endpoint.getPath(), e.getMessage());
            // Не считаем ошибку за уязвимость
        }

        if (findings.isEmpty()) {
            System.out.println("✅ Inventory protection verified: " + endpoint.getMethod() + " " + endpoint.getPath());
        } else {
            System.out.println("🎯 Inventory issues found: " + findings.size() + " on " + endpoint.getPath());
        }

        return findings;
    }

    /**
     * ✅ Создаёт finding для уязвимости управления инвентарём
     */
    private Finding createInventoryFinding(EndpointInfo endpoint, int statusCode, String response) {
        String path = endpoint.getPath();
        String category = getEndpointCategory(path);

        return new Finding(
            "INVENTORY-01",
            "Improper Inventory Management (API9:2023)",
            "🚨 CRITICAL: Exposed potentially dangerous endpoint: " + endpoint.getMethod() + " " + path + "\n\n" +
            "• Vulnerability: Improper Inventory Management\n" +
            "• Endpoint Category: " + category + "\n" +
            "• Response Status: " + statusCode + "\n" +
            "• Response Length: " + (response != null ? response.length() : 0) + " chars\n" +
            "• Impact: Attackers can discover internal endpoints, debug interfaces, or undocumented functionality\n" +
            "• Risk: Information disclosure, increased attack surface, potential privilege escalation",
            Severity.HIGH,
            getId(),
            endpoint.getFullUrl(),
            "✅ CRITICAL REMEDIATION REQUIRED:\n\n" +
            "1. REMOVE EXPOSED DEBUG/INTERNAL ENDPOINTS\n" +
            "   • Delete all /debug, /admin, /internal, /health endpoints from production\n" +
            "   • Never expose development/testing endpoints in production\n\n" +
            "2. IMPLEMENT PROPER INVENTORY MANAGEMENT\n" +
            "   • Maintain documented API inventory\n" +
            "   • Regularly audit exposed endpoints\n" +
            "   • Remove unused/legacy API versions\n\n" +
            "3. ENFORCE ACCESS CONTROLS\n" +
            "   • Apply authentication/authorization to all endpoints\n" +
            "   • Block access to administrative endpoints in production\n" +
            "   • Use network-level restrictions for sensitive paths\n\n" +
            "4. CONFIGURE PRODUCTION SECURITY\n" +
            "   • Disable Swagger UI in production\n" +
            "   • Hide detailed error messages\n" +
            "   • Restrict access to monitoring endpoints"
        );
    }

    /**
     * ✅ Возвращает категорию подозрительного эндпоинта
     */
    private String getEndpointCategory(String path) {
        if (path.contains("debug")) return "Debug Interface";
        if (path.contains("admin")) return "Administrative Interface";
        if (path.contains("test")) return "Testing Interface";
        if (path.contains("internal")) return "Internal Interface";
        if (path.contains("health")) return "Health Check";
        if (path.contains("metrics")) return "Metrics Interface";
        if (path.contains("actuator")) return "Spring Actuator";
        if (path.contains("swagger") || path.contains("api-docs")) return "API Documentation";
        if (path.contains("old") || path.contains("v1-") || path.contains("v2-")) return "Legacy API Version";
        if (path.contains("backup") || path.contains("bak")) return "Backup/Archive";
        if (path.contains("dev") || path.contains("temp")) return "Development Interface";
        return "Suspicious Endpoint";
    }
}
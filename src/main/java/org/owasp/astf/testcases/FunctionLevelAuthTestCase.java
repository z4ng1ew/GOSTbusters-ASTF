package org.owasp.astf.testcases;

import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.methods.HttpRequestBase;
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
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Tests for API5:2023 - Broken Function Level Authorization.
 * 
 * This test case checks if users can access HTTP methods they shouldn't have permission to use
 * on specific endpoints. For example, a regular user might be allowed to GET /accounts/{id}
 * but should NOT be allowed to DELETE /accounts/{id}. Function Level Authorization ensures
 * that users can only perform the actions they are authorized to perform.
 * 
 * @see <a href="https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-auth/">OWASP API Security Top 10 2023: API5 Broken Function Level Authorization</a>
 */
public class FunctionLevelAuthTestCase implements TestCase {
    private static final Logger logger = LogManager.getLogger(FunctionLevelAuthTestCase.class);

    private ScanConfig config;

    @Override
    public void init(ScanConfig config) {
        this.config = config;
    }

    @Override
    public String getId() {
        return "API5:2023";
    }

    @Override
    public String getName() {
        return "Broken Function Level Authorization (API5:2023)";
    }

    @Override
    public String getDescription() {
        return """
               Tests for function level authorization bypass where users can access HTTP methods
               they shouldn't have permission to use. Checks if users can perform unauthorized
               actions like DELETE on GET-only endpoints.
               """;
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient client) throws IOException {
        logger.info("Executing {} test on {}", getId(), endpoint);
        List<Finding> findings = new ArrayList<>();

        System.out.println("🔐 Testing function level authorization on: " + endpoint.getMethod() + " " + endpoint.getPath());

        // ✅ ПРОВЕРЯЕМ: содержит ли эндпоинт ID-параметры (потенциально уязвим к FLA)
        if (!endpoint.getPath().contains("{id}") && 
            !endpoint.getPath().contains("{accountId}") && 
            !endpoint.getPath().contains("{account_id}")) {
            logger.debug("Skipping non-ID endpoint for FLA: {}", endpoint.getPath());
            return findings;
        }

        // ✅ ПРОВЕРЯЕМ: есть ли у нас токен для выполнения запросов
        if (config.getHeaders() == null || config.getHeaders().isEmpty()) {
            logger.warn("❌ No authentication headers available for FLA test on: {}", endpoint.getPath());
            return findings;
        }

        // ✅ ПРОВЕРЯЕМ: можем ли мы выполнить метод, отличный от разрешенного
        findings.addAll(testUnauthorizedMethodAccess(endpoint, client));

        if (findings.isEmpty()) {
            System.out.println("✅ Function level authorization working: " + endpoint.getMethod() + " " + endpoint.getPath());
        } else {
            System.out.println("🚨 FLA vulnerabilities found: " + findings.size() + " on " + endpoint.getPath());
        }

        return findings;
    }

    /**
     * ✅ Тестирует доступ к неразрешенным HTTP методам
     */
    private List<Finding> testUnauthorizedMethodAccess(EndpointInfo endpoint, HttpClient client) throws IOException {
        List<Finding> findings = new ArrayList<>();

        // ✅ Определяем разрешенные методы (на основе текущего метода в endpoint)
        String allowedMethod = endpoint.getMethod().toUpperCase();
        List<String> unauthorizedMethods = getUnauthorizedMethods(allowedMethod);

        // ✅ Создаем поддельный ID для теста
        String fakeId = generateFakeId(endpoint);

        for (String unauthorizedMethod : unauthorizedMethods) {
            try {
                // ✅ ЗАМЕНЯЕМ {id} на поддельный ID
                String testUrl = endpoint.getFullUrl()
                    .replace("{id}", fakeId)
                    .replace("{accountId}", fakeId)
                    .replace("{account_id}", fakeId);

                // ✅ ВЫПОЛНЯЕМ ЗАПРОС С НЕРАЗРЕШЕННОГО МЕТОДА
                HttpRequestBase request = createRequest(unauthorizedMethod, testUrl);
                
                // ✅ ИСПОЛЬЗУЕМ АУТЕНТИФИКАЦИОННЫЕ ЗАГОЛОВКИ ИЗ КОНФИГА
                Map<String, String> authHeaders = config.getHeaders();
                HttpResponse response = client.executeRequest(request, authHeaders);

                // ✅ АНАЛИЗИРУЕМ ОТВЕТ
                int statusCode = response.getStatusCode();
                
                if (isUnauthorizedAccessAllowed(statusCode)) {
                    findings.add(createFlaFinding(unauthorizedMethod, endpoint, testUrl, statusCode));
                    System.out.println("🚨 FLA VULNERABILITY: " + unauthorizedMethod + " on " + endpoint.getPath() + " -> " + statusCode);
                } else if (statusCode == 403 || statusCode == 405) {
                    logger.debug("✅ FLA protection working: {} blocked on {} (status: {})", 
                        unauthorizedMethod, endpoint.getPath(), statusCode);
                } else {
                    logger.debug("ℹ️ Unexpected status {} for {} on {}", statusCode, unauthorizedMethod, endpoint.getPath());
                }

            } catch (Exception e) {
                logger.debug("FLA test failed for {} on {}: {}", unauthorizedMethod, endpoint.getPath(), e.getMessage());
                // Не считаем ошибку за уязвимость
            }
        }

        return findings;
    }

    /**
     * ✅ Возвращает методы, которые НЕ должны быть разрешены
     */
    private List<String> getUnauthorizedMethods(String allowedMethod) {
        List<String> allMethods = List.of("GET", "POST", "PUT", "DELETE", "PATCH");
        return allMethods.stream()
            .filter(method -> !method.equals(allowedMethod))
            .toList();
    }

    /**
     * ✅ Создает HTTP-запрос для указанного метода
     */
    private HttpRequestBase createRequest(String method, String url) {
        return switch (method.toUpperCase()) {
            case "GET" -> new HttpGet(url);
            case "POST" -> new HttpPost(url);
            case "PUT" -> new HttpPut(url);
            case "DELETE" -> new HttpDelete(url);
            case "PATCH" -> {
                // Apache HttpComponents не имеет встроенного HttpPatch
                // Создаем как HttpPost с заголовком Method Override
                HttpPost post = new HttpPost(url);
                post.setHeader("X-HTTP-Method-Override", "PATCH");
                yield post;
            }
            default -> new HttpGet(url); // fallback
        };
    }

    /**
     * ✅ Проверяет, разрешён ли доступ к неразрешённому методу
     */
    private boolean isUnauthorizedAccessAllowed(int statusCode) {
        // ✅ Если получаем 200/201/204 - это уязвимость (доступ разрешён без прав)
        return statusCode >= 200 && statusCode < 300;
    }

    /**
     * ✅ Генерирует поддельный ID для теста
     */
    private String generateFakeId(EndpointInfo endpoint) {
        String path = endpoint.getPath().toLowerCase();
        
        if (path.contains("account")) {
            return "acc-" + System.currentTimeMillis() + "-" + (int)(Math.random() * 1000);
        } else if (path.contains("user")) {
            return "usr-" + System.currentTimeMillis() + "-" + (int)(Math.random() * 1000);
        } else if (path.contains("transaction")) {
            return "txn-" + System.currentTimeMillis() + "-" + (int)(Math.random() * 1000);
        } else {
            return "obj-" + System.currentTimeMillis() + "-" + (int)(Math.random() * 1000);
        }
    }

    /**
     * ✅ Создает finding для FLA уязвимости
     */
    private Finding createFlaFinding(String unauthorizedMethod, EndpointInfo endpoint, String url, int statusCode) {
        return new Finding(
            "FLA-01",
            "Function Level Authorization Bypass",
            "🚨 CRITICAL: User can execute " + unauthorizedMethod + " on endpoint restricted to " + endpoint.getMethod() + "\n\n" +
            "• Vulnerability: Function Level Authorization Bypass\n" +
            "• Endpoint: " + endpoint.getMethod() + " " + endpoint.getPath() + "\n" +
            "• Unauthorized Method: " + unauthorizedMethod + "\n" +
            "• Request URL: " + url + "\n" +
            "• Response Status: " + statusCode + "\n" +
            "• Impact: Attackers can perform unauthorized actions (delete, modify) on resources they can only read",
            Severity.HIGH,
            getId(),
            endpoint.getFullUrl(),
            "✅ CRITICAL REMEDIATION REQUIRED:\n\n" +
            "1. IMPLEMENT METHOD-LEVEL AUTHORIZATION\n" +
            "   • Verify HTTP method permissions for each endpoint\n" +
            "   • Block unauthorized HTTP methods with 403 Forbidden\n\n" +
            "2. USE FRAMEWORK AUTHORIZATION\n" +
            "   • Apply @PreAuthorize or similar annotations\n" +
            "   • Define explicit method permissions per endpoint\n\n" +
            "3. VALIDATE REQUESTS SERVER-SIDE\n" +
            "   • Don't rely solely on client-side restrictions\n" +
            "   • Implement server-side method validation\n\n" +
            "4. FOLLOW PRINCIPLE OF LEAST PRIVILEGE\n" +
            "   • Grant minimal necessary permissions\n" +
            "   • Audit and review method-level access regularly"
        );
    }
}
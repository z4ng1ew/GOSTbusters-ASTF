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
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Tests for IDOR (Insecure Direct Object Reference) vulnerabilities - API4:2023.
 * 
 * This test case checks for broken object-level authorization where users can access
 * resources they shouldn't have permission to access by manipulating object identifiers
 * in requests. IDOR occurs when an application does not properly verify whether a user
 * is authorized to access a particular resource identified by a direct reference.
 * 
 * @see <a href="https://owasp.org/API-Security/editions/2023/en/0xa4-broken-object-level-auth/">OWASP API Security Top 10 2023: API4 Broken Object Level Authorization</a>
 */
public class IdorTestCase implements TestCase {
    private static final Logger logger = LogManager.getLogger(IdorTestCase.class);

    private ScanConfig config;
    private static final AtomicBoolean idorTestCompleted = new AtomicBoolean(false);

    @Override
    public void init(ScanConfig config) {
        this.config = config;
    }

    @Override
    public String getId() {
        return "API4:2023";
    }

    @Override
    public String getName() {
        return "Insecure Direct Object Reference (IDOR) - Broken Object Level Authorization (API4:2023)";
    }

    @Override
    public String getDescription() {
        return """
               Tests for IDOR by attempting to access foreign object IDs with current user's token.
               This covers both BOLA (Broken Object Level Authorization) and broader IDOR patterns.
               """;
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient client) throws IOException {
        // ✅ ПРОВЕРКА: уже выполнен ли тест
        if (idorTestCompleted.getAndSet(true)) {
            logger.info("⏩ IDOR test already executed. Skipping duplicate run.");
            return Collections.emptyList();
        }

        List<Finding> findings = new ArrayList<>();
        String path = endpoint.getPath();

        System.out.println("🔍 Testing IDOR on: " + endpoint.getMethod() + " " + endpoint.getPath());

        // ✅ ПРОВЕРКА: содержит ли эндпоинт ID параметры
        if (!path.contains("{id}") && 
            !path.contains("{resource_id}") && 
            !path.contains("{account_id}") &&
            !path.contains("{user_id}") &&
            !path.contains("{transaction_id}")) {
            logger.debug("⏭️ Skipping non-IDOR endpoint: {}", endpoint.getPath());
            return findings;
        }

        // ✅ ИСПОЛЬЗУЕМ АУТЕНТИФИКАЦИОННЫЕ ЗАГОЛОВКИ ИЗ КОНФИГА
        Map<String, String> authHeaders = config.getHeaders() != null ? config.getHeaders() : Collections.emptyMap();

        // ✅ ГЕНЕРИРУЕМ ПОДДЕЛЬНЫЕ ID ДЛЯ ТЕСТИРОВАНИЯ
        List<String> testIds = generateTestIds();

        for (String testId : testIds) {
            try {
                // ✅ ЗАМЕНЯЕМ ВСЕ ТИПЫ ID ПАРАМЕТРОВ
                String testUrl = endpoint.getFullUrl()
                    .replace("{id}", testId)
                    .replace("{resource_id}", testId)
                    .replace("{account_id}", testId)
                    .replace("{user_id}", testId)
                    .replace("{transaction_id}", testId);

                logger.debug("🧪 Testing IDOR with ID: {} -> URL: {}", testId, testUrl);

                // ✅ ИСПРАВЛЕНО: Используем executeRequest с двумя параметрами
                HttpResponse response = client.executeRequest(new HttpGet(testUrl), authHeaders);

                // ✅ АНАЛИЗИРУЕМ ОТВЕТ
                if (isIdorVulnerable(response)) {
                    findings.add(createIdorFinding(endpoint, testUrl, testId, response.getStatusCode()));
                    System.out.println("🚨 IDOR VULNERABILITY FOUND: access to " + testId);
                } else {
                    System.out.println("✅ IDOR protection working: denied access to " + testId);
                }

            } catch (Exception e) {
                logger.debug("IDOR test failed for ID {}: {}", testId, e.getMessage());
                // Не считаем ошибку за уязвимость
            }
        }

        if (findings.isEmpty()) {
            System.out.println("✅ IDOR protection verified for: " + endpoint.getMethod() + " " + endpoint.getPath());
        } else {
            System.out.println("🎯 IDOR test completed: " + findings.size() + " vulnerabilities found");
        }

        return findings;
    }

    /**
     * ✅ Генерирует ID для тестирования (другие команды, случайные числа)
     */
    private List<String> generateTestIds() {
        List<String> testIds = new ArrayList<>();
        
        // ✅ ID других команд
        for (int teamNum = 170; teamNum <= 190; teamNum++) {
            if (teamNum != 179) { // Не наша команда
                testIds.add("acc-" + teamNum + "-1");
                testIds.add("usr-" + teamNum + "-1");
                testIds.add("txn-" + teamNum + "-1");
            }
        }
        
        // ✅ Случайные числовые ID
        for (int i = 1000; i <= 9999; i += 1000) {
            testIds.add(String.valueOf(i));
        }
        
        // ✅ Общие подозрительные ID
        testIds.addAll(List.of("001", "999", "admin", "test", "demo", "12345", "99999"));
        
        return testIds;
    }

    /**
     * ✅ Проверяет, является ли ответ уязвимым к IDOR
     */
    private boolean isIdorVulnerable(HttpResponse response) {
        // ✅ Уязвимость: 200 OK + чувствительные данные
        if (response.getStatusCode() == 200) {
            String body = response.getResponseBody(); // ✅ ИСПРАВЛЕНО: используем getResponseBody()
            
            // ✅ Проверяем, содержит ли ответ данные объекта (а не ошибку)
            return body.toLowerCase().contains("account") || 
                   body.toLowerCase().contains("user") || 
                   body.toLowerCase().contains("balance") ||
                   body.toLowerCase().contains("owner") ||
                   body.length() > 100; // Длинный ответ = вероятно, данные
        }
        
        // ✅ Также уязвимость: 200 OK на DELETE/PUT (если это не GET endpoint)
        return response.getStatusCode() == 200 && 
               (response.getResponseBody() == null || response.getResponseBody().isEmpty());
    }

    /**
     * ✅ Создает finding для IDOR уязвимости
     */
    private Finding createIdorFinding(EndpointInfo endpoint, String url, String testId, int statusCode) {
        return new Finding(
            "IDOR-01",
            "Insecure Direct Object Reference (API4:2023)",
            "🚨 CRITICAL: Successfully accessed foreign object with ID " + testId + "\n\n" +
            "• Vulnerability: Broken Object Level Authorization\n" +
            "• Endpoint: " + endpoint.getMethod() + " " + endpoint.getPath() + "\n" +
            "• Test ID: " + testId + "\n" +
            "• Response Status: " + statusCode + "\n" +
            "• Impact: Attackers can access other users' resources by changing object IDs",
            Severity.CRITICAL,
            getId(),
            url,
            "✅ CRITICAL REMEDIATION REQUIRED:\n\n" +
            "1. IMPLEMENT OBJECT OWNERSHIP CHECKS\n" +
            "   • Validate that requested object belongs to authenticated user\n" +
            "   • Use JOIN queries: WHERE user_id = :current_user_id\n\n" +
            "2. USE INDIRECT REFERENCES\n" +
            "   • Map internal IDs to random UUIDs\n" +
            "   • Never expose internal object IDs directly\n\n" +
            "3. APPLY RBAC CONTROLS\n" +
            "   • Implement role-based access control\n" +
            "   • Verify permissions for each object access\n\n" +
            "4. LOG UNAUTHORIZED ACCESS ATTEMPTS\n" +
            "   • Monitor and alert on suspicious ID patterns\n" +
            "   • Track access to foreign objects"
        );
    }
}
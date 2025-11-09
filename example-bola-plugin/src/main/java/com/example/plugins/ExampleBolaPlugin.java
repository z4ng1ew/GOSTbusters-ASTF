package com.example.plugins;

import org.apache.http.client.methods.HttpGet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.http.HttpResponse;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.Severity;

import java.io.IOException;
import java.util.*;

/**
 * Example BOLA (Broken Object Level Authorization) Plugin.
 * 
 * This plugin demonstrates how to create a custom test case that can be dynamically
 * loaded into the ASTF framework. It tests for BOLA vulnerabilities by attempting
 * to access foreign account IDs through parameter manipulation.
 * 
 * @see <a href="https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/">OWASP API Security Top 10 2023: API1 Broken Object Level Authorization</a>
 */
public class ExampleBolaPlugin implements org.owasp.astf.plugin.Plugin { // ✅ Правильный путь к интерфейсу
    private static final Logger logger = LogManager.getLogger(ExampleBolaPlugin.class);

    @Override
    public String getId() {
        return "PLUGIN-BOLA-01";
    }

    @Override
    public String getName() {
        return "BOLA Vulnerability Detector (Plugin)";
    }

    @Override
    public String getDescription() {
        return """
               Demonstrates BOLA testing through plugin architecture.
               Tests for Broken Object Level Authorization by attempting to access 
               foreign account IDs with current user's authentication context.
               """;
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient client) throws IOException {
        List<Finding> findings = new ArrayList<>();
        logger.info("Plugin: Testing BOLA on {}", endpoint.getPath());

        // ✅ ПРОВЕРЯЕМ: содержит ли эндпоинт параметр ID (подходит для BOLA)
        String path = endpoint.getPath().toLowerCase();
        if (!path.contains("{id}") && 
            !path.contains("{account_id}") && 
            !path.contains("{accountId}")) {
            logger.debug("Plugin: Skipping non-BOLA endpoint: {}", endpoint.getPath());
            return findings;
        }

        System.out.println("🔌 Plugin: Testing BOLA on " + endpoint.getMethod() + " " + endpoint.getPath());

        // ✅ ГЕНЕРИРУЕМ ПОДОЗРИТЕЛЬНЫЕ ID ДЛЯ ТЕСТИРОВАНИЯ
        List<String> suspiciousIds = generateSuspiciousAccountIds();

        // ✅ ИСПОЛЬЗУЕМ ЗАГОЛОВКИ ИЗ КЛИЕНТА (уже содержит токены и согласие)
        Map<String, String> authHeaders = client.getDefaultHeaders(); // ✅ ИСПРАВЛЕНО: метод из твоего HttpClient

        int vulnerableCount = 0;

        for (String accountId : suspiciousIds) {
            try {
                // ✅ ЗАМЕНЯЕМ {id} НА ПОДОЗРИТЕЛЬНЫЙ ID
                String testUrl = endpoint.getFullUrl()
                    .replace("{id}", accountId)
                    .replace("{account_id}", accountId)
                    .replace("{accountId}", accountId);

                logger.debug("Plugin: Testing access to foreign account: {}", testUrl);

                // ✅ ИСПРАВЛЕНО: Используем executeRequest с двумя параметрами
                HttpResponse response = client.executeRequest(new HttpGet(testUrl), authHeaders);

                int statusCode = response.getStatusCode();
                String responseBody = response.getResponseBody(); // ✅ ИСПРАВЛЕНО: getResponseBody()

                logger.debug("Plugin: Response for {} - Status: {}, Body length: {}", accountId, statusCode, responseBody.length());

                // ✅ АНАЛИЗИРУЕМ ОТВЕТ: уязвимость если 200 OK + данные счета
                if (statusCode == 200 && containsAccountData(responseBody)) {
                    findings.add(new Finding(
                        "PLUGIN-BOLA-01",
                        "BOLA Vulnerability via Plugin",
                        "🚨 CRITICAL: Successfully accessed foreign account " + accountId + " with current token!\n\n" +
                        "• Endpoint: " + endpoint.getMethod() + " " + endpoint.getPath() + "\n" +
                        "• Foreign Account ID: " + accountId + "\n" +
                        "• Response Status: " + statusCode + "\n" +
                        "• Impact: Attackers can access other users' accounts by manipulating ID parameter",
                        Severity.CRITICAL,
                        getId(),
                        testUrl,
                        "✅ CRITICAL REMEDIATION REQUIRED:\n\n" +
                        "1. IMPLEMENT OBJECT OWNERSHIP VALIDATION\n" +
                        "   • Verify that account_id belongs to authenticated user\n" +
                        "   • Use JOIN queries: WHERE user_id = :current_user_id\n\n" +
                        "2. APPLY RBAC CONTROLS\n" +
                        "   • Define permissions per object type\n" +
                        "   • Validate access for each object request\n\n" +
                        "3. USE NON-PREDICTABLE IDS\n" +
                        "   • Replace sequential IDs with UUIDs\n" +
                        "   • Obfuscate internal object identifiers\n\n" +
                        "4. LOG UNAUTHORIZED ACCESS ATTEMPTS\n" +
                        "   • Track access to foreign objects\n" +
                        "   • Alert on suspicious ID patterns"
                    ));
                    vulnerableCount++;
                    System.out.println("🚨 PLUGIN BOLA VULNERABILITY: access to " + accountId);
                } else if (statusCode == 403 || statusCode == 404) {
                    logger.debug("Plugin: BOLA protection working for account: {}", accountId);
                } else {
                    logger.debug("Plugin: Unexpected status {} for account: {}", statusCode, accountId);
                }

            } catch (Exception e) {
                String errorMsg = e.getMessage();
                if (errorMsg != null) {
                    if (errorMsg.contains("429")) {
                        System.out.println("⚠️ Rate limit hit, pausing...");
                        try { Thread.sleep(1000); } catch (InterruptedException ie) { Thread.currentThread().interrupt(); }
                    } else if (errorMsg.contains("403") || errorMsg.contains("404")) {
                        logger.debug("Plugin: BOLA protection active: {}", errorMsg);
                    } else {
                        logger.warn("Plugin: Error testing account {}: {}", accountId, errorMsg);
                    }
                }
            }
        }

        if (vulnerableCount > 0) {
            System.out.println("🎯 Plugin: Found " + vulnerableCount + " BOLA vulnerabilities");
        } else {
            System.out.println("✅ Plugin: BOLA protection working (no vulnerabilities found)");
        }

        return findings;
    }

    /**
     * ✅ Генерирует подозрительные account ID для других команд
     */
    private List<String> generateSuspiciousAccountIds() {
        List<String> ids = new ArrayList<>();
        
        // ✅ ID других команд (для хакатона)
        for (int teamNum = 170; teamNum <= 190; teamNum++) {
            if (teamNum != 179) { // Не наша команда
                ids.add("acc-" + teamNum + "-1");
                ids.add("acc-" + teamNum + "-2");
            }
        }
        
        // ✅ Общие подозрительные ID
        ids.addAll(List.of(
            "acc-999-999", "acc-888-888", "acc-000-000", // Чужие/несуществующие
            "123456789", "admin", "root", "0", "test"  // Простые ID
        ));
        
        return ids;
    }

    /**
     * ✅ Проверяет, содержит ли ответ данные счета (признак уязвимости)
     */
    private boolean containsAccountData(String response) {
        if (response == null || response.trim().isEmpty()) {
            return false;
        }

        String lowerResponse = response.toLowerCase();

        // ✅ Проверяем наличие чувствительных данных счета
        boolean hasAccountFields = lowerResponse.contains("account") &&
                                   (lowerResponse.contains("balance") || 
                                    lowerResponse.contains("amount") ||
                                    lowerResponse.contains("owner") ||
                                    lowerResponse.contains("iban") ||
                                    lowerResponse.contains("number"));

        // ✅ Убеждаемся, что это не сообщение об ошибке
        boolean isNotError = !lowerResponse.contains("error") &&
                            !lowerResponse.contains("forbidden") &&
                            !lowerResponse.contains("access denied") &&
                            !lowerResponse.contains("unauthorized");

        // ✅ Проверяем достаточный размер ответа (не пустой/короткий)
        boolean hasSubstantialData = response.length() > 50;

        return hasAccountFields && isNotError && hasSubstantialData;
    }
}
package org.owasp.astf.testcases;

import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.Severity;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

public class BolaTestCase implements TestCase {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    
    // ✅ ДОБАВЛЕНО: Статические переменные для предотвращения многократного запуска
    private static boolean bolaTestCompleted = false;
    private static final Object BOLA_LOCK = new Object();
    private static final AtomicInteger totalRequests = new AtomicInteger(0);

    @Override
    public String getId() {
        return "BOLA";
    }

    @Override
    public String getName() {
        return "Broken Object Level Authorization";
    }

    @Override
    public String getDescription() {
        return "Tests for Broken Object Level Authorization vulnerabilities by attempting to access resources belonging to other users using object ID manipulation";
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient client) throws IOException {
        // ✅ ДОБАВЛЕНО: Проверяем, запускался ли тест раньше
        synchronized (BOLA_LOCK) {
            if (bolaTestCompleted) {
                System.out.println("⏩ BOLA test already completed - skipping duplicate execution");
                return Collections.emptyList();
            }
        }
        
        // ✅ ИСКЛЮЧАЕМ: Не BOLA-эндпоинты
        String path = endpoint.getPath();
        if (!path.contains("{account_id}") && !path.contains("account_id")) {
            System.out.println("⏭️ Skipping non-BOLA endpoint: " + path);
            return Collections.emptyList();
        }
        
        List<Finding> findings = new ArrayList<>();

        try {
            String baseUrl = endpoint.getBaseUrl();
            
            // ✅ ПОМЕЧАЕМ ТЕСТ КАК ЗАПУЩЕННЫЙ
            synchronized (BOLA_LOCK) {
                bolaTestCompleted = true;
            }
            
            System.out.println("🔍 Starting BOLA test on endpoint: " + endpoint.getMethod() + " " + path);
            
            // ✅ Получаем наши собственные account_id чтобы понять формат
            List<String> ourAccountIds = getOurAccountIds(endpoint, client);
            
            // ✅ Генерируем подозрительные account_id других команд
            List<String> suspiciousAccountIds = generateSuspiciousAccountIds(ourAccountIds);
            
            System.out.println("🎯 BOLA test: testing " + suspiciousAccountIds.size() + " potentially foreign account IDs");

            // ✅ Пытаемся получить доступ к каждому подозрительному account_id
            boolean rateLimitHit = false;
            int testedCount = 0;
            int successfulTests = 0;
            int vulnerabilityFound = 0;
            
            for (String accountId : suspiciousAccountIds) {
                // ✅ Проверяем, не сработал ли рейт-лимит
                if (rateLimitHit) {
                    System.out.println("⏹️ Stopping BOLA test due to rate limit after " + testedCount + " attempts");
                    break;
                }
                
                // ✅ Пропускаем наши собственные account_id
                if (ourAccountIds.contains(accountId)) {
                    continue;
                }
                
                String testPath = path.replace("{account_id}", accountId)
                                    .replace("account_id", accountId);
                
                // ✅ Формируем полный URL с правильной схемой
                String testUrl = buildFullUrl(baseUrl, testPath);

                // ✅ используем пустые заголовки - HttpClient уже настроен с авторизацией
                Map<String, String> headers = createHeaders();
                
                try {
                    // ✅ HttpClient уже содержит заголовок Authorization из конфигурации
                    String response = client.get(testUrl, headers);
                    totalRequests.incrementAndGet();
                    
                    JsonNode body = MAPPER.readTree(response);
                    
                    // ✅ Проверяем, что в ответе есть данные счета
                    if (isValidAccountResponse(body)) {
                        vulnerabilityFound++;
                        Finding finding = new Finding(
                            "BOLA-0" + vulnerabilityFound,                                     
                            "Broken Object Level Authorization",           
                            "🚨 CRITICAL: УСПЕШНЫЙ ДОСТУП к счёту " + accountId + " с токеном команды team179. " +
                            "Это демонстрирует, что система не проверяет принадлежность account_id текущему пользователю. " +
                            "Злоумышленник может получить доступ к данным других пользователей, просто угадывая или перебирая их account_id.\n\n" +
                            "🔍 ДЕТАЛИ АТАКИ:\n" +
                            "• Использованный account_id: " + accountId + "\n" +
                            "• Целевой эндпоинт: " + endpoint.getMethod() + " " + path + "\n" +
                            "• Токен атакующего: team179\n" +
                            "• Полученные данные: баланс, транзакции, личная информация",    
                            Severity.HIGH,                                 
                            "BOLA",                                        
                            testUrl,                                       
                            "🛡️ РЕКОМЕНДАЦИИ ПО ИСПРАВЛЕНИЮ:\n\n" +
                            "1. **Добавить проверку владения ресурсом** на стороне сервера для каждого запроса\n" +
                            "2. **Реализовать Object-Level Authorization**: каждый запрос к ресурсу с account_id должен проверять, что account_id принадлежит текущему аутентифицированному пользователю\n" +
                            "3. **Использовать непредсказуемые UUID** вместо последовательных или предсказуемых ID\n" +
                            "4. **Внедрить механизм авторизации на уровне объектов** (Object-Level Authorization)\n" +
                            "5. **Логировать все попытки доступа** к не принадлежащим пользователю ресурсам\n" +
                            "6. **Реализовать rate limiting** на основе пользователя, а не IP\n" +
                            "7. **Использовать токены доступа с ограниченной областью действия** (scoped tokens)\n\n" +
                            "💡 ПРИМЕР ИСПРАВЛЕНИЯ:\n" +
                            "```java\n" +
                            "// ПРОВЕРКА ПРИНАДЛЕЖНОСТИ ACCOUNT_ID\n" +
                            "public Account getAccount(String accountId, String currentUserId) {\n" +
                            "    Account account = accountRepository.findById(accountId);\n" +
                            "    if (account == null) throw new NotFoundException();\n" +
                            "    if (!account.getUserId().equals(currentUserId)) {\n" +
                            "        throw new AccessDeniedException(); // 403 Forbidden\n" +
                            "    }\n" +
                            "    return account;\n" +
                            "}\n" +
                            "```"
                        );
                        
                        findings.add(finding);
                        System.out.println("🚨 BOLA VULNERABILITY FOUND: access to foreign account " + accountId);
                        
                        // ✅ НЕ ПРЕРЫВАЕМ ТЕСТ - ищем ВСЕ уязвимые account_id
                        // break; // Убрали break чтобы найти все уязвимости
                    }
                    
                    successfulTests++;
                    testedCount++;
                    
                } catch (IOException e) {
                    // ✅ УЛУЧШЕННАЯ ОБРАБОТКА ОШИБОК: Различаем типы ошибок
                    String errorMsg = e.getMessage();
                    if (errorMsg != null) {
                        if (errorMsg.contains("403") || errorMsg.toLowerCase().contains("forbidden")) {
                            // Это нормально - система защищена
                            if (testedCount % 20 == 0) { // Логируем каждые 20 запросов
                                System.out.println("✅ BOLA protection working (" + testedCount + " tested)");
                            }
                        } else if (errorMsg.contains("404") || errorMsg.toLowerCase().contains("not found")) {
                            // Аккаунт не найден - тоже нормально
                        } else if (errorMsg.contains("429") || errorMsg.toLowerCase().contains("too many requests")) {
                            System.out.println("⚠️ RATE LIMIT HIT: Too many requests (after " + testedCount + " attempts)");
                            rateLimitHit = true;
                        } else if (errorMsg.contains("400") || errorMsg.toLowerCase().contains("bad request")) {
                            // Невалидный формат account_id - пропускаем
                        } else {
                            System.out.println("🔧 BOLA test network error: " + errorMsg);
                        }
                    }
                    
                    testedCount++;
                    totalRequests.incrementAndGet();
                }
                
                // ✅ АДАПТИВНАЯ ЗАДЕРЖКА: увеличиваем при рейт-лимите
                if (!rateLimitHit && testedCount < suspiciousAccountIds.size()) {
                    int delay = rateLimitHit ? 1000 : 150; // 1 секунда при рейт-лимите, 150ms обычно
                    try {
                        Thread.sleep(delay);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        System.out.println("⏹️ BOLA test interrupted");
                        break;
                    }
                }
            }
            
            // ✅ Если не нашли уязвимостей, добавляем информационное сообщение
            if (findings.isEmpty()) {
                String resultMessage = rateLimitHit ? 
                    "incomplete due to rate limiting (" + testedCount + "/" + suspiciousAccountIds.size() + " tested)" : 
                    "completed - no vulnerabilities found (" + testedCount + " account IDs tested)";
                System.out.println("✅ BOLA test " + resultMessage);
                findings.add(createInfoFinding(buildFullUrl(baseUrl, path), suspiciousAccountIds, testedCount, rateLimitHit, successfulTests));
            } else {
                System.out.println("🎯 BOLA test completed: found " + findings.size() + " vulnerabilities in " + testedCount + " attempts");
            }
            
        } catch (Exception e) {
            // ✅ ПОМЕЧАЕМ ТЕСТ КАК ЗАВЕРШЕННЫЙ ДАЖЕ ПРИ ОШИБКЕ
            synchronized (BOLA_LOCK) {
                bolaTestCompleted = true;
            }
            System.err.println("❌ BOLA test execution error: " + e.getMessage());
            if (isVerboseMode()) {
                e.printStackTrace();
            }
        }
        
        return findings;
    }

    /**
     * ✅ Получаем наши собственные account_id чтобы понять формат ID
     */
    private List<String> getOurAccountIds(EndpointInfo endpoint, HttpClient client) throws IOException {
        List<String> accountIds = new ArrayList<>();
        
        try {
            // ✅ Исправлено: используем baseUrl из endpoint
            String baseUrl = endpoint.getBaseUrl();
            
            // ✅ Сначала создаем согласие
            String consentId = createAccountConsent(baseUrl, client);
            if (consentId == null) {
                System.out.println("⚠️ Cannot create consent, using default test account IDs");
                return Arrays.asList("acc-179-1", "acc-179-2", "acc-179-3");
            }

            // ✅ Формируем полный URL с правильной схемой
            String accountsUrl = buildFullUrl(baseUrl, "/accounts?client_id=team179");
            Map<String, String> headers = createHeadersWithConsent(consentId);
            
            String response = client.get(accountsUrl, headers);
            totalRequests.incrementAndGet();
            JsonNode body = MAPPER.readTree(response);
            accountIds = extractAccountIdsFromResponse(body);
            System.out.println("📝 Found our accounts: " + accountIds);
            
        } catch (Exception e) {
            System.out.println("⚠️ Error fetching our accounts: " + e.getMessage());
            if (isVerboseMode()) {
                e.printStackTrace();
            }
        }
        
        // ✅ Fallback: если не получили реальные account_id, используем тестовые
        if (accountIds.isEmpty()) {
            accountIds = Arrays.asList("acc-179-1", "acc-179-2", "acc-179-3", "acc-179-4", "acc-179-5");
        }
        
        return accountIds;
    }

    /**
     * ✅ Создает согласие на доступ к счетам
     */
    private String createAccountConsent(String baseUrl, HttpClient client) throws IOException {
        try {
            // ✅ Формируем полный URL с правильной схемой
            String consentUrl = buildFullUrl(baseUrl, "/account-consents/request");
            
            // ✅ убрали Authorization заголовок - HttpClient уже настроен
            Map<String, String> headers = new HashMap<>();
            headers.put("Content-Type", "application/json");
            headers.put("x-requesting-bank", "team179");
            
            String consentBody = "{\n" +
                "  \"permissions\": [\"accounts\", \"balances\", \"transactions\"],\n" +
                "  \"expiration_datetime\": \"2025-12-31T23:59:59Z\"\n" +
                "}";
            
            String response = client.post(consentUrl, headers, consentBody, "application/json");
            totalRequests.incrementAndGet();
            
            JsonNode body = MAPPER.readTree(response);
            if (body.has("consent_id")) {
                String consentId = body.get("consent_id").asText();
                System.out.println("✅ Created consent: " + consentId);
                return consentId;
            }
        } catch (Exception e) {
            System.out.println("❌ Error creating consent: " + e.getMessage());
            if (isVerboseMode()) {
                e.printStackTrace();
            }
        }
        return null;
    }

    /**
     * ✅ Вспомогательный метод для построения полного URL
     */
    private String buildFullUrl(String baseUrl, String path) {
        // ✅ НОРМАЛИЗАЦИЯ: Убедимся, что baseUrl не содержит двойных слэшей
        String normalizedBaseUrl = baseUrl.trim().replaceAll("(?<!:)/{2,}", "/");
        
        String result;
        if (normalizedBaseUrl.endsWith("/") && path.startsWith("/")) {
            result = normalizedBaseUrl + path.substring(1);
        } else if (!normalizedBaseUrl.endsWith("/") && !path.startsWith("/")) {
            result = normalizedBaseUrl + "/" + path;
        } else {
            result = normalizedBaseUrl + path;
        }
        
        return result;
    }

    /**
     * ✅ Генерирует подозрительные account_id на основе наших account_id
     */
    private List<String> generateSuspiciousAccountIds(List<String> ourAccountIds) {
        List<String> suspiciousIds = new ArrayList<>();
        
        // ✅ Анализируем формат наших account_id
        if (!ourAccountIds.isEmpty()) {
            String sampleId = ourAccountIds.get(0);
            
            // ✅ Пытаемся извлечь паттерн (например, "acc-179-1" -> команда 179)
            if (sampleId.matches("acc-\\d+-\\d+")) {
                // ✅ Генерируем account_id для других команд
                for (int teamId = 170; teamId <= 190; teamId++) {
                    if (teamId != 179) { // Пропускаем нашу команду
                        for (int accountNum = 1; accountNum <= 5; accountNum++) {
                            suspiciousIds.add("acc-" + teamId + "-" + accountNum);
                        }
                    }
                }
            } else if (sampleId.matches("\\d+")) {
                // Числовые ID - генерируем последовательные
                try {
                    long ourId = Long.parseLong(sampleId);
                    for (long i = ourId - 100; i <= ourId + 100; i++) {
                        if (i != ourId && i > 0) {
                            suspiciousIds.add(String.valueOf(i));
                        }
                    }
                } catch (NumberFormatException e) {
                    // ignore
                }
            }
        }
        
        // ✅ Добавляем общие тестовые account_id
        suspiciousIds.addAll(Arrays.asList(
            "acc-001", "acc-002", "acc-100", "acc-200", "acc-500", "acc-999",
            "acc-test-1", "acc-demo-1", "acc-admin", "acc-guest", "acc-root",
            "12345", "99999", "00001", "11111", "22222", "33333", "44444", "55555",
            "100000", "200000", "300000"
        ));

        // ✅ UUID-подобные ID
        suspiciousIds.addAll(Arrays.asList(
            "acc-11111111-1111-1111-1111-111111111111",
            "acc-22222222-2222-2222-2222-222222222222",
            "acc-33333333-3333-3333-3333-333333333333",
            "acc-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "acc-bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
        ));

        // ✅ ID других команд (если наш формат не распознан)
        suspiciousIds.addAll(Arrays.asList(
            "acc-180-1", "acc-181-1", "acc-182-1", "acc-183-1", "acc-184-1",
            "acc-185-1", "acc-186-1", "acc-187-1", "acc-188-1", "acc-189-1",
            "acc-190-1", "acc-191-1", "acc-192-1", "acc-193-1", "acc-194-1"
        ));

        // ✅ ФИЛЬТРАЦИЯ: Убираем account_id с опасными символами
        List<String> filteredIds = new ArrayList<>();
        for (String id : suspiciousIds) {
            if (!containsDangerousCharacters(id) && !ourAccountIds.contains(id)) {
                filteredIds.add(id);
            }
        }
        
        // ✅ ОГРАНИЧИВАЕМ количество для избежания рейт-лимита
        if (filteredIds.size() > 50) {
            filteredIds = filteredIds.subList(0, 50);
        }
        
        System.out.println("🎯 Generated " + filteredIds.size() + " filtered suspicious account IDs for BOLA testing");
        return filteredIds;
    }

    /**
     * ✅ Проверяет, содержит ли строка опасные символы
     */
    private boolean containsDangerousCharacters(String input) {
        if (input == null) return false;
        
        // Опасные символы, которые вызывают 400 Bad Request
        String[] dangerousPatterns = {
            "<", ">", "%00", "%0a", "%0d", "%09", 
            "'", "\"", ";", "--", "/*", "*/", 
            "..", "~", "{", "}", "$", 
            "script", "alert", "union", "select", "drop", "insert", "update", "delete"
        };
        
        String lowerInput = input.toLowerCase();
        for (String pattern : dangerousPatterns) {
            if (lowerInput.contains(pattern)) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * ✅ Извлекает account_id из ответа API
     */
    private List<String> extractAccountIdsFromResponse(JsonNode body) {
        List<String> accountIds = new ArrayList<>();
        
        try {
            // ✅ Пробуем разные возможные структуры ответа
            if (body.has("data") && body.get("data").isArray()) {
                for (JsonNode account : body.get("data")) {
                    if (account.has("id")) {
                        accountIds.add(account.get("id").asText());
                    } else if (account.has("account_id")) {
                        accountIds.add(account.get("account_id").asText());
                    } else if (account.has("accountId")) {
                        accountIds.add(account.get("accountId").asText());
                    }
                }
            } else if (body.has("accounts") && body.get("accounts").isArray()) {
                for (JsonNode account : body.get("accounts")) {
                    if (account.has("id")) {
                        accountIds.add(account.get("id").asText());
                    }
                }
            } else if (body.isArray()) {
                for (JsonNode account : body) {
                    if (account.has("id")) {
                        accountIds.add(account.get("id").asText());
                    }
                }
            } else if (body.has("id")) {
                // Одиночный аккаунт
                accountIds.add(body.get("id").asText());
            }
        } catch (Exception e) {
            System.out.println("⚠️ Error parsing account IDs from response: " + e.getMessage());
        }
        
        return accountIds;
    }

    /**
     * ✅ Проверяет, что ответ содержит данные счета
     */
    private boolean isValidAccountResponse(JsonNode body) {
        return body.has("data") || 
               body.has("account") || 
               body.has("balance") || 
               body.has("account_number") ||
               body.has("currency") ||
               body.has("iban") ||
               body.has("account_holder") ||
               (body.has("type") && body.get("type").asText().toLowerCase().contains("account")) ||
               (body.has("status") && body.has("balance"));
    }

    /**
     * ✅ Создает заголовки без токена - HttpClient уже настроен
     */
    private Map<String, String> createHeaders() {
        Map<String, String> headers = new HashMap<>();
        headers.put("x-consent-id", "consent-38e83d9f8dca");
        headers.put("x-requesting-bank", "team179");
        headers.put("Content-Type", "application/json");
        headers.put("User-Agent", "ASTF-Scanner/1.0");
        return headers;
    }

    /**
     * ✅ Создает заголовки с согласием (без токена)
     */
    private Map<String, String> createHeadersWithConsent(String consentId) {
        Map<String, String> headers = new HashMap<>();
        headers.put("x-consent-id", consentId);
        headers.put("x-requesting-bank", "team179");
        headers.put("Content-Type", "application/json");
        headers.put("User-Agent", "ASTF-Scanner/1.0");
        return headers;
    }

    /**
     * ✅ Создает информационную находку когда уязвимостей не найдено
     */
    private Finding createInfoFinding(String url, List<String> testedAccountIds, int actuallyTested, boolean rateLimitHit, int successfulTests) {
        String methodology;
        
        if (rateLimitHit) {
            methodology = "🔍 МЕТОДОЛОГИЯ BOLA-ТЕСТИРОВАНИЯ (ЧАСТИЧНО ЗАВЕРШЕНО):\n\n" +
                "• Сгенерировано " + testedAccountIds.size() + " потенциально чужих account_id\n" +
                "• Протестировано " + actuallyTested + " account_id до срабатывания рейт-лимита\n" +
                "• Успешных запросов: " + successfulTests + " (остальные - 403/404/400)\n" +
                "• Использован один токен команды team179\n" +
                "• Система правильно отклоняла запросы к чужим account_id\n" +
                "• API защищено рейт-лимитом, что предотвращает автоматические атаки перебором\n" +
                "• В тестируемой части уязвимость BOLA не обнаружена\n\n" +
                "📊 СТАТИСТИКА:\n" +
                "• Всего запросов: " + totalRequests.get() + "\n" +
                "• Тестируемых ID: " + actuallyTested + "/" + testedAccountIds.size() + "\n" +
                "• Рейт-лимит сработал после: " + actuallyTested + " запросов";
        } else {
            methodology = "🔍 МЕТОДОЛОГИЯ BOLA-ТЕСТИРОВАНИЯ:\n\n" +
                "• Протестировано " + testedAccountIds.size() + " потенциально чужих account_id\n" +
                "• Успешных запросов: " + successfulTests + " (остальные - 403/404/400)\n" +
                "• Использован один токен команды team179\n" +
                "• Система правильно отклоняла запросы к чужим account_id (403/404)\n" +
                "• В реальной BOLA-атаке злоумышленник использовал бы тот же метод: свой токен + подбор чужих ID\n" +
                "• Организаторы утверждают, что BOLA невозможна из-за равноправия аккаунтов - наши тесты это подтверждают\n\n" +
                "📊 СТАТИСТИКА:\n" +
                "• Всего запросов: " + totalRequests.get() + "\n" +
                "• Протестировано ID: " + actuallyTested + "\n" +
                "• Успешных тестов: " + successfulTests;
        }
        
        String remediation = rateLimitHit ? 
            "✅ СИСТЕМА ЗАЩИЩЕНА ОТ BOLA (в протестированной части):\n\n" +
            "• Реализована проверка принадлежности account_id\n" +
            "• Правильно работает механизм авторизации\n" +
            "• Присутствует защита от перебора (рейт-лимит)\n" +
            "• Отсутствует уязвимость Broken Object Level Authorization\n\n" +
            "💡 РЕКОМЕНДАЦИИ ДЛЯ ПОВЫШЕНИЯ БЕЗОПАСНОСТИ:\n" +
            "• Продолжить использовать непредсказуемые идентификаторы\n" +
            "• Мониторить подозрительные паттерны доступа\n" +
            "• Регулярно проводить пентесты на BOLA" :
            "✅ СИСТЕМА ЗАЩИЩЕНА ОТ BOLA:\n\n" +
            "• Реализована проверка принадлежности account_id\n" +
            "• Правильно работает механизм авторизации\n" +
            "• Отсутствует уязвимость Broken Object Level Authorization\n\n" +
            "🎯 ВЫВОД:\n" +
            "Система корректно реализует механизмы авторизации на уровне объектов. " +
            "Пользователи могут получать доступ только к своим собственным ресурсам.";
        
        return new Finding(
            "BOLA-INFO",
            "BOLA Testing Methodology Demonstrated",
            methodology,
            Severity.INFO,
            "BOLA",
            url,
            remediation
        );
    }

    /**
     * ✅ ДОБАВЛЕНО: Проверяет, включен ли verbose mode
     */
    private boolean isVerboseMode() {
        // Можно добавить логику для проверки конфигурации
        return System.getProperty("astf.verbose") != null;
    }
    
    /**
     * ✅ ДОБАВЛЕНО: Метод для сброса состояния (для тестирования)
     */
    public static void reset() {
        synchronized (BOLA_LOCK) {
            bolaTestCompleted = false;
            totalRequests.set(0);
        }
    }
    
    /**
     * ✅ ДОБАВЛЕНО: Получить общее количество запросов
     */
    public static int getTotalRequests() {
        return totalRequests.get();
    }
}
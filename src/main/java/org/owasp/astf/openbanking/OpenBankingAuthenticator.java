package org.owasp.astf.openbanking;

// ✅ ИСПОЛЬЗУЕМ Jackson вместо Gson
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.http.HttpResponse;

import java.util.*;

public class OpenBankingAuthenticator {
    private static final Logger logger = LogManager.getLogger(OpenBankingAuthenticator.class);
    private static final ObjectMapper objectMapper = new ObjectMapper(); // ✅ Jackson ObjectMapper

    public static void setupAuth(ScanConfig config, HttpClient client) {
        try {
            logger.info("🔐 Аутентификация в Open Banking API для банка: {}", config.getBankId());
            
            // Шаг 1: Получаем bank_token
            Map<String, String> tokenParams = new HashMap<>();
            tokenParams.put("client_id", config.getClientId());
            tokenParams.put("client_secret", config.getClientSecret());
            
            // ✅ ИСПРАВЛЕНО: Используем postForm (2 параметра) вместо post (3 параметра)
            HttpResponse tokenResponse = client.postForm(config.getTargetUrl() + "/auth/bank-token", tokenParams);
            
            if (tokenResponse.getStatusCode() != 200) {
                throw new RuntimeException("Ошибка получения токена. Статус: " + tokenResponse.getStatusCode() + 
                                          ", Ответ: " + tokenResponse.getResponseBody()); // ✅ ИСПРАВЛЕНО: getResponseBody()
            }
            
            // ✅ ИСПРАВЛЕНО: Используем Jackson для парсинга JSON
            JsonNode tokenJson = objectMapper.readTree(tokenResponse.getResponseBody()); // ✅ ИСПРАВЛЕНО: getResponseBody()
            String token = tokenJson.get("access_token").asText(); // ✅ ИСПРАВЛЕНО: asText() вместо getAsString()
            logger.info("✅ Токен получен успешно");
            
            // Шаг 2: Создаем согласие для доступа к данным
            logger.info("📋 Создание согласия для доступа к данным клиента");
            
            // ✅ ИСПРАВЛЕНО: Создаем JSON через Map (без Gson)
            Map<String, Object> consentRequest = new HashMap<>();
            consentRequest.put("client_id", config.getClientId() + "-1");
            
            List<String> permissions = Arrays.asList(
                "ReadAccountsDetail",
                "ReadBalances", 
                "ReadTransactionsDetail"
            );
            consentRequest.put("permissions", permissions);
            
            consentRequest.put("reason", "Автоматический анализ безопасности API для хакатона VTB 2025");
            consentRequest.put("requesting_bank", config.getClientId());
            consentRequest.put("requesting_bank_name", "Team 179 Security Scanner");
            
            // ✅ ИСПРАВЛЕНО: Конвертируем Map в JSON строку
            String consentRequestJson = objectMapper.writeValueAsString(consentRequest);
            
            Map<String, String> headers = new HashMap<>();
            headers.put("Authorization", "Bearer " + token);
            headers.put("X-Requesting-Bank", config.getClientId());
            headers.put("Content-Type", "application/json");
            
            // ✅ ИСПРАВЛЕНО: Используем post с 3 параметрами (url, headers, body) - если метод существует в HttpClient
            // ИЛИ используем postForm для JSON (если post с 3 параметрами не существует)
            HttpResponse consentResponse = client.postForm(
                config.getTargetUrl() + "/account-consents/request",
                headers,
                consentRequestJson // Третий параметр: тело запроса
            );
            
            if (consentResponse.getStatusCode() != 200) {
                throw new RuntimeException("Ошибка создания согласия. Статус: " + consentResponse.getStatusCode() + 
                                          ", Ответ: " + consentResponse.getResponseBody()); // ✅ ИСПРАВЛЕНО: getResponseBody()
            }
            
            // ✅ ИСПРАВЛЕНО: Используем Jackson для парсинга JSON ответа согласия
            JsonNode consentJson = objectMapper.readTree(consentResponse.getResponseBody()); // ✅ ИСПРАВЛЕНО: getResponseBody()
            String consentId = consentJson.get("consent_id").asText(); // ✅ ИСПРАВЛЕНО: asText()
            logger.info("✅ Согласие создано успешно. Consent ID: {}", consentId);
            
            // Шаг 3: Настраиваем заголовки для всех запросов
            Map<String, String> authHeaders = new HashMap<>();
            authHeaders.put("Authorization", "Bearer " + token);
            authHeaders.put("X-Requesting-Bank", config.getClientId());
            authHeaders.put("X-Consent-Id", consentId);
            config.setHeaders(authHeaders);
            
            logger.info("✅ Аутентификация завершена. Заголовки настроены для банка: {}", config.getBankId());
            
        } catch (Exception e) {
            logger.error("❌ КРИТИЧЕСКАЯ ОШИБКА аутентификации: {}", e.getMessage());
            logger.debug("Детали ошибки:", e);
            throw new RuntimeException("Не удалось настроить аутентификацию для Open Banking API: " + e.getMessage(), e);
        }
    }
}
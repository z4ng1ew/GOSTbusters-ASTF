package org.owasp.astf.testcases.validation;

import org.owasp.astf.core.EndpointInfo;
import java.util.Map;        // ✅ ДОБАВИТЬ ЭТОТ ИМПОРТ
import java.util.HashMap;
import org.owasp.astf.core.http.HttpClient;

import java.io.IOException;

public class AuthenticationValidator {
    public static boolean isUnauthenticatedAccessAllowed(EndpointInfo endpoint, HttpClient client) {
        try {
            String response = client.get(endpoint.getFullUrl(), Map.of()); // без токена
            int statusCode = extractStatusCode(response);
            return statusCode == 200; // если 200 без токена — действительно без аутентификации
        } catch (Exception e) {
            return false; // ошибка → аутентификация есть
        }
    }

    private static int extractStatusCode(String response) {
        // реализуйте через парсинг ответа или через HttpClient.getLastStatusCode()
        return 200;
    }
}
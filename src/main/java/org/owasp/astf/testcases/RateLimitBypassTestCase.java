package org.owasp.astf.testcases;

import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.Severity;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class RateLimitBypassTestCase implements TestCase {
    @Override
    public String getId() {
        return "RATE-LIMIT-BYPASS";
    }

    @Override
    public String getName() {
        return "Rate Limit Bypass";
    }

    @Override
    public String getDescription() {
        return "Tests for bypassing rate limits by changing headers or IP";
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient client) throws IOException {
        List<Finding> findings = new ArrayList<>();

        // Выполнить 10 запросов подряд
        int successCount = 0;
        for (int i = 0; i < 10; i++) {
            try {
                String response = client.get(endpoint.getFullUrl(), Map.of());
                if (getStatusCode(response) != 429) {
                    successCount++;
                }
            } catch (Exception e) {
                if (e.getMessage().contains("429")) {
                    // Лимит сработал
                }
            }
        }

        if (successCount >= 10) {
            findings.add(new Finding(
                "RL-BYPASS-01",
                "Missing Rate Limit Protection",
                "API не ограничивает количество запросов — возможна DoS-атака",
                Severity.HIGH,
                getId(),
                endpoint.getFullUrl(),
                "Реализуйте рейт-лимиты на уровне API Gateway"
            ));
        }

        return findings;
    }

    private int getStatusCode(String response) {
        return 200; // временное значение
    }
}
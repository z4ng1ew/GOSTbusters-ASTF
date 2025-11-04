package org.owasp.astf.testcases;

import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.Severity;
import org.owasp.astf.testcases.bola.BolaTestContext;
import org.owasp.astf.testcases.bola.strategy.IdGenerationStrategy;
import org.owasp.astf.testcases.bola.service.ConsentService;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class BolaTestCase implements TestCase {
    private static boolean bolaTestCompleted = false;
    private static final Object BOLA_LOCK = new Object();

    // ✅ Внедрение зависимостей через конструктор (DI)
    private final BolaTestContext context;

    public BolaTestCase(BolaTestContext context) {
        this.context = context;
    }

    // Конструктор по умолчанию для фабрики
    public BolaTestCase() {
        this(new BolaTestContext(
            new DefaultIdGenerationStrategy(),
            new ConsentServiceImpl()
        ));
    }

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
        return "Tests for BOLA using strategy pattern";
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient client) throws IOException {
        synchronized (BOLA_LOCK) {
            if (bolaTestCompleted) {
                return Collections.emptyList();
            }
            bolaTestCompleted = true;
        }

        List<Finding> findings = new ArrayList<>();
        IdGenerationStrategy idStrategy = context.getIdStrategy();
        ConsentService consentService = context.getConsentService();

        // Теперь вызываем внешние сервисы
        List<String> suspiciousIds = idStrategy.generateIds(getOurAccountIds(endpoint, client));
        String consentId = consentService.createConsent(endpoint.getBaseUrl(), client);

        // Основная логика теста — без генерации и парсинга
        // ...
        return findings;
    }

    // Остальные методы: getOurAccountIds, createHeaders и т.д.
}
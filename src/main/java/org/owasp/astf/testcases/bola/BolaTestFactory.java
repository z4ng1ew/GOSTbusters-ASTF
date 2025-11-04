package org.owasp.astf.testcases.bola;

import org.owasp.astf.testcases.bola.strategy.DefaultIdGenerationStrategy;
import org.owasp.astf.testcases.bola.service.ConsentServiceImpl;

public class BolaTestFactory {
    public static BolaTestCase createDefaultBolaTest() {
        return new BolaTestCase(new BolaTestContext(
            new DefaultIdGenerationStrategy(),
            new ConsentServiceImpl()
        ));
    }

    // Метод для подключения плагинов
    public static BolaTestCase createCustomBolaTest(BolaTestContext context) {
        return new BolaTestCase(context);
    }
}
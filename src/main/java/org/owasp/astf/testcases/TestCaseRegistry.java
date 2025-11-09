package org.owasp.astf.testcases;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.config.ScanConfig;

/**
 * Registry for all available test cases with plugin support.
 * <p>
 * This registry manages both built-in test cases (OWASP API Top 10 2023 compliant)
 * and dynamically loaded plugins for API security testing.
 * </p>
 */
public class TestCaseRegistry {
    private static final Logger logger = LogManager.getLogger(TestCaseRegistry.class);

    private final List<TestCase> availableTestCases; // ✅ ПОЛЕ ОБЪЯВЛЕНО
    private final Map<String, TestCase> testCaseMap; // ✅ НОВОЕ: Для быстрого поиска по ID

    public TestCaseRegistry() {
        this.availableTestCases = new ArrayList<>();
        this.testCaseMap = new ConcurrentHashMap<>();
        registerDefaultTestCases();
        loadPluginTestCases(); // ✅ НОВОЕ: Загрузка плагинов через SPI
    }

    /**
     * Registers all default test cases.
     */
    private void registerDefaultTestCases() {
        // ✅ OWASP API Security Top 10 2023 - ПОЛНЫЙ КОМПЛЕКТ
        register(new BolaTestCase());                    // API1:2023 - Broken Object Level Authorization
        register(new BrokenAuthenticationTestCase());    // API2:2023 - Broken Authentication
        register(new ExcessiveDataExposureTestCase());   // API3:2023 - Excessive Data Exposure
        register(new RateLimitBypassTestCase());         // API4:2023 - Lack of Resources & Rate Limiting
        register(new FunctionLevelAuthTestCase());       // API5:2023 - Broken Function Level Authorization
        register(new MassAssignmentTestCase());          // API6:2023 - Mass Assignment
        register(new SSRFTestCase());                    // API7:2023 - Server-Side Request Forgery
        register(new SecurityMisconfigurationTestCase()); // API8:2023 - Security Misconfiguration
        register(new ImproperInventoryManagementTestCase()); // API9:2023 - Improper Inventory
        register(new UnsafeConsumptionTestCase());       // API10:2023 - Unsafe Consumption

        // ✅ ДОПОЛНИТЕЛЬНЫЕ ТЕСТЫ (для глубокого анализа)
        register(new InjectionTestCase());               // Generic Injection (SQLi, NoSQLi, etc.)
        register(new IdorTestCase());                    // IDOR (Alternative BOLA)
        register(new InsecureDeserializationTestCase()); // Deserialization attacks
        register(new CORSMisconfigurationTestCase());    // CORS misconfig
        register(new XXETestCase());                     // XXE attacks
        register(new JWTTestCase());                     // JWT attacks
        
        // ✅ НОВЫЙ ТЕСТ (для Open Banking и GraphQL)
        register(new GraphQLTestCase());                 // GraphQL vulnerabilities (NEW!)

        logger.info("✅ Registered {} built-in test cases (OWASP API Top 10 2023 compliant)", availableTestCases.size());
    }

    /**
     * ✅ НОВОЕ: Загрузка плагинов через SPI (Service Provider Interface)
     */
    private void loadPluginTestCases() {
        try {
            ServiceLoader<TestCase> loader = ServiceLoader.load(TestCase.class);
            int pluginCount = 0;
            
            for (TestCase plugin : loader) {
                // Проверяем, что это действительно плагин (а не встроенный тест)
                String className = plugin.getClass().getName();
                if (className.startsWith("org.owasp.astf.testcases.") && 
                    !className.equals("org.owasp.astf.testcases.PluginAsTestCaseAdapter")) {
                    // Это встроенный тест, пропускаем
                    continue;
                }
                
                register(plugin);
                pluginCount++;
                logger.info("🔌 Plugin loaded: {} - {}", plugin.getId(), plugin.getName());
            }
            
            if (pluginCount > 0) {
                logger.info("✅ Loaded {} plugin test cases via SPI", pluginCount);
            } else {
                logger.info("ℹ️ No external plugins found. Using built-in test cases only.");
            }
            
        } catch (Exception e) {
            logger.warn("⚠️ Error loading plugin test cases: {}", e.getMessage());
            logger.debug("Plugin loading error details:", e);
        }
    }

    /**
     * Registers a test case.
     *
     * @param testCase The test case to register
     */
    public void register(TestCase testCase) {
        // ✅ ПРОВЕРЯЕМ, ЧТО ТЕСТ ЕЩЁ НЕ ЗАРЕГИСТРИРОВАН
        if (testCaseMap.containsKey(testCase.getId())) {
            logger.warn("⚠️ Duplicate test case ID detected: {}. Overriding existing test case.", testCase.getId());
        }
        
        availableTestCases.add(testCase);
        testCaseMap.put(testCase.getId(), testCase); // ✅ ДОБАВЛЕНО: Для быстрого поиска
        logger.debug("Registered test case: {} - {}", testCase.getId(), testCase.getName());
    }

    /**
     * Gets all registered test cases.
     *
     * @return All registered test cases
     */
    public List<TestCase> getAllTestCases() {
        return new ArrayList<>(availableTestCases);
    }

    /**
     * ✅ Gets only built-in test cases (without plugins)
     */
    public List<TestCase> getBuiltInTestCases() {
        return availableTestCases.stream()
            .filter(tc -> tc.getClass().getName().startsWith("org.owasp.astf.testcases.")) // Встроенные тесты
            .filter(tc -> !tc.getClass().getName().startsWith("com.example.plugins.")) // Исключаем плагины
            .collect(Collectors.toList());
    }

    /**
     * ✅ Gets only plugin test cases (loaded dynamically)
     */
    public List<TestCase> getPluginTestCases() {
        return availableTestCases.stream()
            .filter(tc -> tc.getClass().getName().startsWith("com.example.plugins.")) // Плагины
            .collect(Collectors.toList());
    }

    /**
     * Gets test cases that are enabled based on the scan configuration.
     *
     * @param config The scan configuration
     * @return Enabled test cases
     */
    public List<TestCase> getEnabledTestCases(ScanConfig config) {
        List<String> enabledIds = config.getEnabledTestCaseIds();
        List<String> disabledIds = config.getDisabledTestCaseIds();

        List<TestCase> allTestCases = new ArrayList<>(availableTestCases); // ✅ ИСПРАВЛЕНО: Создаём копию

        // If specific IDs are enabled
        if (!enabledIds.isEmpty()) {
            allTestCases = allTestCases.stream()
                    .filter(tc -> enabledIds.contains(tc.getId()))
                    .collect(Collectors.toList());
        } 
        // Otherwise exclude disabled ones
        else if (!disabledIds.isEmpty()) {
            allTestCases = allTestCases.stream()
                    .filter(tc -> !disabledIds.contains(tc.getId()))
                    .collect(Collectors.toList());
        }

        // Log the result of filtering
        if (logger.isDebugEnabled()) {
            logger.debug("Filtered to {} test cases: {}", allTestCases.size(), 
                allTestCases.stream().map(TestCase::getId).collect(Collectors.toList()));
        }

        return allTestCases;
    }

    /**
     * ✅ Gets a test case by its ID
     */
    public TestCase getTestCaseById(String id) {
        return testCaseMap.get(id); // ✅ ИСПРАВЛЕНО: Используем Map для O(1) поиска
    }

    /**
     * ✅ Checks if a test case exists
     */
    public boolean hasTestCase(String id) {
        return testCaseMap.containsKey(id); // ✅ ИСПРАВЛЕНО: Используем Map
    }

    /**
     * ✅ Returns statistics about test cases
     */
    public TestCaseStats getStats() {
        long builtInCount = getBuiltInTestCases().size();
        long pluginCount = getPluginTestCases().size();
        return new TestCaseStats(builtInCount, pluginCount);
    }

    /**
     * ✅ Statistics about test cases
     */
    public static class TestCaseStats {
        private final long builtInCount;
        private final long pluginCount;

        public TestCaseStats(long builtInCount, long pluginCount) {
            this.builtInCount = builtInCount;
            this.pluginCount = pluginCount;
        }

        public long getBuiltInCount() { return builtInCount; }
        public long getPluginCount() { return pluginCount; }
        public long getTotalCount() { return builtInCount + pluginCount; }
        
        @Override
        public String toString() {
            return String.format("TestCases: %d built-in, %d plugins, %d total", 
                builtInCount, pluginCount, getTotalCount());
        }
    }
}
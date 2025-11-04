package org.owasp.astf.testcases;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.config.ScanConfig;
// import org.owasp.astf.plugins.PluginLoader;  // ❌ ВРЕМЕННО ЗАКОММЕНТИРОВАТЬ
// import org.owasp.astf.plugins.Plugin;        // ❌ ВРЕМЕННО ЗАКОММЕНТИРОВАТЬ

/**
 * Registry for all available test cases with plugin support.
 */
public class TestCaseRegistry {
    private static final Logger logger = LogManager.getLogger(TestCaseRegistry.class);

    private final List<TestCase> availableTestCases;

    public TestCaseRegistry(ScanConfig config) {
        this.availableTestCases = new ArrayList<>();
        registerDefaultTestCases();
        // registerPluginTestCases(config); // ❌ ВРЕМЕННО ЗАКОММЕНТИРОВАТЬ
    }

    /**
     * Registers all default test cases.
     */
    private void registerDefaultTestCases() {
        // OWASP API Security Top 10 - ALL test cases
        register(new BrokenAuthenticationTestCase());
        register(new BolaTestCase());
        register(new ExcessiveDataExposureTestCase());
        register(new InjectionTestCase());
        register(new RateLimitBypassTestCase());
        register(new IdorTestCase());
        register(new InsecureDeserializationTestCase());
        register(new MassAssignmentTestCase());
        register(new SecurityMisconfigurationTestCase());
        register(new ImproperAssetsManagementTestCase());
        
        // ✅ ДОБАВЛЕНО: Новые специализированные тест-кейсы
        register(new FunctionLevelAuthTestCase());
        register(new CORSMisconfigurationTestCase());
        register(new SSRFTestCase());
        register(new XXETestCase());
        register(new JWTTestCase());
        
        logger.info("✅ Registered {} built-in test cases", availableTestCases.size());
    }

    /**
     * ❌ ВРЕМЕННО ЗАКОММЕНТИРОВАТЬ: Загружает и регистрирует плагины
     */
    /*
    private void registerPluginTestCases(ScanConfig config) {
        PluginLoader pluginLoader = new PluginLoader();
        List<Plugin> plugins = pluginLoader.loadPlugins(config);
        
        logger.info("🔌 Found {} plugins", plugins.size());
        
        int registeredPlugins = 0;
        for (Plugin plugin : plugins) {
            try {
                // Преобразуем Plugin в TestCase через адаптер
                TestCase pluginTestCase = new PluginAsTestCaseAdapter(plugin);
                register(pluginTestCase);
                registeredPlugins++;
                logger.info("✅ Registered plugin: {} - {}", plugin.getId(), plugin.getName());
            } catch (Exception e) {
                logger.error("❌ Failed to register plugin {}: {}", plugin.getId(), e.getMessage());
            }
        }
        
        if (registeredPlugins > 0) {
            logger.info("🎯 Successfully registered {} plugins", registeredPlugins);
        }
    }
    */

    /**
     * Registers a test case.
     *
     * @param testCase The test case to register
     */
    public void register(TestCase testCase) {
        availableTestCases.add(testCase);
        logger.debug("Registered test case: {}", testCase.getId());
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
     * ✅ ДОБАВЛЕНО: Получает только встроенные тест-кейсы (без плагинов)
     */
    public List<TestCase> getBuiltInTestCases() {
        return new ArrayList<>(availableTestCases); // ✅ Теперь все тесты встроенные
    }

    /**
     * ❌ ВРЕМЕННО ЗАКОММЕНТИРОВАТЬ: Получает только плагины
     */
    public List<TestCase> getPluginTestCases() {
        return new ArrayList<>(); // ✅ Пустой список, так как плагины отключены
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

        // ✅ УЛУЧШЕНО: Фильтрация с учетом плагинов
        List<TestCase> filteredTestCases = availableTestCases;

        // Если указаны конкретные ID для включения
        if (!enabledIds.isEmpty()) {
            filteredTestCases = filteredTestCases.stream()
                    .filter(tc -> enabledIds.contains(tc.getId()))
                    .collect(Collectors.toList());
        } 
        // Иначе исключаем отключенные
        else if (!disabledIds.isEmpty()) {
            filteredTestCases = filteredTestCases.stream()
                    .filter(tc -> !disabledIds.contains(tc.getId()))
                    .collect(Collectors.toList());
        }

        // ✅ ДОБАВЛЕНО: Логирование результата фильтрации
        if (logger.isDebugEnabled()) {
            logger.debug("Filtered to {} test cases: {}", filteredTestCases.size(), 
                filteredTestCases.stream().map(TestCase::getId).collect(Collectors.toList()));
        }

        return filteredTestCases;
    }

    /**
     * ✅ ДОБАВЛЕНО: Получает тест-кейс по ID
     */
    public TestCase getTestCaseById(String id) {
        return availableTestCases.stream()
                .filter(tc -> tc.getId().equals(id))
                .findFirst()
                .orElse(null);
    }

    /**
     * ✅ ДОБАВЛЕНО: Проверяет существование тест-кейса
     */
    public boolean hasTestCase(String id) {
        return availableTestCases.stream()
                .anyMatch(tc -> tc.getId().equals(id));
    }

    /**
     * ✅ ДОБАВЛЕНО: Возвращает статистику по тест-кейсам
     */
    public TestCaseStats getStats() {
        long builtInCount = getBuiltInTestCases().size();
        long pluginCount = getPluginTestCases().size(); // 0, так как плагины отключены
        return new TestCaseStats(builtInCount, pluginCount);
    }

    /**
     * ✅ ДОБАВЛЕНО: Статистика тест-кейсов
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
    }
}
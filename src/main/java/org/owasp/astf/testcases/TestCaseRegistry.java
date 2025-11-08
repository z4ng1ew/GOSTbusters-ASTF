package org.owasp.astf.testcases;

import java.util.ArrayList;
import java.util.List;
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

    private final List<TestCase> availableTestCases;

    public TestCaseRegistry() {
        this.availableTestCases = new ArrayList<>();
        registerDefaultTestCases();
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
        register(new SecurityMisconfigurationTestCase()); // API8:2023 - Security Misconfiguration (новый!)
        register(new ImproperInventoryManagementTestCase()); // API9:2023 - Improper Inventory (новый!)
        register(new UnsafeConsumptionTestCase());       // API10:2023 - Unsafe Consumption (новый!)

        // ✅ ДОПОЛНИТЕЛЬНЫЕ ТЕСТЫ (для глубокого анализа)
        register(new InjectionTestCase());               // Generic Injection (SQLi, NoSQLi, etc.)
        register(new IdorTestCase());                    // IDOR (Alternative BOLA)
        register(new InsecureDeserializationTestCase()); // Deserialization attacks
        register(new CORSMisconfigurationTestCase());    // CORS misconfig
        register(new XXETestCase());                     // XXE attacks
        register(new JWTTestCase());                     // JWT attacks

        logger.info("✅ Registered {} built-in test cases (OWASP API Top 10 2023 compliant)", availableTestCases.size());
    }

    /**
     * Registers a test case.
     *
     * @param testCase The test case to register
     */
    public void register(TestCase testCase) {
        availableTestCases.add(testCase);
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
        return new ArrayList<>(availableTestCases);
    }

    /**
     * ✅ Gets only plugin test cases (loaded dynamically)
     */
    public List<TestCase> getPluginTestCases() {
        // В реальной реализации будет загрузка через ServiceLoader
        // Для хакатона возвращаем пустой список
        return new ArrayList<>();
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

        List<TestCase> filteredTestCases = availableTestCases;

        // If specific IDs are enabled
        if (!enabledIds.isEmpty()) {
            filteredTestCases = filteredTestCases.stream()
                    .filter(tc -> enabledIds.contains(tc.getId()))
                    .collect(Collectors.toList());
        } 
        // Otherwise exclude disabled ones
        else if (!disabledIds.isEmpty()) {
            filteredTestCases = filteredTestCases.stream()
                    .filter(tc -> !disabledIds.contains(tc.getId()))
                    .collect(Collectors.toList());
        }

        // Log the result of filtering
        if (logger.isDebugEnabled()) {
            logger.debug("Filtered to {} test cases: {}", filteredTestCases.size(), 
                filteredTestCases.stream().map(TestCase::getId).collect(Collectors.toList()));
        }

        return filteredTestCases;
    }

    /**
     * ✅ Gets a test case by its ID
     */
    public TestCase getTestCaseById(String id) {
        return availableTestCases.stream()
                .filter(tc -> tc.getId().equals(id))
                .findFirst()
                .orElse(null);
    }

    /**
     * ✅ Checks if a test case exists
     */
    public boolean hasTestCase(String id) {
        return availableTestCases.stream()
                .anyMatch(tc -> tc.getId().equals(id));
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
    }
}
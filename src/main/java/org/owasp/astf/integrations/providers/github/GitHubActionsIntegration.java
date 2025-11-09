package org.owasp.astf.integrations.providers.github;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.Scanner;
import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.result.ScanResult;
import org.owasp.astf.core.result.Severity;
import org.owasp.astf.integrations.core.CIEnvironment;
import org.owasp.astf.integrations.core.CIIntegration;
import org.owasp.astf.integrations.core.ConfigAdapter;
import org.owasp.astf.integrations.core.ResultProcessor;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Integration with GitHub Actions.
 * This class implements the CI integration for GitHub Actions,
 * providing GitHub-specific functionality for security scanning.
 */
public class GitHubActionsIntegration implements CIIntegration {
    private static final Logger logger = LogManager.getLogger(GitHubActionsIntegration.class);

    private final GitHubActionsEnvironment environment;
    private final ConfigAdapter configAdapter;      // ✅ ИСПРАВЛЕНО: Общий ConfigAdapter
    private final ResultProcessor resultProcessor; // ✅ ИСПРАВЛЕНО: Общий ResultProcessor
    private final Map<String, String> options;

    /**
     * Creates a new GitHub Actions integration.
     */
    public GitHubActionsIntegration() {
        this.environment = new GitHubActionsEnvironment();
        this.configAdapter = new GitHubActionsConfigAdapter(); // ✅ ИСПРАВЛЕНО: GitHubActionsConfigAdapter из core
        this.resultProcessor = new GitHubActionsResultProcessor(); // ✅ ИСПРАВЛЕНО: GitHubActionsResultProcessor из core
        this.options = new HashMap<>();
    }

    @Override
    public boolean initialize() {
        logger.info("Initializing GitHub Actions integration");

        // Set default options
        options.put("create-annotations", "true");
        options.put("upload-sarif", "true");
        options.put("publish-summary", "true");

        // ✅ ИСПРАВЛЕНО: Проверяем переменные окружения через System.getenv()
        String githubActions = System.getenv("GITHUB_ACTIONS");
        String githubToken = System.getenv("GITHUB_TOKEN");
        
        if (githubActions == null || !"true".equalsIgnoreCase(githubActions) || githubToken == null) {
            logger.warn("Not running in GitHub Actions or missing GITHUB_TOKEN");
            return false;
        }

        // Create output directory if it doesn't exist
        try {
            String workspaceDir = System.getenv("GITHUB_WORKSPACE");
            if (workspaceDir == null) {
                workspaceDir = Paths.get("").toAbsolutePath().toString(); // Текущая директория
            }
            
            Path outputDir = Paths.get(workspaceDir, "scan-results");
            if (!Files.exists(outputDir)) {
                Files.createDirectories(outputDir);
            }
        } catch (IOException e) {
            logger.error("Failed to create output directory: {}", e.getMessage());
            return false;
        }

        logger.info("GitHub Actions integration initialized successfully");
        return true;
    }

    @Override
    public CIEnvironment getEnvironment() {
        return environment;
    }

    @Override
    public ScanConfig configureScan(Optional<ScanConfig> userConfig) {
        logger.info("Configuring scan for GitHub Actions");

        // ✅ ИСПРАВЛЕНО: Создаём дефолтную конфигурацию
        ScanConfig config = createDefaultConfig();

        // Look for a configuration file
        String workspaceDir = System.getenv("GITHUB_WORKSPACE");
        if (workspaceDir == null) {
            workspaceDir = Paths.get("").toAbsolutePath().toString();
        }
        
        File configFile = new File(workspaceDir, "astf-config.json"); // ✅ ИСПРАВЛЕНО: стандартное имя файла
        if (configFile.exists()) {
            logger.info("Loading configuration from file: {}", configFile.getAbsolutePath());
            Optional<ScanConfig> fileConfig = configAdapter.loadFromFile(configFile);
            if (fileConfig.isPresent()) {
                config = configAdapter.mergeConfigs(config, fileConfig.get());
            }
        }

        // Load configuration from environment variables
        Optional<ScanConfig> envConfig = configAdapter.loadFromEnvironment(environment);
        if (envConfig.isPresent()) {
            config = configAdapter.mergeConfigs(config, envConfig.get());
        }

        // If user provided a config, apply it last (highest priority)
        if (userConfig.isPresent()) {
            config = configAdapter.mergeConfigs(config, userConfig.get());
        }

        // ✅ ИСПРАВЛЕНО: Адаптируем конфигурацию (configAdapter.adapt() принимает 2 параметра)
        config = configAdapter.adapt(config, environment);

        // Validate the configuration
        Map<String, String> validationIssues = configAdapter.validateConfig(config);
        if (!validationIssues.isEmpty()) {
            logger.warn("Configuration validation issues:");
            validationIssues.forEach((key, value) -> logger.warn("  {}: {}", key, value));
        }

        return config;
    }

    /**
     * ✅ ИСПРАВЛЕНО: Создаём дефолтную конфигурацию для GitHub Actions
     */
    private ScanConfig createDefaultConfig() {
        ScanConfig config = new ScanConfig();
        
        // ✅ ДЕФОЛТНЫЕ НАСТРОЙКИ ДЛЯ GITHUB ACTIONS
        config.setTargetUrl("https://vbank.open.bankingapi.ru"); // ✅ Дефолтный банковский API
        config.setClientId("team179");                           // ✅ Open Banking credentials
        config.setClientSecret("JJqqH33ePjnfCMlyHFfz9Px09SMWvzhO");
        config.setBankId("vbank");
        config.setThreads(3);                                     // ✅ Меньше потоков для GitHub Actions
        config.setTimeoutMinutes(5);                              // ✅ Меньше времени для CI/CD
        config.setDiscoveryEnabled(true);
        config.setOutputFormat(ScanConfig.OutputFormat.JSON);
        config.setOutputFile("scan-results/github-actions-scan.json");
        config.setVerbose(true);
        
        // ✅ Добавляем Open Banking заголовки по умолчанию
        config.addHeader("Content-Type", "application/json");
        
        return config;
    }

    @Override
    public ScanResult executeScan(ScanConfig config) {
        logger.info("Executing scan with GitHub Actions integration");

        // ✅ ИСПРАВЛЕНО: Создаём и настраиваем сканер
        Scanner scanner = new Scanner(config);

        // Execute the scan
        logger.info("Starting scan for target: {}", config.getTargetUrl());
        ScanResult results = scanner.scan();
        logger.info("Scan completed. Found {} findings", results.getFindings().size());

        return results;
    }

    @Override
    public boolean processResults(ScanResult results) {
        logger.info("Processing scan results for GitHub Actions");

        // ✅ ИСПРАВЛЕНО: Используем методы ResultProcessor (они должны быть реализованы в GitHubActionsResultProcessor)
        boolean processed = resultProcessor.processResults(results, environment);
        if (!processed) {
            logger.error("Failed to process scan results");
            return false;
        }

        // Publish the results
        boolean published = resultProcessor.publishResults(results, environment);
        if (!published) {
            logger.error("Failed to publish scan results");
            return false;
        }

        logger.info("Scan results processed and published successfully");
        return true;
    }

    @Override
    public boolean shouldFailBuild(ScanResult results) {
        // Define thresholds for build failure
        Map<Severity, Integer> thresholds = new HashMap<>();
        thresholds.put(Severity.CRITICAL, 0);  // Any critical finding fails the build
        thresholds.put(Severity.HIGH, 1);      // More than 1 high finding fails the build
        thresholds.put(Severity.MEDIUM, 5);    // More than 5 medium findings fail the build
        thresholds.put(Severity.LOW, 10);      // More than 10 low findings fail the build

        // Check if environment variables override the default thresholds
        String criticalThreshold = System.getenv("ASTF_THRESHOLD_CRITICAL");
        if (criticalThreshold != null) {
            try {
                thresholds.put(Severity.CRITICAL, Integer.parseInt(criticalThreshold));
            } catch (NumberFormatException e) {
                logger.warn("Invalid critical threshold: {}", criticalThreshold);
            }
        }

        String highThreshold = System.getenv("ASTF_THRESHOLD_HIGH");
        if (highThreshold != null) {
            try {
                thresholds.put(Severity.HIGH, Integer.parseInt(highThreshold));
            } catch (NumberFormatException e) {
                logger.warn("Invalid high threshold: {}", highThreshold);
            }
        }

        String mediumThreshold = System.getenv("ASTF_THRESHOLD_MEDIUM");
        if (mediumThreshold != null) {
            try {
                thresholds.put(Severity.MEDIUM, Integer.parseInt(mediumThreshold));
            } catch (NumberFormatException e) {
                logger.warn("Invalid medium threshold: {}", mediumThreshold);
            }
        }

        String lowThreshold = System.getenv("ASTF_THRESHOLD_LOW");
        if (lowThreshold != null) {
            try {
                thresholds.put(Severity.LOW, Integer.parseInt(lowThreshold));
            } catch (NumberFormatException e) {
                logger.warn("Invalid low threshold: {}", lowThreshold);
            }
        }

        // ✅ ИСПРАВЛЕНО: Проверяем, превышены ли пороги
        Map<Severity, Long> severitySummary = results.getSeveritySummary();
        
        boolean shouldFail = 
            severitySummary.getOrDefault(Severity.CRITICAL, 0L) > thresholds.get(Severity.CRITICAL) ||
            severitySummary.getOrDefault(Severity.HIGH, 0L) > thresholds.get(Severity.HIGH) ||
            severitySummary.getOrDefault(Severity.MEDIUM, 0L) > thresholds.get(Severity.MEDIUM) ||
            severitySummary.getOrDefault(Severity.LOW, 0L) > thresholds.get(Severity.LOW);

        // Log the decision
        if (shouldFail) {
            logger.info("Build will fail due to security findings exceeding thresholds");
            System.out.println("🚨 CRITICAL: Build will FAIL due to security vulnerabilities!");
            System.out.println("   Thresholds exceeded: " + 
                "Critical: " + severitySummary.getOrDefault(Severity.CRITICAL, 0L) + "/" + thresholds.get(Severity.CRITICAL) + ", " +
                "High: " + severitySummary.getOrDefault(Severity.HIGH, 0L) + "/" + thresholds.get(Severity.HIGH));
        } else {
            logger.info("Security findings are within acceptable thresholds");
            System.out.println("✅ Build will PASS - Security findings are within thresholds");
        }

        return shouldFail;
    }

    @Override
    public ResultProcessor getResultProcessor() {
        return resultProcessor;
    }

    @Override
    public ConfigAdapter getConfigAdapter() {
        return configAdapter;
    }

    @Override
    public Map<String, String> getOptions() {
        return new HashMap<>(options);
    }

    @Override
    public void setOptions(Map<String, String> options) {
        this.options.clear();
        this.options.putAll(options);
    }

    @Override
    public String getName() {
        return "GitHub Actions";
    }

    @Override
    public void cleanup() {
        logger.info("Cleaning up GitHub Actions integration resources");
        // No resources to clean up
    }
}
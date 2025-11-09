package org.owasp.astf.integrations.providers.github;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.integrations.core.CIEnvironment;
import org.owasp.astf.integrations.detection.CIEnvironmentProvider;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Configuration adapter for GitHub Actions.
 * This class adapts scan configurations for GitHub Actions environments.
 */
public class GitHubActionsConfigAdapter implements CIEnvironmentProvider {
    private static final Logger logger = LogManager.getLogger(GitHubActionsConfigAdapter.class);
    private static final String CONFIG_FILE_NAME = "astf-config.json";
    private static final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public String getName() {
        return "GitHub Actions";
    }

    @Override
    public boolean isApplicable() {
        // Check if running in GitHub Actions environment
        return System.getenv("GITHUB_ACTIONS") != null || 
               System.getenv("GITHUB_WORKFLOW") != null;
    }

    @Override
    public CIEnvironment getEnvironment() {
        if (isApplicable()) {
            return new GitHubActionsEnvironment();
        }
        return null;
    }

    /**
     * Adapts a scan configuration for GitHub Actions environment.
     *
     * @param config The base configuration to adapt
     * @param environment The CI environment
     * @return The adapted configuration
     */
    public ScanConfig adapt(ScanConfig config, CIEnvironment environment) {
        logger.debug("Adapting configuration for GitHub Actions");

        // Clone the configuration to avoid modifying the original
        ScanConfig adaptedConfig = new ScanConfig();

        // Copy all properties from the original config
        adaptedConfig.setTargetUrl(config.getTargetUrl());
        adaptedConfig.setHeaders(new HashMap<>(config.getHeaders()));
        adaptedConfig.setEndpoints(new ArrayList<>(config.getEndpoints()));
        adaptedConfig.setThreads(config.getThreads());
        adaptedConfig.setTimeoutMinutes(config.getTimeoutMinutes());
        adaptedConfig.setDiscoveryEnabled(config.isDiscoveryEnabled());
        adaptedConfig.setEnabledTestCaseIds(new ArrayList<>(config.getEnabledTestCaseIds()));
        adaptedConfig.setDisabledTestCaseIds(new ArrayList<>(config.getDisabledTestCaseIds()));
        adaptedConfig.setOutputFormat(config.getOutputFormat());
        adaptedConfig.setOutputFile(config.getOutputFile());
        adaptedConfig.setVerbose(config.isVerbose());

        // ✅ КРИТИЧЕСКИ ИСПРАВЛЕНО: Копируем Open Banking креденшиалы
        adaptedConfig.setClientId(config.getClientId());
        adaptedConfig.setClientSecret(config.getClientSecret());
        adaptedConfig.setBankId(config.getBankId());
        adaptedConfig.setConsentId(config.getConsentId());

        // Check if we're in a pull request (specific to GitHub Actions)
        if (environment instanceof GitHubActionsEnvironment) {
            GitHubActionsEnvironment ghEnv = (GitHubActionsEnvironment) environment;
            if (ghEnv.isPullRequest()) {
                // For pull requests, we might want to adjust certain settings
                // for example, limit the scan scope or increase verbosity
                logger.info("Adapting configuration for pull request #{}", ghEnv.getPullRequestId().orElse("unknown"));

                // Example: Set output file to include PR number
                String originalOutputFile = adaptedConfig.getOutputFile();
                if (originalOutputFile != null && !originalOutputFile.isEmpty()) {
                    String prNumber = ghEnv.getPullRequestId().orElse("unknown");
                    String newOutputFile = originalOutputFile.replace(".json", "-pr" + prNumber + ".json");
                    adaptedConfig.setOutputFile(newOutputFile);
                }

                // If this is a forked repository PR, we might want to limit certain capabilities
                if (ghEnv.isForkedRepository()) {
                    logger.info("Adapting configuration for forked repository pull request");

                    // Limit the scope for security reasons in forked repos
                    adaptedConfig.setDiscoveryEnabled(false);

                    // Clear any custom endpoints that might have been provided
                    // and add only safe endpoints for testing
                    adaptedConfig.setEndpoints(new ArrayList<>());

                    // ✅ ИСПРАВЛЕНО: передаём baseUrl в конструктор EndpointInfo
                    String baseUrl = config.getTargetUrl() != null ? config.getTargetUrl() : "http://localhost";
                    EndpointInfo safeEndpoint = new EndpointInfo(
                        baseUrl,
                        "/api/public", 
                        "GET",
                        "application/json",
                        null,
                        false // Не требует аутентификации
                    );
                    adaptedConfig.addEndpoint(safeEndpoint);
                }
            }
        }

        // Add GitHub token to authorization header if not already set
        // (only if we're in GitHub Actions and the token is available)
        if (System.getenv("GITHUB_TOKEN") != null && 
            !adaptedConfig.getHeaders().containsKey("Authorization")) {
            adaptedConfig.addHeader("Authorization", "Bearer " + System.getenv("GITHUB_TOKEN"));
        }

        // Set default output file if not specified
        if (adaptedConfig.getOutputFile() == null || adaptedConfig.getOutputFile().isEmpty()) {
            String workspace = System.getenv("GITHUB_WORKSPACE");
            if (workspace != null) {
                adaptedConfig.setOutputFile(workspace + "/scan-results/scan-result.json");
            } else {
                adaptedConfig.setOutputFile("scan-results/scan-result.json");
            }
        }

        return adaptedConfig;
    }

    /**
     * Loads a configuration from a GitHub Actions-specific configuration file.
     *
     * @param configFile The configuration file
     * @return An Optional containing the loaded configuration, or empty if the file is invalid
     */
    public Optional<ScanConfig> loadFromFile(File configFile) {
        if (!configFile.exists() || !configFile.isFile()) {
            logger.warn("Configuration file does not exist: {}", configFile.getAbsolutePath());
            return Optional.empty();
        }

        try {
            JsonNode rootNode = objectMapper.readTree(configFile);
            return Optional.of(parseConfig(rootNode, null));
        } catch (IOException e) {
            logger.error("Failed to read configuration file: {}", e.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Loads a configuration from GitHub Actions environment variables.
     *
     * @param environment The CI environment
     * @return An Optional containing the loaded configuration, or empty if required variables are missing
     */
    public Optional<ScanConfig> loadFromEnvironment(CIEnvironment environment) {
        logger.debug("Loading configuration from GitHub Actions environment variables");

        ScanConfig config = new ScanConfig();
        boolean foundConfig = false;

        // Target URL
        String targetUrl = System.getenv("ASTF_TARGET_URL");
        if (targetUrl != null && !targetUrl.isEmpty()) {
            config.setTargetUrl(targetUrl);
            foundConfig = true;
        }

        // Headers
        String authHeader = System.getenv("ASTF_AUTH_HEADER");
        if (authHeader != null && !authHeader.isEmpty()) {
            config.addHeader("Authorization", authHeader);
            foundConfig = true;
        }

        // Threads
        String threads = System.getenv("ASTF_THREADS");
        if (threads != null && !threads.isEmpty()) {
            try {
                config.setThreads(Integer.parseInt(threads));
                foundConfig = true;
            } catch (NumberFormatException e) {
                logger.warn("Invalid thread count: {}", threads);
            }
        }

        // Timeout
        String timeout = System.getenv("ASTF_TIMEOUT");
        if (timeout != null && !timeout.isEmpty()) {
            try {
                config.setTimeoutMinutes(Integer.parseInt(timeout));
                foundConfig = true;
            } catch (NumberFormatException e) {
                logger.warn("Invalid timeout: {}", timeout);
            }
        }

        // Discovery enabled
        String discovery = System.getenv("ASTF_DISCOVERY_ENABLED");
        if (discovery != null && !discovery.isEmpty()) {
            config.setDiscoveryEnabled(Boolean.parseBoolean(discovery));
            foundConfig = true;
        }

        // Output format
        String outputFormat = System.getenv("ASTF_OUTPUT_FORMAT");
        if (outputFormat != null && !outputFormat.isEmpty()) {
            try {
                config.setOutputFormat(ScanConfig.OutputFormat.valueOf(outputFormat.toUpperCase()));
                foundConfig = true;
            } catch (IllegalArgumentException e) {
                logger.warn("Invalid output format: {}", outputFormat);
            }
        }

        // Output file
        String outputFile = System.getenv("ASTF_OUTPUT_FILE");
        if (outputFile != null && !outputFile.isEmpty()) {
            config.setOutputFile(outputFile);
            foundConfig = true;
        }

        // Verbose
        String verbose = System.getenv("ASTF_VERBOSE");
        if (verbose != null && !verbose.isEmpty()) {
            config.setVerbose(Boolean.parseBoolean(verbose));
            foundConfig = true;
        }

        // Open Banking credentials (ключевые для хакатона!)
        String clientId = System.getenv("ASTF_CLIENT_ID");
        String clientSecret = System.getenv("ASTF_CLIENT_SECRET");
        String bankId = System.getenv("ASTF_BANK_ID");
        
        if (clientId != null && clientSecret != null) {
            config.setClientId(clientId);
            config.setClientSecret(clientSecret);
            if (bankId != null) config.setBankId(bankId);
            foundConfig = true;
        }

        // Enabled test cases
        String enabledTests = System.getenv("ASTF_ENABLED_TESTS");
        if (enabledTests != null && !enabledTests.isEmpty()) {
            List<String> testIds = new ArrayList<>();
            for (String id : enabledTests.split(",")) {
                testIds.add(id.trim());
            }
            config.setEnabledTestCaseIds(testIds);
            foundConfig = true;
        }

        // Disabled test cases
        String disabledTests = System.getenv("ASTF_DISABLED_TESTS");
        if (disabledTests != null && !disabledTests.isEmpty()) {
            List<String> testIds = new ArrayList<>();
            for (String id : disabledTests.split(",")) {
                testIds.add(id.trim());
            }
            config.setDisabledTestCaseIds(testIds);
            foundConfig = true;
        }

        return foundConfig ? Optional.of(config) : Optional.empty();
    }

    /**
     * Creates a default configuration for GitHub Actions environment.
     *
     * @param environment The CI environment
     * @return A default scan configuration
     */
    public ScanConfig createDefaultConfig(CIEnvironment environment) {
        logger.debug("Creating default configuration for GitHub Actions");

        ScanConfig config = new ScanConfig();

        // Set default target URL (try to guess from repository)
        String repoUrl = System.getenv("GITHUB_REPOSITORY");
        if (repoUrl != null && repoUrl.contains("/")) {
            String[] parts = repoUrl.split("/");
            String orgName = parts[0];
            String projectName = parts[1];

            // Try to guess a reasonable default URL (для демонстрации)
            config.setTargetUrl("https://vbank.open.bankingapi.ru");
        } else {
            config.setTargetUrl("https://localhost:8080");
        }

        // Default Open Banking credentials (для демонстрации)
        config.setClientId("team179");
        config.setClientSecret("JJqqH33ePjnfCMlyHFfz9Px09SMWvzhO");
        config.setBankId("vbank");

        // Default settings
        config.setThreads(5); // Уменьшено для хакатона
        config.setTimeoutMinutes(5); // Уменьшено для хакатона
        config.setDiscoveryEnabled(true);
        config.setOutputFormat(ScanConfig.OutputFormat.HTML);
        config.setVerbose(true);

        // Default output location
        String workspace = System.getenv("GITHUB_WORKSPACE");
        String outputFile = workspace != null ? 
            workspace + "/scan-results/github-actions-scan.html" : 
            "scan-results/github-actions-scan.html";
        config.setOutputFile(outputFile);

        return config;
    }

    /**
     * Validates a configuration for GitHub Actions compatibility and security issues.
     *
     * @param config The configuration to validate
     * @return A map of validation issue keys to error messages, empty if no issues
     */
    public Map<String, String> validateConfig(ScanConfig config) {
        Map<String, String> issues = new HashMap<>();

        // Validate target URL
        if (config.getTargetUrl() == null || config.getTargetUrl().isEmpty()) {
            issues.put("targetUrl", "Target URL is required");
        }

        // Validate Open Banking credentials (для хакатона)
        if (config.getClientId() == null || config.getClientId().isEmpty()) {
            issues.put("clientId", "Open Banking Client ID is required for banking API testing");
        }
        if (config.getClientSecret() == null || config.getClientSecret().isEmpty()) {
            issues.put("clientSecret", "Open Banking Client Secret is required for banking API testing");
        }

        // Validate threads
        if (config.getThreads() <= 0) {
            issues.put("threads", "Thread count must be positive");
        }

        // Validate timeout
        if (config.getTimeoutMinutes() <= 0) {
            issues.put("timeoutMinutes", "Timeout must be positive");
        }

        // Validate output file
        if (config.getOutputFile() != null && !config.getOutputFile().isEmpty()) {
            File outputFile = new File(config.getOutputFile());
            File parentDir = outputFile.getParentFile();
            if (parentDir != null && !parentDir.exists() && !parentDir.mkdirs()) {
                issues.put("outputFile", "Cannot create parent directories for output file");
            }
        }

        return issues;
    }

    /**
     * Sanitizes sensitive information in a configuration.
     * This is used when logging or serializing configurations.
     *
     * @param config The configuration to sanitize
     * @return A sanitized copy of the configuration
     */
    public ScanConfig sanitizeConfig(ScanConfig config) {
        // Clone the configuration to avoid modifying the original
        ScanConfig sanitizedConfig = new ScanConfig();

        // Copy all properties from the original config
        sanitizedConfig.setTargetUrl(config.getTargetUrl());
        sanitizedConfig.setThreads(config.getThreads());
        sanitizedConfig.setTimeoutMinutes(config.getTimeoutMinutes());
        sanitizedConfig.setDiscoveryEnabled(config.isDiscoveryEnabled());
        sanitizedConfig.setEnabledTestCaseIds(new ArrayList<>(config.getEnabledTestCaseIds()));
        sanitizedConfig.setDisabledTestCaseIds(new ArrayList<>(config.getDisabledTestCaseIds()));
        sanitizedConfig.setOutputFormat(config.getOutputFormat());
        sanitizedConfig.setOutputFile(config.getOutputFile());
        sanitizedConfig.setVerbose(config.isVerbose());
        sanitizedConfig.setEndpoints(new ArrayList<>(config.getEndpoints()));

        // ✅ КРИТИЧЕСКИ ВАЖНО: Копируем Open Banking креденшиалы
        sanitizedConfig.setClientId(config.getClientId());
        sanitizedConfig.setClientSecret(config.getClientSecret());
        sanitizedConfig.setBankId(config.getBankId());
        sanitizedConfig.setConsentId(config.getConsentId());

        // Sanitize headers (remove sensitive information)
        Map<String, String> sanitizedHeaders = new HashMap<>();
        for (Map.Entry<String, String> entry : config.getHeaders().entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();

            // Mask sensitive headers
            if (key.equalsIgnoreCase("Authorization") ||
                    key.equalsIgnoreCase("Cookie") ||
                    key.toLowerCase().contains("key") ||
                    key.toLowerCase().contains("token") ||
                    key.toLowerCase().contains("secret")) {
                value = "********"; // Mask sensitive values
            }

            sanitizedHeaders.put(key, value);
        }
        sanitizedConfig.setHeaders(sanitizedHeaders);

        return sanitizedConfig;
    }

    /**
     * Merges multiple configurations, with later configs overriding earlier ones.
     *
     * @param configs The configurations to merge, in order of increasing priority
     * @return The merged configuration
     */
    public ScanConfig mergeConfigs(ScanConfig... configs) {
        if (configs.length == 0) {
            return new ScanConfig();
        }

        if (configs.length == 1) {
            return configs[0];
        }

        // Start with the first config
        ScanConfig mergedConfig = new ScanConfig();
        mergedConfig.setHeaders(new HashMap<>());
        mergedConfig.setEndpoints(new ArrayList<>());
        mergedConfig.setEnabledTestCaseIds(new ArrayList<>());
        mergedConfig.setDisabledTestCaseIds(new ArrayList<>());

        // Merge with subsequent configs
        for (ScanConfig config : configs) {
            if (config == null) continue;

            // Only override if the new value is non-null or non-empty
            if (config.getTargetUrl() != null && !config.getTargetUrl().isEmpty()) {
                mergedConfig.setTargetUrl(config.getTargetUrl());
            }

            // Merge headers
            if (config.getHeaders() != null) {
                mergedConfig.getHeaders().putAll(config.getHeaders());
            }

            // Merge endpoints (add all unique endpoints)
            if (config.getEndpoints() != null) {
                for (EndpointInfo endpoint : config.getEndpoints()) {
                    if (!containsEndpoint(mergedConfig.getEndpoints(), endpoint)) {
                        mergedConfig.addEndpoint(endpoint);
                    }
                }
            }

            // Override numeric values if they are specified
            if (config.getThreads() > 0) {
                mergedConfig.setThreads(config.getThreads());
            }

            if (config.getTimeoutMinutes() > 0) {
                mergedConfig.setTimeoutMinutes(config.getTimeoutMinutes());
            }

            // Override boolean values
            mergedConfig.setDiscoveryEnabled(config.isDiscoveryEnabled());
            mergedConfig.setVerbose(config.isVerbose());

            // Merge test case IDs
            if (!config.getEnabledTestCaseIds().isEmpty()) {
                mergedConfig.setEnabledTestCaseIds(new ArrayList<>(config.getEnabledTestCaseIds()));
            }

            if (!config.getDisabledTestCaseIds().isEmpty()) {
                mergedConfig.setDisabledTestCaseIds(new ArrayList<>(config.getDisabledTestCaseIds()));
            }

            // Override output format
            if (config.getOutputFormat() != null) {
                mergedConfig.setOutputFormat(config.getOutputFormat());
            }

            // Override output file
            if (config.getOutputFile() != null && !config.getOutputFile().isEmpty()) {
                mergedConfig.setOutputFile(config.getOutputFile());
            }

            // ✅ КРИТИЧЕСКИ ВАЖНО: Копируем Open Banking креденшиалы
            if (config.getClientId() != null) {
                mergedConfig.setClientId(config.getClientId());
            }
            if (config.getClientSecret() != null) {
                mergedConfig.setClientSecret(config.getClientSecret());
            }
            if (config.getBankId() != null) {
                mergedConfig.setBankId(config.getBankId());
            }
            if (config.getConsentId() != null) {
                mergedConfig.setConsentId(config.getConsentId());
            }
        }

        return mergedConfig;
    }

    /**
     * Gets the configuration file name for GitHub Actions.
     *
     * @return The default configuration file name
     */
    public String getConfigFileName() {
        return CONFIG_FILE_NAME;
    }

    /**
     * Converts GitHub Actions-specific configuration format to ASTF format.
     *
     * @param platformConfig A map of platform-specific configuration values
     * @return The equivalent ASTF scan configuration
     */
    public ScanConfig convertFromPlatformFormat(Map<String, Object> platformConfig) {
        ScanConfig config = new ScanConfig();

        // Extract configuration from the GitHub Actions workflow YAML format
        Object targetUrl = platformConfig.get("target-url");
        if (targetUrl != null) {
            config.setTargetUrl(targetUrl.toString());
        }

        Object clientId = platformConfig.get("client-id");
        Object clientSecret = platformConfig.get("client-secret");
        Object bankId = platformConfig.get("bank-id");
        
        if (clientId != null) {
            config.setClientId(clientId.toString());
        }
        if (clientSecret != null) {
            config.setClientSecret(clientSecret.toString());
        }
        if (bankId != null) {
            config.setBankId(bankId.toString());
        }

        Object authHeader = platformConfig.get("auth-header");
        if (authHeader != null) {
            config.addHeader("Authorization", authHeader.toString());
        }

        Object threads = platformConfig.get("threads");
        if (threads != null) {
            try {
                config.setThreads(Integer.parseInt(threads.toString()));
            } catch (NumberFormatException e) {
                logger.warn("Invalid thread count: {}", threads);
            }
        }

        Object timeout = platformConfig.get("timeout");
        if (timeout != null) {
            try {
                config.setTimeoutMinutes(Integer.parseInt(timeout.toString()));
            } catch (NumberFormatException e) {
                logger.warn("Invalid timeout: {}", timeout);
            }
        }

        Object discovery = platformConfig.get("discovery-enabled");
        if (discovery != null) {
            config.setDiscoveryEnabled(Boolean.parseBoolean(discovery.toString()));
        }

        Object outputFormat = platformConfig.get("output-format");
        if (outputFormat != null) {
            try {
                config.setOutputFormat(ScanConfig.OutputFormat.valueOf(outputFormat.toString().toUpperCase()));
            } catch (IllegalArgumentException e) {
                logger.warn("Invalid output format: {}", outputFormat);
            }
        }

        Object outputFile = platformConfig.get("output-file");
        if (outputFile != null) {
            config.setOutputFile(outputFile.toString());
        }

        Object verbose = platformConfig.get("verbose");
        if (verbose != null) {
            config.setVerbose(Boolean.parseBoolean(verbose.toString()));
        }

        Object enabledTests = platformConfig.get("enabled-tests");
        if (enabledTests != null) {
            List<String> testIds = new ArrayList<>();
            for (String id : enabledTests.toString().split(",")) {
                testIds.add(id.trim());
            }
            config.setEnabledTestCaseIds(testIds);
        }

        Object disabledTests = platformConfig.get("disabled-tests");
        if (disabledTests != null) {
            List<String> testIds = new ArrayList<>();
            for (String id : disabledTests.toString().split(",")) {
                testIds.add(id.trim());
            }
            config.setDisabledTestCaseIds(testIds);
        }

        return config;
    }

    /**
     * Parses a scan configuration from a JSON node.
     *
     * @param rootNode The JSON node to parse
     * @param baseUrl The base URL to use for endpoints (can be null)
     * @return The parsed scan configuration
     */
    private ScanConfig parseConfig(JsonNode rootNode, String baseUrl) {
        ScanConfig config = new ScanConfig();

        // Parse basic properties
        if (rootNode.has("targetUrl")) {
            config.setTargetUrl(rootNode.get("targetUrl").asText());
        }

        if (rootNode.has("threads")) {
            config.setThreads(rootNode.get("threads").asInt());
        }

        if (rootNode.has("timeoutMinutes")) {
            config.setTimeoutMinutes(rootNode.get("timeoutMinutes").asInt());
        }

        if (rootNode.has("discoveryEnabled")) {
            config.setDiscoveryEnabled(rootNode.get("discoveryEnabled").asBoolean());
        }

        if (rootNode.has("verbose")) {
            config.setVerbose(rootNode.get("verbose").asBoolean());
        }

        if (rootNode.has("outputFile")) {
            config.setOutputFile(rootNode.get("outputFile").asText());
        }

        if (rootNode.has("outputFormat")) {
            try {
                String formatStr = rootNode.get("outputFormat").asText();
                config.setOutputFormat(ScanConfig.OutputFormat.valueOf(formatStr.toUpperCase()));
            } catch (IllegalArgumentException e) {
                logger.warn("Invalid output format: {}", rootNode.get("outputFormat").asText());
            }
        }

        // ✅ ПАРСИМ Open Banking креденшиалы (для хакатона!)
        if (rootNode.has("clientId")) {
            config.setClientId(rootNode.get("clientId").asText());
        }
        if (rootNode.has("clientSecret")) {
            config.setClientSecret(rootNode.get("clientSecret").asText());
        }
        if (rootNode.has("bankId")) {
            config.setBankId(rootNode.get("bankId").asText());
        }
        if (rootNode.has("consentId")) {
            config.setConsentId(rootNode.get("consentId").asText());
        }

        // Parse headers
        if (rootNode.has("headers") && rootNode.get("headers").isObject()) {
            JsonNode headersNode = rootNode.get("headers");
            headersNode.fields().forEachRemaining(entry -> {
                config.addHeader(entry.getKey(), entry.getValue().asText());
            });
        }

        // Parse enabled test cases
        if (rootNode.has("enabledTestCaseIds") && rootNode.get("enabledTestCaseIds").isArray()) {
            List<String> enabledIds = new ArrayList<>();
            for (JsonNode idNode : rootNode.get("enabledTestCaseIds")) {
                enabledIds.add(idNode.asText());
            }
            config.setEnabledTestCaseIds(enabledIds);
        }

        // Parse disabled test cases
        if (rootNode.has("disabledTestCaseIds") && rootNode.get("disabledTestCaseIds").isArray()) {
            List<String> disabledIds = new ArrayList<>();
            for (JsonNode idNode : rootNode.get("disabledTestCaseIds")) {
                disabledIds.add(idNode.asText());
            }
            config.setDisabledTestCaseIds(disabledIds);
        }

        // Parse endpoints
        if (rootNode.has("endpoints") && rootNode.get("endpoints").isArray()) {
            for (JsonNode endpointNode : rootNode.get("endpoints")) {
                String path = endpointNode.has("path") ? endpointNode.get("path").asText() : null;
                String method = endpointNode.has("method") ? endpointNode.get("method").asText() : "GET";

                if (path != null && !path.isEmpty()) {
                    String contentType = endpointNode.has("contentType") ? endpointNode.get("contentType").asText() : "application/json";
                    String requestBody = endpointNode.has("requestBody") ? endpointNode.get("requestBody").asText() : null;
                    boolean requiresAuth = !endpointNode.has("requiresAuthentication") || endpointNode.get("requiresAuthentication").asBoolean();

                    // ✅ ИСПРАВЛЕНО: передаём baseUrl в конструктор EndpointInfo
                    String effectiveBaseUrl = baseUrl != null ? baseUrl : 
                        (config.getTargetUrl() != null ? config.getTargetUrl() : "http://localhost");
                    
                    EndpointInfo endpoint = new EndpointInfo(
                        effectiveBaseUrl,
                        path,
                        method,
                        contentType,
                        requestBody,
                        requiresAuth
                    );
                    config.addEndpoint(endpoint);
                }
            }
        }

        return config;
    }

    /**
     * Checks if a list of endpoints already contains an endpoint with the same path and method.
     *
     * @param endpoints The list of endpoints to check
     * @param endpoint The endpoint to look for
     * @return true if the list contains an equivalent endpoint, false otherwise
     */
    private boolean containsEndpoint(List<EndpointInfo> endpoints, EndpointInfo endpoint) {
        if (endpoints == null) return false;
        return endpoints.stream().anyMatch(e ->
                e.getPath().equals(endpoint.getPath()) &&
                        e.getMethod().equalsIgnoreCase(endpoint.getMethod())
        );
    }
}
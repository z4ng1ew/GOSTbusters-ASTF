package org.owasp.astf.core.config;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.EndpointInfo;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

/**
 * Loads configuration from various sources such as files, environment variables,
 * and command-line arguments.
 * <p>
 * This class provides methods to:
 * <ul>
 *   <li>Load configuration from YAML/JSON files</li>
 *   <li>Load configuration from properties files</li>
 *   <li>Load configuration from environment variables</li>
 *   <li>Load endpoints from text files</li>
 *   <li>Merge configurations from multiple sources</li>
 * </ul>
 * </p>
 */
public class ConfigLoader {
    private static final Logger logger = LogManager.getLogger(ConfigLoader.class);

    private final ObjectMapper jsonMapper;
    private final ObjectMapper yamlMapper;

    /**
     * Creates a new configuration loader.
     */
    public ConfigLoader() {
        this.jsonMapper = new ObjectMapper();
        this.yamlMapper = new ObjectMapper(new YAMLFactory());
    }

    /**
     * Loads a configuration from a YAML or JSON file.
     *
     * @param filePath The path to the configuration file
     * @return The scan configuration
     * @throws IOException If the file cannot be read or parsed
     */
    public static ScanConfig load(String filePath) throws IOException { // ✅ СТАТИЧЕСКИЙ МЕТОД
        File file = new File(filePath);
        if (!file.exists() || !file.isFile()) {
            throw new IOException("Configuration file not found: " + filePath);
        }

        ConfigLoader loader = new ConfigLoader(); // ✅ Создаём экземпляр для использования
        ScanConfig config = new ScanConfig();

        // Determine file type by extension
        if (filePath.endsWith(".yaml") || filePath.endsWith(".yml")) {
            JsonNode root = loader.yamlMapper.readTree(file);
            loader.parseJsonConfig(root, config);
        } else if (filePath.endsWith(".json")) {
            JsonNode root = loader.jsonMapper.readTree(file);
            loader.parseJsonConfig(root, config);
        } else if (filePath.endsWith(".properties")) {
            Properties props = new Properties();
            try (FileInputStream fis = new FileInputStream(file)) {
                props.load(fis);
            }
            loader.parsePropertiesConfig(props, config);
        } else {
            throw new IOException("Unsupported configuration file format: " + filePath);
        }

        logger.info("Loaded configuration from file: {}", filePath);
        return config;
    }

    /**
     * Loads endpoints from a text file.
     *
     * @param filePath The path to the endpoints file
     * @param baseUrl The base URL to use for endpoints (can be null)
     * @return A list of endpoints
     * @throws IOException If the file cannot be read
     */
    public List<EndpointInfo> loadEndpointsFromFile(String filePath, String baseUrl) throws IOException {
        File file = new File(filePath);
        if (!file.exists() || !file.isFile()) {
            throw new IOException("Endpoints file not found: " + filePath);
        }

        List<EndpointInfo> endpoints = new ArrayList<>();
        List<String> lines = Files.readAllLines(Paths.get(filePath));

        // ✅ Исправлено: используем переданный baseUrl или заглушку
        String effectiveBaseUrl = baseUrl != null && !baseUrl.isEmpty() ? baseUrl : "http://localhost";

        for (String line : lines) {
            // Skip comments and empty lines
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }

            String[] parts = line.split("\\s+", 2);
            if (parts.length == 2) {
                String method = parts[0].trim();
                String path = parts[1].trim();
                // ✅ Исправлено: передаем baseUrl в конструктор EndpointInfo
                endpoints.add(new EndpointInfo(effectiveBaseUrl, path, method));
            } else {
                logger.warn("Invalid endpoint format: {}. Expected 'METHOD PATH'", line);
            }
        }

        logger.info("Loaded {} endpoints from file: {}", endpoints.size(), filePath);
        return endpoints;
    }

    /**
     * Loads endpoints from a text file using default base URL.
     * This is a convenience method for backward compatibility.
     *
     * @param filePath The path to the endpoints file
     * @return A list of endpoints
     * @throws IOException If the file cannot be read
     */
    public List<EndpointInfo> loadEndpointsFromFile(String filePath) throws IOException {
        // ✅ Исправлено: используем заглушку для baseUrl
        return loadEndpointsFromFile(filePath, "http://localhost");
    }

    /**
     * Loads configuration from environment variables.
     *
     * @param prefix The prefix for environment variables (e.g., "ASTF_")
     * @param config The configuration to update
     */
    public void loadFromEnvironment(String prefix, ScanConfig config) {
        Map<String, String> env = System.getenv();

        // Process environment variables with the specified prefix
        for (Map.Entry<String, String> entry : env.entrySet()) {
            String key = entry.getKey();
            String value = entry.getValue();

            if (key.startsWith(prefix)) {
                String configKey = key.substring(prefix.length()).toLowerCase();
                applyConfigValue(config, configKey, value);
            }
        }

        logger.info("Loaded configuration from environment variables with prefix: {}", prefix);
    }

    /**
     * Loads configuration from system properties.
     *
     * @param prefix The prefix for system properties (e.g., "astf.")
     * @param config The configuration to update
     */
    public void loadFromSystemProperties(String prefix, ScanConfig config) {
        Properties sysProps = System.getProperties();

        // Process system properties with the specified prefix
        for (String key : sysProps.stringPropertyNames()) {
            if (key.startsWith(prefix)) {
                String configKey = key.substring(prefix.length()).toLowerCase();
                String value = sysProps.getProperty(key);
                applyConfigValue(config, configKey, value);
            }
        }

        logger.info("Loaded configuration from system properties with prefix: {}", prefix);
    }

    /**
     * Parses a JSON/YAML configuration.
     *
     * @param root The root JSON node
     * @param config The configuration to update
     */
    private void parseJsonConfig(JsonNode root, ScanConfig config) {
        // ✅ ОСНОВНЫЕ НАСТРОЙКИ (как было)
        if (root.has("targetUrl")) {
            config.setTargetUrl(root.get("targetUrl").asText());
        }

        if (root.has("outputFile")) {
            config.setOutputFile(root.get("outputFile").asText());
        }

        if (root.has("outputFormat")) {
            String format = root.get("outputFormat").asText().toUpperCase();
            try {
                config.setOutputFormat(ScanConfig.OutputFormat.valueOf(format));
            } catch (IllegalArgumentException e) {
                logger.warn("Invalid output format: {}. Using default: {}", format, config.getOutputFormat());
            }
        }

        if (root.has("threads")) {
            config.setThreads(root.get("threads").asInt());
        }

        if (root.has("timeoutMinutes")) {
            config.setTimeoutMinutes(root.get("timeoutMinutes").asInt());
        }

        if (root.has("discoveryEnabled")) {
            config.setDiscoveryEnabled(root.get("discoveryEnabled").asBoolean());
        }

        if (root.has("verbose")) {
            config.setVerbose(root.get("verbose").asBoolean());
        }

        // ✅ КРИТИЧЕСКИЕ ИСПРАВЛЕНИЯ: Open Banking Russia параметры
        if (root.has("clientId")) {
            config.setClientId(root.get("clientId").asText()); // ✅ ДОБАВЛЕНО
        }

        if (root.has("clientSecret")) {
            config.setClientSecret(root.get("clientSecret").asText()); // ✅ ДОБАВЛЕНО
        }

        if (root.has("bankId")) {
            config.setBankId(root.get("bankId").asText()); // ✅ ДОБАВЛЕНО
        }

        if (root.has("useGost")) {
            config.setUseGost(root.get("useGost").asBoolean()); // ✅ ДОБАВЛЕНО
        }

        if (root.has("consentId")) {
            config.setConsentId(root.get("consentId").asText()); // ✅ ДОБАВЛЕНО
        }

        if (root.has("attackerToken")) {
            config.setAttackerToken(root.get("attackerToken").asText()); // ✅ ДОБАВЛЕНО
        }

        if (root.has("victimToken")) {
            config.setVictimToken(root.get("victimToken").asText()); // ✅ ДОБАВЛЕНО
        }

        // ✅ КРИТИЧЕСКИЕ ИСПРАВЛЕНИЯ: OpenAPI спецификация
        if (root.has("openApiSpecPath")) {
            config.setOpenApiSpecPath(root.get("openApiSpecPath").asText()); // ✅ ДОБАВЛЕНО
        }

        // Headers
        if (root.has("headers") && root.get("headers").isObject()) {
            JsonNode headers = root.get("headers");
            headers.fields().forEachRemaining(entry -> {
                config.addHeader(entry.getKey(), entry.getValue().asText());
            });
        }

        // Proxy settings
        if (root.has("proxy")) {
            JsonNode proxy = root.get("proxy");
            if (proxy.has("host")) {
                config.setProxyHost(proxy.get("host").asText());
            }
            if (proxy.has("port")) {
                config.setProxyPort(proxy.get("port").asInt());
            }
            if (proxy.has("username")) {
                config.setProxyUsername(proxy.get("username").asText());
            }
            if (proxy.has("password")) {
                config.setProxyPassword(proxy.get("password").asText());
            }
        }

        // Basic auth
        if (root.has("basicAuth")) {
            JsonNode basicAuth = root.get("basicAuth");
            if (basicAuth.has("username")) {
                config.setBasicAuthUsername(basicAuth.get("username").asText());
            }
            if (basicAuth.has("password")) {
                config.setBasicAuthPassword(basicAuth.get("password").asText());
            }
        }

        // Test case configuration
        if (root.has("enabledTestCases") && root.get("enabledTestCases").isArray()) { // ✅ ИСПРАВЛЕНО: enabledTestCases
            JsonNode enableTests = root.get("enabledTestCases");
            List<String> enabledTestCaseIds = new ArrayList<>();
            enableTests.forEach(node -> enabledTestCaseIds.add(node.asText()));
            config.setEnabledTestCaseIds(enabledTestCaseIds);
        }

        if (root.has("disabledTestCases") && root.get("disabledTestCases").isArray()) { // ✅ ИСПРАВЛЕНО: disabledTestCases
            JsonNode disableTests = root.get("disabledTestCases");
            List<String> disabledTestCaseIds = new ArrayList<>();
            disableTests.forEach(node -> disabledTestCaseIds.add(node.asText()));
            config.setDisabledTestCaseIds(disabledTestCaseIds);
        }

        // ✅ ДОБАВЛЕНО: Plugin конфигурация
        if (root.has("pluginJars") && root.get("pluginJars").isArray()) {
            JsonNode pluginJarsNode = root.get("pluginJars");
            List<String> pluginJars = new ArrayList<>();
            pluginJarsNode.forEach(node -> pluginJars.add(node.asText()));
            config.setPluginJars(pluginJars);
        }

        if (root.has("pluginRepositoryUrl")) {
            config.setPluginRepositoryUrl(root.get("pluginRepositoryUrl").asText());
        }
    }

    /**
     * Parses a properties configuration.
     *
     * @param props The properties
     * @param config The configuration to update
     */
    private void parsePropertiesConfig(Properties props, ScanConfig config) {
        // ✅ ОСНОВНЫЕ НАСТРОЙКИ (как было)
        if (props.containsKey("targetUrl")) {
            config.setTargetUrl(props.getProperty("targetUrl"));
        }

        if (props.containsKey("outputFile")) {
            config.setOutputFile(props.getProperty("outputFile"));
        }

        if (props.containsKey("outputFormat")) {
            String format = props.getProperty("outputFormat").toUpperCase();
            try {
                config.setOutputFormat(ScanConfig.OutputFormat.valueOf(format));
            } catch (IllegalArgumentException e) {
                logger.warn("Invalid output format: {}. Using default: {}", format, config.getOutputFormat());
            }
        }

        if (props.containsKey("threads")) {
            config.setThreads(Integer.parseInt(props.getProperty("threads")));
        }

        if (props.containsKey("timeoutMinutes")) {
            config.setTimeoutMinutes(Integer.parseInt(props.getProperty("timeoutMinutes")));
        }

        if (props.containsKey("discoveryEnabled")) {
            config.setDiscoveryEnabled(Boolean.parseBoolean(props.getProperty("discoveryEnabled")));
        }

        if (props.containsKey("verbose")) {
            config.setVerbose(Boolean.parseBoolean(props.getProperty("verbose")));
        }

        // ✅ КРИТИЧЕСКИЕ ИСПРАВЛЕНИЯ: Open Banking параметры
        if (props.containsKey("clientId")) {
            config.setClientId(props.getProperty("clientId")); // ✅ ДОБАВЛЕНО
        }

        if (props.containsKey("clientSecret")) {
            config.setClientSecret(props.getProperty("clientSecret")); // ✅ ДОБАВЛЕНО
        }

        if (props.containsKey("bankId")) {
            config.setBankId(props.getProperty("bankId")); // ✅ ДОБАВЛЕНО
        }

        if (props.containsKey("useGost")) {
            config.setUseGost(Boolean.parseBoolean(props.getProperty("useGost"))); // ✅ ДОБАВЛЕНО
        }

        if (props.containsKey("consentId")) {
            config.setConsentId(props.getProperty("consentId")); // ✅ ДОБАВЛЕНО
        }

        if (props.containsKey("openApiSpecPath")) {
            config.setOpenApiSpecPath(props.getProperty("openApiSpecPath")); // ✅ ДОБАВЛЕНО
        }

        // Headers
        for (String key : props.stringPropertyNames()) {
            if (key.startsWith("header.")) {
                String headerName = key.substring("header.".length());
                config.addHeader(headerName, props.getProperty(key));
            }
        }

        // Proxy settings
        if (props.containsKey("proxy.host")) {
            config.setProxyHost(props.getProperty("proxy.host"));
        }
        if (props.containsKey("proxy.port")) {
            config.setProxyPort(Integer.parseInt(props.getProperty("proxy.port")));
        }
        if (props.containsKey("proxy.username")) {
            config.setProxyUsername(props.getProperty("proxy.username"));
        }
        if (props.containsKey("proxy.password")) {
            config.setProxyPassword(props.getProperty("proxy.password"));
        }

        // Basic auth
        if (props.containsKey("basicAuth.username")) {
            config.setBasicAuthUsername(props.getProperty("basicAuth.username"));
        }
        if (props.containsKey("basicAuth.password")) {
            config.setBasicAuthPassword(props.getProperty("basicAuth.password"));
        }

        // Test case configuration
        if (props.containsKey("enabledTestCases")) { // ✅ ИСПРАВЛЕНО: enabledTestCases
            String enableTests = props.getProperty("enabledTestCases");
            String[] testIds = enableTests.split(",");
            List<String> enabledTestCaseIds = new ArrayList<>();
            for (String id : testIds) {
                id = id.trim();
                if (!id.isEmpty()) {
                    enabledTestCaseIds.add(id);
                }
            }
            config.setEnabledTestCaseIds(enabledTestCaseIds);
        }

        if (props.containsKey("disabledTestCases")) { // ✅ ИСПРАВЛЕНО: disabledTestCases
            String disableTests = props.getProperty("disabledTestCases");
            String[] testIds = disableTests.split(",");
            List<String> disabledTestCaseIds = new ArrayList<>();
            for (String id : testIds) {
                id = id.trim();
                if (!id.isEmpty()) {
                    disabledTestCaseIds.add(id);
                }
            }
            config.setDisabledTestCaseIds(disabledTestCaseIds);
        }
    }

    /**
     * Applies a configuration value to the specified configuration.
     *
     * @param config The configuration to update
     * @param key The configuration key
     * @param value The configuration value
     */
    private void applyConfigValue(ScanConfig config, String key, String value) {
        switch (key) {
            case "targeturl" -> config.setTargetUrl(value);
            case "outputfile" -> config.setOutputFile(value);
            case "outputformat" -> {
                try {
                    config.setOutputFormat(ScanConfig.OutputFormat.valueOf(value.toUpperCase()));
                } catch (IllegalArgumentException e) {
                    logger.warn("Invalid output format: {}. Using default: {}", value, config.getOutputFormat());
                }
            }
            case "threads" -> config.setThreads(Integer.parseInt(value));
            case "timeoutminutes" -> config.setTimeoutMinutes(Integer.parseInt(value));
            case "discoveryenabled" -> config.setDiscoveryEnabled(Boolean.parseBoolean(value));
            case "verbose" -> config.setVerbose(Boolean.parseBoolean(value));
            // ✅ КРИТИЧЕСКИЕ ИСПРАВЛЕНИЯ: Open Banking параметры
            case "clientid" -> config.setClientId(value); // ✅ ДОБАВЛЕНО
            case "clientsecret" -> config.setClientSecret(value); // ✅ ДОБАВЛЕНО
            case "bankid" -> config.setBankId(value); // ✅ ДОБАВЛЕНО
            case "usegost" -> config.setUseGost(Boolean.parseBoolean(value)); // ✅ ДОБАВЛЕНО
            case "consentid" -> config.setConsentId(value); // ✅ ДОБАВЛЕНО
            case "openapispecpath" -> config.setOpenApiSpecPath(value); // ✅ ДОБАВЛЕНО
            case "attackertoken" -> config.setAttackerToken(value); // ✅ ДОБАВЛЕНО
            case "victimtoken" -> config.setVictimToken(value); // ✅ ДОБАВЛЕНО
            case "pluginrepositoryurl" -> config.setPluginRepositoryUrl(value); // ✅ ДОБАВЛЕНО
            case "proxy_host" -> config.setProxyHost(value);
            case "proxy_port" -> config.setProxyPort(Integer.parseInt(value));
            case "proxy_username" -> config.setProxyUsername(value);
            case "proxy_password" -> config.setProxyPassword(value);
            case "basicauth_username" -> config.setBasicAuthUsername(value);
            case "basicauth_password" -> config.setBasicAuthPassword(value);
            default -> {
                if (key.startsWith("header_")) {
                    String headerName = key.substring("header_".length());
                    config.addHeader(headerName, value);
                } else if (key.equals("enabledtestcases")) { // ✅ ИСПРАВЛЕНО: enabledtestcases
                    String[] testIds = value.split(",");
                    List<String> enabledTestCaseIds = new ArrayList<>();
                    for (String id : testIds) {
                        id = id.trim();
                        if (!id.isEmpty()) {
                            enabledTestCaseIds.add(id);
                        }
                    }
                    config.setEnabledTestCaseIds(enabledTestCaseIds);
                } else if (key.equals("disabledtestcases")) { // ✅ ИСПРАВЛЕНО: disabledtestcases
                    String[] testIds = value.split(",");
                    List<String> disabledTestCaseIds = new ArrayList<>();
                    for (String id : testIds) {
                        id = id.trim();
                        if (!id.isEmpty()) {
                            disabledTestCaseIds.add(id);
                        }
                    }
                    config.setDisabledTestCaseIds(disabledTestCaseIds);
                }
            }
        }
    }
}
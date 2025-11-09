package org.owasp.astf.core.config;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.owasp.astf.core.EndpointInfo;

/**
 * Configuration for an API security scan.
 * <p>
 * This class contains all configuration parameters for executing a security scan,
 * including target information, authentication settings, test case selection,
 * threading options, output formats, and more.
 * </p>
 */
public class ScanConfig {
    // Target and scope configuration
    private String targetUrl;
    private List<EndpointInfo> endpoints;
    private boolean discoveryEnabled = true;
    private List<String> excludePatterns;
    private Map<String, String> headers;

    // Authentication settings
    private String basicAuthUsername;
    private String basicAuthPassword;
    private String apiKey;
    private String apiKeyHeader = "X-API-Key";
    private String bearerToken;
    private String authHeader;

    // Proxy settings
    private String proxyHost;
    private int proxyPort;
    private String proxyUsername;
    private String proxyPassword;

    // Test case configuration
    private List<String> enabledTestCaseIds;
    private List<String> disabledTestCaseIds;

    // Execution settings
    private int threads = 10;
    private int timeoutMinutes = 30;
    private int requestDelayMs = 0;
    private int maxRequestsPerSecond = 0;
    private boolean followRedirects = true;
    private boolean validateCertificates = true;

    // Output settings
    private OutputFormat outputFormat = OutputFormat.JSON;
    private String outputFile;
    private boolean verbose = false;
    private int maxFindings = 0;
    private List<String> excludeSeverities;

    // ✅ ПОЛЯ ДЛЯ ХАКАТОНА (OpenAPI, GOST, BOLA)
    private String openApiSpecPath;
    private boolean useGost = false;
    private String attackerToken;
    private String victimToken;
    
    // 💡 OPEN BANKING API ПОЛЯ
    private String clientId;
    private String clientSecret;
    private String bankId;
    private String consentId;
    
    // 💡 1. AsyncAPI ПОЛЯ
    private String asyncApiSpecPath;
    private List<String> enabledAsyncTestCases;
    
    // 💡 2. ПОЛЯ ДЛЯ ПОДДЕРЖКИ ПЛАГИНОВ
    private List<String> pluginJars;
    private String pluginRepositoryUrl;

    /**
     * Creates a new scan configuration with default settings.
     */
    public ScanConfig() {
        this.headers = new HashMap<>();
        this.endpoints = new ArrayList<>();
        this.enabledTestCaseIds = new ArrayList<>();
        this.disabledTestCaseIds = new ArrayList<>();
        this.excludePatterns = new ArrayList<>();
        this.excludeSeverities = new ArrayList<>();
        this.enabledAsyncTestCases = new ArrayList<>(); // Инициализация
        this.pluginJars = new ArrayList<>();           // Инициализация
    }

    // Target and scope getters/setters
    public String getTargetUrl() { return targetUrl; }
    public void setTargetUrl(String targetUrl) { 
        if (targetUrl != null && !targetUrl.endsWith("/")) {
            this.targetUrl = targetUrl + "/";
        } else {
            this.targetUrl = targetUrl;
        }
    }
    
    public List<EndpointInfo> getEndpoints() { 
        return endpoints != null ? endpoints : new ArrayList<>(); // ✅ ИСПРАВЛЕНО: защита от null
    }
    public void setEndpoints(List<EndpointInfo> endpoints) { 
        this.endpoints = endpoints != null ? endpoints : new ArrayList<>(); // ✅ ИСПРАВЛЕНО: защита от null
    }
    
    public boolean isDiscoveryEnabled() { return discoveryEnabled; }
    public void setDiscoveryEnabled(boolean discoveryEnabled) { this.discoveryEnabled = discoveryEnabled; }
    
    public List<String> getExcludePatterns() { 
        return excludePatterns != null ? excludePatterns : new ArrayList<>(); // ✅ ИСПРАВЛЕНО: защита от null
    }
    public void setExcludePatterns(List<String> excludePatterns) { 
        this.excludePatterns = excludePatterns != null ? excludePatterns : new ArrayList<>(); // ✅ ИСПРАВЛЕНО: защита от null
    }
    
    public Map<String, String> getHeaders() { 
        return headers != null ? headers : new HashMap<>(); // ✅ ИСПРАВЛЕНО: защита от null
    }
    public void setHeaders(Map<String, String> headers) { 
        this.headers = headers != null ? headers : new HashMap<>(); // ✅ ИСПРАВЛЕНО: защита от null
    }
    public void addHeader(String name, String value) { 
        if (this.headers == null) {
            this.headers = new HashMap<>(); // ✅ ИСПРАВЛЕНО: инициализация при null
        }
        this.headers.put(name, value); 
    }


    // Authentication getters/setters
    public String getBasicAuthUsername() { return basicAuthUsername; }
    public void setBasicAuthUsername(String basicAuthUsername) { this.basicAuthUsername = basicAuthUsername; }
    public String getBasicAuthPassword() { return basicAuthPassword; }
    public void setBasicAuthPassword(String basicAuthPassword) { this.basicAuthPassword = basicAuthPassword; }
    public String getApiKey() { return apiKey; }
    public void setApiKey(String apiKey) { this.apiKey = apiKey; }
    public String getApiKeyHeader() { return apiKeyHeader; }
    public void setApiKeyHeader(String apiKeyHeader) { this.apiKeyHeader = apiKeyHeader; }
    public String getBearerToken() { return bearerToken; }
    public void setBearerToken(String bearerToken) { 
        this.bearerToken = bearerToken;
        if (bearerToken != null && !bearerToken.isEmpty() && getHeaders().isEmpty()) {
            getHeaders().put("Authorization", "Bearer " + bearerToken);
        }
    }
    public String getAuthHeader() { return authHeader; }
    public void setAuthHeader(String authHeader) {
        this.authHeader = authHeader;
        if (authHeader != null && !authHeader.trim().isEmpty()) {
            String[] parts = authHeader.split(":", 2);
            if (parts.length == 2) {
                getHeaders().put(parts[0].trim(), parts[1].trim()); // ✅ ИСПРАВЛЕНО: используем getHeaders()
            }
        }
    }


    // Proxy getters/setters
    public String getProxyHost() { return proxyHost; }
    public void setProxyHost(String proxyHost) { this.proxyHost = proxyHost; }
    public int getProxyPort() { return proxyPort; }
    public void setProxyPort(int proxyPort) { this.proxyPort = proxyPort; }
    public String getProxyUsername() { return proxyUsername; }
    public void setProxyUsername(String proxyUsername) { this.proxyUsername = proxyUsername; }
    public String getProxyPassword() { return proxyPassword; }
    public void setProxyPassword(String proxyPassword) { this.proxyPassword = proxyPassword; }


    // Test case configuration getters/setters
    public List<String> getEnabledTestCaseIds() { 
        return enabledTestCaseIds != null ? enabledTestCaseIds : new ArrayList<>(); // ✅ ИСПРАВЛЕНО: защита от null
    }
    public void setEnabledTestCaseIds(List<String> enabledTestCaseIds) { 
        this.enabledTestCaseIds = enabledTestCaseIds != null ? enabledTestCaseIds : new ArrayList<>(); // ✅ ИСПРАВЛЕНО: защита от null
    }
    
    public List<String> getDisabledTestCaseIds() { 
        return disabledTestCaseIds != null ? disabledTestCaseIds : new ArrayList<>(); // ✅ ИСПРАВЛЕНО: защита от null
    }
    public void setDisabledTestCaseIds(List<String> disabledTestCaseIds) { 
        this.disabledTestCaseIds = disabledTestCaseIds != null ? disabledTestCaseIds : new ArrayList<>(); // ✅ ИСПРАВЛЕНО: защита от null
    }


    // Execution settings getters/setters
    public int getThreads() { return threads; }
    public void setThreads(int threads) { this.threads = threads; }
    public int getTimeoutMinutes() { return timeoutMinutes; }
    public void setTimeoutMinutes(int timeoutMinutes) { this.timeoutMinutes = timeoutMinutes; }
    public int getRequestDelayMs() { return requestDelayMs; }
    public void setRequestDelayMs(int requestDelayMs) { this.requestDelayMs = requestDelayMs; }
    public int getMaxRequestsPerSecond() { return maxRequestsPerSecond; }
    public void setMaxRequestsPerSecond(int maxRequestsPerSecond) { this.maxRequestsPerSecond = maxRequestsPerSecond; }
    public boolean isFollowRedirects() { return followRedirects; }
    public void setFollowRedirects(boolean followRedirects) { this.followRedirects = followRedirects; }
    public boolean isValidateCertificates() { return validateCertificates; }
    public void setValidateCertificates(boolean validateCertificates) { this.validateCertificates = validateCertificates; }


    // Output settings getters/setters
    public OutputFormat getOutputFormat() { return outputFormat; }
    public void setOutputFormat(OutputFormat outputFormat) { this.outputFormat = outputFormat; }
    public String getOutputFile() { return outputFile; }
    public void setOutputFile(String outputFile) { this.outputFile = outputFile; }
    public boolean isVerbose() { return verbose; }
    public void setVerbose(boolean verbose) { this.verbose = verbose; }
    public int getMaxFindings() { return maxFindings; }
    public void setMaxFindings(int maxFindings) { this.maxFindings = maxFindings; }
    public List<String> getExcludeSeverities() { 
        return excludeSeverities != null ? excludeSeverities : new ArrayList<>(); // ✅ ИСПРАВЛЕНО: защита от null
    }
    public void setExcludeSeverities(List<String> excludeSeverities) { 
        this.excludeSeverities = excludeSeverities != null ? excludeSeverities : new ArrayList<>(); // ✅ ИСПРАВЛЕНО: защита от null
    }


    // ✅ ГЕТТЕРЫ И СЕТТЕРЫ ДЛЯ ХАКАТОНА
    public String getOpenApiSpecPath() { return openApiSpecPath; }
    public void setOpenApiSpecPath(String openApiSpecPath) { this.openApiSpecPath = openApiSpecPath; }
    public boolean isUseGost() { return useGost; }
    public void setUseGost(boolean useGost) { this.useGost = useGost; }
    public String getAttackerToken() { return attackerToken; }
    public void setAttackerToken(String attackerToken) { this.attackerToken = attackerToken; }
    public String getVictimToken() { return victimToken; }
    public void setVictimToken(String victimToken) { this.victimToken = victimToken; }
    
    // 💡 ГЕТТЕРЫ И СЕТТЕРЫ ДЛЯ OPEN BANKING API
    public String getClientId() { return clientId; }
    public void setClientId(String clientId) { this.clientId = clientId; }
    public String getClientSecret() { return clientSecret; }
    public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }
    public String getBankId() { return bankId; }
    public void setBankId(String bankId) { this.bankId = bankId; }
    public String getConsentId() { return consentId; }
    public void setConsentId(String consentId) { this.consentId = consentId; }
    
    // 💡 1. ГЕТТЕРЫ И СЕТТЕРЫ ДЛЯ AsyncAPI
    public String getAsyncApiSpecPath() { return asyncApiSpecPath; }
    public void setAsyncApiSpecPath(String asyncApiSpecPath) { this.asyncApiSpecPath = asyncApiSpecPath; }
    
    public List<String> getEnabledAsyncTestCases() { 
        return enabledAsyncTestCases != null ? enabledAsyncTestCases : new ArrayList<>(); // ✅ ИСПРАВЛЕНО: защита от null
    }
    public void setEnabledAsyncTestCases(List<String> enabledAsyncTestCases) { 
        this.enabledAsyncTestCases = enabledAsyncTestCases != null ? enabledAsyncTestCases : new ArrayList<>(); // ✅ ИСПРАВЛЕНО: защита от null
    }

    // 💡 2. ГЕТТЕРЫ И СЕТТЕРЫ ДЛЯ ПОДДЕРЖКИ ПЛАГИНОВ
    public List<String> getPluginJars() { 
        return pluginJars != null ? pluginJars : new ArrayList<>(); // ✅ ИСПРАВЛЕНО: защита от null
    }
    public void setPluginJars(List<String> pluginJars) { 
        this.pluginJars = pluginJars != null ? pluginJars : new ArrayList<>(); // ✅ ИСПРАВЛЕНО: защита от null
    }
    
    public String getPluginRepositoryUrl() { return pluginRepositoryUrl; }
    public void setPluginRepositoryUrl(String pluginRepositoryUrl) { this.pluginRepositoryUrl = pluginRepositoryUrl; }
    
    // 💡 3. ИСПРАВЛЕННЫЙ МЕТОД НАСЛЕДОВАНИЯ КОНФИГУРАЦИИ
    /**
     * Merges properties from a parent configuration into this one,
     * overriding only if the current property is null.
     *
     * @param parentConfig The configuration to inherit properties from.
     * @return This ScanConfig instance with inherited properties.
     */
    public ScanConfig inheritFrom(ScanConfig parentConfig) {
        if (parentConfig == null) return this;

        // Target and scope
        if (this.targetUrl == null) this.targetUrl = parentConfig.targetUrl;
        if (this.endpoints == null) this.endpoints = new ArrayList<>(parentConfig.getEndpoints()); // ✅ ИСПРАВЛЕНО: null-safe
        if (this.excludePatterns == null) this.excludePatterns = new ArrayList<>(parentConfig.getExcludePatterns()); // ✅ ИСПРАВЛЕНО: null-safe
        if (this.headers == null) this.headers = new HashMap<>(parentConfig.getHeaders()); // ✅ ИСПРАВЛЕНО: null-safe

        // Authentication
        if (this.basicAuthUsername == null) this.basicAuthUsername = parentConfig.getBasicAuthUsername();
        if (this.basicAuthPassword == null) this.basicAuthPassword = parentConfig.getBasicAuthPassword();
        if (this.apiKey == null) this.apiKey = parentConfig.getApiKey();
        if (this.bearerToken == null) this.bearerToken = parentConfig.getBearerToken();
        if (this.authHeader == null) this.authHeader = parentConfig.getAuthHeader();

        // Open Banking
        if (this.clientId == null) this.clientId = parentConfig.getClientId();
        if (this.clientSecret == null) this.clientSecret = parentConfig.getClientSecret();
        if (this.bankId == null) this.bankId = parentConfig.getBankId();
        if (this.consentId == null) this.consentId = parentConfig.getConsentId();

        // Specs and Plugins
        if (this.openApiSpecPath == null) this.openApiSpecPath = parentConfig.getOpenApiSpecPath();
        if (this.asyncApiSpecPath == null) this.asyncApiSpecPath = parentConfig.getAsyncApiSpecPath();
        if (this.enabledTestCaseIds == null) this.enabledTestCaseIds = new ArrayList<>(parentConfig.getEnabledTestCaseIds()); // ✅ ИСПРАВЛЕНО: null-safe
        if (this.pluginJars == null) this.pluginJars = new ArrayList<>(parentConfig.getPluginJars()); // ✅ ИСПРАВЛЕНО: null-safe
        if (this.pluginRepositoryUrl == null) this.pluginRepositoryUrl = parentConfig.getPluginRepositoryUrl();
        
        // Settings (проверяем, что не используется значение по умолчанию 0/false)
        if (this.threads == 10 && parentConfig.getThreads() != 10) this.threads = parentConfig.getThreads();
        
        return this;
    }
    
    // 💡 4. ИСПРАВЛЕННЫЙ МЕТОД ВАЛИДАЦИИ КОНФИГУРАЦИИ
    /**
     * Validates the current scan configuration settings.
     *
     * @throws IllegalArgumentException if any configuration setting is invalid.
     */
    public void validate() {
        if (targetUrl == null || targetUrl.trim().isEmpty()) {
            throw new IllegalArgumentException("Target URL must be set.");
        }
        
        if (threads <= 0) {
            throw new IllegalArgumentException("Number of threads must be a positive integer.");
        }
        
        // GOST + Open Banking API validation
        if (useGost) {
            Pattern obApiPattern = Pattern.compile("open\\.bankingapi\\.ru", Pattern.CASE_INSENSITIVE);
            Matcher matcher = obApiPattern.matcher(targetUrl);
            
            if (!matcher.find()) {
                throw new IllegalArgumentException("GOST can only be used with a target URL containing 'open.bankingapi.ru'. Current URL: " + targetUrl);
            }
            if (clientId == null || clientId.isEmpty() || clientSecret == null || clientSecret.isEmpty()) {
                 throw new IllegalArgumentException("Client ID and Client Secret must be provided when useGost is true for Open Banking API testing.");
            }
        }
        
        // OpenAPI spec validation
        if (openApiSpecPath != null) {
            String lowerCasePath = openApiSpecPath.toLowerCase();
            if (!lowerCasePath.endsWith(".yaml") && !lowerCasePath.endsWith(".json")) {
                throw new IllegalArgumentException("OpenAPI spec path must point to a .yaml or .json file. Current path: " + openApiSpecPath);
            }
            // ✅ ПРОВЕРЯЕМ СУЩЕСТВОВАНИЕ ФАЙЛА
            Path path = Paths.get(openApiSpecPath);
            if (!Files.exists(path)) {
                throw new IllegalArgumentException("OpenAPI spec file does not exist: " + openApiSpecPath);
            }
        }
        
        // AsyncAPI spec validation
        if (asyncApiSpecPath != null) {
            String lowerCasePath = asyncApiSpecPath.toLowerCase();
            if (!lowerCasePath.endsWith(".yaml") && !lowerCasePath.endsWith(".json")) {
                throw new IllegalArgumentException("AsyncAPI spec path must point to a .yaml or .json file. Current path: " + asyncApiSpecPath);
            }
            // ✅ ПРОВЕРЯЕМ СУЩЕСТВОВАНИЕ ФАЙЛА
            Path path = Paths.get(asyncApiSpecPath);
            if (!Files.exists(path)) {
                throw new IllegalArgumentException("AsyncAPI spec file does not exist: " + asyncApiSpecPath);
            }
        }
        
        // Plugin file validation
        if (pluginJars != null) {
            for (String jarPath : pluginJars) {
                if (!jarPath.toLowerCase().endsWith(".jar")) {
                    throw new IllegalArgumentException("Plugin must be a .jar file: " + jarPath);
                }
                // ✅ ПРОВЕРЯЕМ СУЩЕСТВОВАНИЕ ФАЙЛА
                try {
                    Path path = Paths.get(jarPath);
                    if (!Files.exists(path)) {
                        throw new IllegalArgumentException("Plugin file does not exist: " + jarPath);
                    }
                } catch (Exception e) {
                    throw new IllegalArgumentException("Invalid path or file access error for plugin: " + jarPath + ". Error: " + e.getMessage());
                }
            }
        }
    }


    /**
     * Enumeration of supported output formats.
     */
    public enum OutputFormat {
        /** JSON output format */
        JSON,
        /** XML output format */
        XML,
        /** HTML output format */
        HTML,
        /** SARIF output format for tool integration */
        SARIF
    }
}
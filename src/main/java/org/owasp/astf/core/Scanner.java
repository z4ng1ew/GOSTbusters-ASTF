package org.owasp.astf.core;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.discovery.EndpointDiscoveryService;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.ScanResult;
import org.owasp.astf.core.result.Severity;
import org.owasp.astf.openapi.OpenApiLoader;
import org.owasp.astf.testcases.TestCase;
import org.owasp.astf.testcases.TestCaseRegistry;

/**
 * The main scanner engine that orchestrates the API security testing process.
 * This class is responsible for:
 * <ul>
 *   <li>Initializing and executing the scan based on configuration</li>
 *   <li>Managing endpoint discovery or using provided endpoints</li>
 *   <li>Coordinating test case execution across endpoints</li>
 *   <li>Collecting and aggregating findings</li>
 *   <li>Providing progress updates and metrics</li>
 * </ul>
 */
public class Scanner {
    private static final Logger logger = LogManager.getLogger(Scanner.class);

    private final ScanConfig config;
    private final HttpClient httpClient;
    private final TestCaseRegistry testCaseRegistry;
    private final EndpointDiscoveryService discoveryService;

    // Scan metrics and tracking
    private final AtomicInteger completedTasks = new AtomicInteger(0);
    private final AtomicInteger totalTasks = new AtomicInteger(0);
    private final Map<Severity, AtomicInteger> findingsBySeverity = new ConcurrentHashMap<>();
    private LocalDateTime scanStartTime;
    private LocalDateTime scanEndTime;

    // ✅ ДОБАВЛЕНО: Статистика фильтрации
    private final AtomicInteger falsePositivesFiltered = new AtomicInteger(0);
    private final AtomicInteger totalFindingsBeforeFiltering = new AtomicInteger(0);

    /**
     * Creates a new scanner with the specified configuration.
     *
     * @param config The scan configuration
     */
    public Scanner(ScanConfig config) {
        // ✅ Обработка GOST-шлюза перед созданием зависимостей
        ScanConfig effectiveConfig = processGostConfig(config);
        
        this.config = effectiveConfig;
        this.httpClient = new HttpClient(effectiveConfig);
        
        // ✅ ИСПРАВЛЕНО: Инициализируем поле с вызовом конструктора без параметров
        this.testCaseRegistry = new TestCaseRegistry();
        this.discoveryService = new EndpointDiscoveryService(effectiveConfig, httpClient);

        // Initialize severity counters
        for (Severity severity : Severity.values()) {
            findingsBySeverity.put(severity, new AtomicInteger(0));
        }
    }

    /**
     * Processes GOST gateway configuration if enabled.
     *
     * @param originalConfig The original configuration
     * @return Effective configuration (original or GOST-modified)
     */
    private ScanConfig processGostConfig(ScanConfig originalConfig) {
        if (!originalConfig.isUseGost()) {
            return originalConfig;
        }

        // ✅ Применяем GOST трансформацию к targetUrl
        String originalUrl = originalConfig.getTargetUrl();
        String gostUrl = originalUrl.replace("https://vbank.open.bankingapi.ru", "https://api.gost.bankingapi.ru:8443");
        
        // Создаем копию конфига с обновленным URL
        ScanConfig gostConfig = new ScanConfig();
        gostConfig.setTargetUrl(gostUrl);
        gostConfig.setHeaders(new HashMap<>(originalConfig.getHeaders()));
        gostConfig.setEndpoints(new ArrayList<>(originalConfig.getEndpoints()));
        gostConfig.setThreads(originalConfig.getThreads());
        gostConfig.setTimeoutMinutes(originalConfig.getTimeoutMinutes());
        gostConfig.setDiscoveryEnabled(originalConfig.isDiscoveryEnabled());
        gostConfig.setEnabledTestCaseIds(new ArrayList<>(originalConfig.getEnabledTestCaseIds()));
        gostConfig.setDisabledTestCaseIds(new ArrayList<>(originalConfig.getDisabledTestCaseIds()));
        gostConfig.setOutputFormat(originalConfig.getOutputFormat());
        gostConfig.setOutputFile(originalConfig.getOutputFile());
        gostConfig.setVerbose(originalConfig.isVerbose());
        gostConfig.setUseGost(true); // Сохраняем флаг
        gostConfig.setOpenApiSpecPath(originalConfig.getOpenApiSpecPath());
        gostConfig.setAttackerToken(originalConfig.getAttackerToken());
        gostConfig.setVictimToken(originalConfig.getVictimToken());
        gostConfig.setAuthHeader(originalConfig.getAuthHeader());
        gostConfig.setMaxRequestsPerSecond(originalConfig.getMaxRequestsPerSecond());
        gostConfig.setFollowRedirects(originalConfig.isFollowRedirects());
        gostConfig.setProxyHost(originalConfig.getProxyHost());
        gostConfig.setProxyPort(originalConfig.getProxyPort());

        logger.info("GOST gateway enabled. Original URL: {} -> GOST URL: {}", originalUrl, gostUrl);
        return gostConfig;
    }

    /**
     * Executes a full scan based on the provided configuration.
     *
     * @return The scan results containing all findings
     */
    public ScanResult scan() {
        scanStartTime = LocalDateTime.now();
        List<Finding> findings = new ArrayList<>();

        try {
            logger.info("Starting API security scan for target: {}", config.getTargetUrl());

            // ✅ Определяем эндпоинты: OpenAPI → discovery → предоставленные
            List<EndpointInfo> endpoints = resolveEndpoints();
            
            // ✅ ДОБАВЛЕНО: Отладочный вывод найденных эндпоинтов
            System.out.println("🔍 Found " + endpoints.size() + " endpoints to scan:");
            for (EndpointInfo endpoint : endpoints) {
                System.out.println("  - " + endpoint.getMethod() + " " + endpoint.getFullUrl());
                if (config.isVerbose()) {
                    System.out.println("    Requires auth: " + endpoint.isRequiresAuthentication());
                }
            }
            
            if (endpoints.isEmpty()) {
                logger.warn("No endpoints found to scan. Check target URL or provide endpoints manually.");
                return createEmptyScanResult();
            }

            // ✅ Применяем GOST трансформацию к эндпоинтам если нужно
            if (config.isUseGost()) {
                endpoints = applyGostToEndpoints(endpoints);
            }

            // Get applicable test cases
            List<TestCase> testCases = testCaseRegistry.getEnabledTestCases(config);
            logger.info("Running {} test cases against {} endpoints", testCases.size(), endpoints.size());

            // ✅ ДОБАВЛЕНО: Отладочный вывод тест-кейсов
            System.out.println("🧪 Running " + testCases.size() + " test cases:");
            for (TestCase testCase : testCases) {
                System.out.println("  - " + testCase.getId() + ": " + testCase.getName());
            }

            // Calculate total tasks for progress tracking
            totalTasks.set(endpoints.size() * testCases.size());

            // Run test cases against endpoints using virtual threads (Java 21)
            try (ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor()) {
                List<CompletableFuture<Void>> futures = new ArrayList<>();

                for (EndpointInfo endpoint : endpoints) {
                    for (TestCase testCase : testCases) {
                        CompletableFuture<Void> future = CompletableFuture.runAsync(() -> {
                            try {
                                logger.debug("Executing {} on {}", testCase.getId(), endpoint);
                                List<Finding> testFindings = testCase.execute(endpoint, httpClient);
                                
                                // ✅ ДОБАВЛЕНО: Фильтрация ложных срабатываний
                                List<Finding> filteredFindings = filterFalsePositives(testFindings, endpoint, httpClient);
                                totalFindingsBeforeFiltering.addAndGet(testFindings.size());

                                if (!filteredFindings.isEmpty()) {
                                    synchronized (findings) {
                                        findings.addAll(filteredFindings);

                                        // Update severity counters
                                        for (Finding finding : filteredFindings) {
                                            findingsBySeverity.get(finding.getSeverity()).incrementAndGet();
                                        }
                                    }

                                    logger.debug("Found {} issues with {} on {} (after filtering)",
                                            filteredFindings.size(), testCase.getId(), endpoint);
                                }
                            } catch (Exception e) {
                                logger.error("Error executing test case {} on endpoint {}: {}",
                                        testCase.getId(), endpoint.getPath(), e.getMessage());
                                if (config.isVerbose()) {
                                    logger.debug("Exception details:", e);
                                }
                            } finally {
                                // Update progress
                                int completed = completedTasks.incrementAndGet();
                                if (completed % 10 == 0 || completed == totalTasks.get()) {
                                    logProgress();
                                }
                            }
                        }, executor);

                        futures.add(future);
                    }
                }

                // Wait for all tasks to complete or timeout
                CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]))
                        .orTimeout(config.getTimeoutMinutes(), TimeUnit.MINUTES)
                        .exceptionally(ex -> {
                            logger.warn("Scan interrupted or timed out before completion: {}", ex.getMessage());
                            return null;
                        })
                        .join();
            }

            logger.info("Scan completed. Found {} issues: {} critical, {} high, {} medium, {} low, {} info",
                    findings.size(),
                    findingsBySeverity.get(Severity.CRITICAL).get(),
                    findingsBySeverity.get(Severity.HIGH).get(),
                    findingsBySeverity.get(Severity.MEDIUM).get(),
                    findingsBySeverity.get(Severity.LOW).get(),
                    findingsBySeverity.get(Severity.INFO).get());

        } catch (Exception e) {
            logger.error("Unhandled exception during scan: {}", e.getMessage());
            if (config.isVerbose()) {
                logger.debug("Exception details:", e);
            }
        }

        scanEndTime = LocalDateTime.now();
        
        // ✅ ДОБАВЛЕНО: Детальный вывод результатов
        logFindings(findings);
        
        ScanResult result = new ScanResult(config.getTargetUrl(), findings);
        result.setScanStartTime(scanStartTime);
        result.setScanEndTime(scanEndTime);

        // ✅ ДОБАВЛЕНО: Вывод статистики в консоль при завершении
        printScanSummary(findings);

        return result;
    }

    /**
     * ✅ ДОБАВЛЕНО: Фильтрует ложные срабатывания
     */
    private List<Finding> filterFalsePositives(List<Finding> findings, EndpointInfo endpoint, HttpClient client) {
        List<Finding> filtered = new ArrayList<>();
        
        for (Finding finding : findings) {
            if ("ASTF-API2-2023".equals(finding.getTestCaseId())) {
                // ✅ Проверить, что эндпоинт действительно не требует аутентификации
                if (isActuallyUnauthenticated(endpoint, client)) {
                    filtered.add(finding);
                } else {
                    if (config.isVerbose()) {
                        System.out.println("❌ FP Filtered: " + finding.getTitle() + " - " + finding.getEndpoint());
                    }
                    falsePositivesFiltered.incrementAndGet();
                }
            } else {
                filtered.add(finding);
            }
        }
        return filtered;
    }

    /**
     * ✅ ДОБАВЛЕНО: Проверяет, можно ли получить доступ без токена
     */
    private boolean isActuallyUnauthenticated(EndpointInfo endpoint, HttpClient client) {
        try {
            // Создаем копию клиента без заголовков аутентификации
            HttpClient noAuthClient = createUnauthenticatedClient();
            
            String response = noAuthClient.get(endpoint.getFullUrl(), Map.of()); // без токена
            int code = extractStatusCode(response);
            
            // ✅ Если 200 без токена — действительно уязвим
            boolean isVulnerable = code == 200;
            
            if (config.isVerbose()) {
                System.out.println("🔍 Auth Check: " + endpoint.getMethod() + " " + endpoint.getFullUrl() + 
                                 " -> Status: " + code + ", Vulnerable: " + isVulnerable);
            }
            
            return isVulnerable;
        } catch (Exception e) {
            // ✅ Если ошибка — значит, аутентификация есть (ложное срабатывание)
            if (config.isVerbose()) {
                System.out.println("🔍 Auth Check: " + endpoint.getMethod() + " " + endpoint.getFullUrl() + 
                                 " -> Error: " + e.getMessage() + " (protected)");
            }
            return false;
        }
    }

    /**
     * ✅ ДОБАВЛЕНО: Создает HttpClient без заголовков аутентификации
     */
    private HttpClient createUnauthenticatedClient() {
        ScanConfig noAuthConfig = new ScanConfig();
        noAuthConfig.setTargetUrl(config.getTargetUrl());
        noAuthConfig.setHeaders(new HashMap<>()); // Пустые заголовки
        noAuthConfig.setTimeoutMinutes(config.getTimeoutMinutes());
        noAuthConfig.setMaxRequestsPerSecond(config.getMaxRequestsPerSecond());
        noAuthConfig.setFollowRedirects(config.isFollowRedirects());
        noAuthConfig.setProxyHost(config.getProxyHost());
        noAuthConfig.setProxyPort(config.getProxyPort());
        
        return new HttpClient(noAuthConfig);
    }

    /**
     * ✅ ДОБАВЛЕНО: Извлекает статус код из ответа
     */
    private int extractStatusCode(String response) {
        if (response == null || response.trim().isEmpty()) {
            return 500; // Assume error for null/empty responses
        }
        
        // ✅ Эвристики для определения статус кода
        boolean isSuccess = true;
        
        // Проверяем признаки ошибок аутентификации
        if (response.toLowerCase().contains("unauthorized") || 
            response.toLowerCase().contains("authentication") ||
            response.toLowerCase().contains("401") ||
            response.toLowerCase().contains("403") ||
            response.toLowerCase().contains("access denied") ||
            response.toLowerCase().contains("forbidden")) {
            return 401; // Authentication error
        }
        
        // Проверяем признаки успешного ответа
        if (response.trim().startsWith("{") && response.trim().endsWith("}")) {
            // JSON response
            if (response.toLowerCase().contains("\"status\":\"success\"") ||
                response.toLowerCase().contains("\"success\":true") ||
                response.toLowerCase().contains("\"data\":") ||
                (response.length() > 50 && !response.toLowerCase().contains("\"error\""))) {
                return 200; // Success
            }
        }
        
        // Проверяем HTML ошибки
        if (response.toLowerCase().contains("<title>401") ||
            response.toLowerCase().contains("<title>403") ||
            response.toLowerCase().contains("<title>error")) {
            return 401; // Authentication error
        }
        
        // Если ответ содержит данные и не содержит ошибок - считаем успешным
        if (response.length() > 20 && 
            !response.toLowerCase().contains("error") &&
            !response.toLowerCase().contains("unauthorized")) {
            return 200; // Success
        }
        
        return 500; // Unknown/error
    }

    /**
     * ✅ ДОБАВЛЕНО: Вывод статистики сканирования в консоль
     */
    private void printScanSummary(List<Finding> findings) {
        // ✅ Подсчет по уровням серьезности
        int criticalCount = findings.stream().mapToInt(f -> f.getSeverity() == Severity.CRITICAL ? 1 : 0).sum();
        int highCount = findings.stream().mapToInt(f -> f.getSeverity() == Severity.HIGH ? 1 : 0).sum();
        int mediumCount = findings.stream().mapToInt(f -> f.getSeverity() == Severity.MEDIUM ? 1 : 0).sum();
        int lowCount = findings.stream().mapToInt(f -> f.getSeverity() == Severity.LOW ? 1 : 0).sum();
        int infoCount = findings.stream().mapToInt(f -> f.getSeverity() == Severity.INFO ? 1 : 0).sum();

        // ✅ Вычисление длительности сканирования
        long durationSeconds = Duration.between(scanStartTime, scanEndTime).getSeconds();
        long minutes = durationSeconds / 60;
        long seconds = durationSeconds % 60;

        System.out.println("\n🎯 SCAN SUMMARY:");
        System.out.println("┌─────────────────────────────────────────────┐");
        System.out.println("│ • Total findings: " + String.format("%-25s", findings.size()) + "│");
        System.out.println("│ • Critical severity: " + String.format("%-21s", criticalCount) + "│");
        System.out.println("│ • High severity: " + String.format("%-25s", highCount) + "│");
        System.out.println("│ • Medium severity: " + String.format("%-23s", mediumCount) + "│");
        System.out.println("│ • Low severity: " + String.format("%-27s", lowCount) + "│");
        System.out.println("│ • Info findings: " + String.format("%-25s", infoCount) + "│");
        
        // ✅ ДОБАВЛЕНО: Статистика фильтрации
        if (falsePositivesFiltered.get() > 0) {
            System.out.println("│ • False positives filtered: " + String.format("%-15s", falsePositivesFiltered.get()) + "│");
        }
        
        if (minutes > 0) {
            System.out.println("│ • Scan duration: " + String.format("%-24s", minutes + "m " + seconds + "s") + "│");
        } else {
            System.out.println("│ • Scan duration: " + String.format("%-24s", seconds + " seconds") + "│");
        }
        
        String outputFile = config.getOutputFile() != null ? config.getOutputFile() : "scan_results.json";
        System.out.println("│ • Report saved to: " + String.format("%-21s", outputFile) + "│");
        System.out.println("└─────────────────────────────────────────────┘");

        // ✅ Дополнительная информация в зависимости от результатов
        if (findings.isEmpty()) {
            System.out.println("✅ Excellent! No security vulnerabilities detected.");
        } else if (criticalCount + highCount > 0) {
            System.out.println("🚨 ATTENTION: Critical or High severity vulnerabilities found!");
        } else {
            System.out.println("⚠️  Review medium and low severity findings for potential improvements.");
        }

        // ✅ ДОБАВЛЕНО: Информация о фильтрации
        if (falsePositivesFiltered.get() > 0) {
            System.out.println("🔍 Note: " + falsePositivesFiltered.get() + " false positives were filtered for accuracy");
        }
    }

    /**
     * ✅ ДОБАВЛЕНО: Логирует детальную информацию о найденных уязвимостях
     */
    private void logFindings(List<Finding> findings) {
        if (findings.isEmpty()) {
            System.out.println("✅ No security findings detected");
            return;
        }
        
        System.out.println("\n🔍 SECURITY FINDINGS DETECTED (" + findings.size() + " total):");
        for (Finding finding : findings) {
            String severityPrefix = getSeverityPrefix(finding.getSeverity());
            
            System.out.println(severityPrefix + " [" + finding.getId() + "] " + 
                             finding.getTitle() + ": " + 
                             finding.getDescription().split("\n")[0]);
            
            if (config.isVerbose()) {
                System.out.println("   Affected Resource: " + finding.getEndpoint());
                String remediation = finding.getRemediation();
                if (remediation != null && !remediation.isEmpty()) {
                    System.out.println("   Remediation: " + remediation.split("\n")[0]);
                }
            }
        }
    }

    /**
     * ✅ ДОБАВЛЕНО: Возвращает префикс для уровня серьезности
     */
    private String getSeverityPrefix(Severity severity) {
        switch (severity) {
            case CRITICAL: return "🔴 CRITICAL";
            case HIGH: return "🟠 HIGH";
            case MEDIUM: return "🟡 MEDIUM";
            case LOW: return "🟢 LOW";
            case INFO: return "🔵 INFO";
            default: return "⚪ UNKNOWN";
        }
    }

    /**
     * Resolves endpoints from multiple sources in priority order.
     *
     * @return List of endpoints to scan
     */
    private List<EndpointInfo> resolveEndpoints() {
        List<EndpointInfo> endpoints = new ArrayList<>();

        // ✅ 1. Пробуем загрузить из OpenAPI спецификации
        if (config.getOpenApiSpecPath() != null && !config.getOpenApiSpecPath().isEmpty()) {
            try {
                logger.info("Loading endpoints from OpenAPI spec: {}", config.getOpenApiSpecPath());
                var openAPI = OpenApiLoader.load(config.getOpenApiSpecPath());
                endpoints.addAll(OpenApiLoader.getEndpoints(openAPI));
                logger.info("Discovered {} endpoints from OpenAPI", endpoints.size());
            } catch (Exception e) {
                logger.warn("Failed to load endpoints from OpenAPI spec: {}", e.getMessage());
                if (config.isVerbose()) {
                    logger.debug("OpenAPI loading error:", e);
                }
            }
        }

        // ✅ 2. Если OpenAPI не дал результатов и discovery включен - используем discovery
        if (endpoints.isEmpty() && config.isDiscoveryEnabled()) {
            logger.info("No endpoints from OpenAPI. Attempting endpoint discovery...");
            endpoints = discoveryService.discoverEndpoints();
        }

        // ✅ 3. Если всё еще нет эндпоинтов - используем предоставленные
        if (endpoints.isEmpty() && !config.getEndpoints().isEmpty()) {
            endpoints = config.getEndpoints();
            logger.info("Using {} provided endpoints", endpoints.size());
        }

        // ✅ ИСПРАВЛЕНИЕ: Проверяем и исправляем baseUrl, если он некорректный
        List<EndpointInfo> fixedEndpoints = new ArrayList<>();
        String targetUrl = config.getTargetUrl();
        for (EndpointInfo ep : endpoints) {
            if ("/".equals(ep.getBaseUrl()) || ep.getBaseUrl() == null || ep.getBaseUrl().startsWith("/")) {
                // Заменяем некорректный baseUrl на targetUrl из конфига
                fixedEndpoints.add(new EndpointInfo(
                    targetUrl,
                    ep.getPath(),
                    ep.getMethod(),
                    ep.getContentType(),
                    ep.getRequestBody(),
                    ep.isRequiresAuthentication()
                ));
                System.out.println("🔧 DEBUG: Fixed baseUrl for endpoint: " + ep.getMethod() + " " + ep.getPath() + " -> " + targetUrl);
            } else {
                fixedEndpoints.add(ep);
            }
        }
        endpoints = fixedEndpoints;

        return endpoints;
    }

    /**
     * Applies GOST gateway URL transformation to all endpoints.
     *
     * @param endpoints Original endpoints
     * @return Endpoints with GOST gateway URL
     */
    private List<EndpointInfo> applyGostToEndpoints(List<EndpointInfo> endpoints) {
        List<EndpointInfo> gostEndpoints = new ArrayList<>();
        String gostBaseUrl = "https://api.gost.bankingapi.ru:8443";
        
        for (EndpointInfo endpoint : endpoints) {
            // Создаем новый EndpointInfo с GOST baseUrl
            EndpointInfo gostEndpoint = new EndpointInfo(
                gostBaseUrl,
                endpoint.getPath(),
                endpoint.getMethod(),
                endpoint.getContentType(),
                endpoint.getRequestBody(),
                endpoint.isRequiresAuthentication()
            );
            gostEndpoints.add(gostEndpoint);
        }
        
        logger.info("Applied GOST gateway transformation to {} endpoints", gostEndpoints.size());
        return gostEndpoints;
    }

    /**
     * Logs the current progress of the scan.
     */
    private void logProgress() {
        int completed = completedTasks.get();
        int total = totalTasks.get();
        double percentComplete = (double) completed / total * 100;

        logger.info("Scan progress: {}% ({}/{} tasks completed)",
                String.format("%.1f", percentComplete), completed, total);
    }

    /**
     * Creates an empty scan result when no endpoints are found.
     *
     * @return An empty scan result
     */
    private ScanResult createEmptyScanResult() {
        scanEndTime = LocalDateTime.now();
        ScanResult result = new ScanResult(config.getTargetUrl(), List.of());
        result.setScanStartTime(scanStartTime);
        result.setScanEndTime(scanEndTime);
        return result;
    }
}
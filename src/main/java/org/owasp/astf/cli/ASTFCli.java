package org.owasp.astf.cli;

import org.owasp.astf.core.Scanner;
import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.result.ScanResult;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.reporting.JsonReportGenerator;

public class ASTFCli {
    // ✅ ДОБАВЛЕНО: Глобальный флаг verbose для легкого доступа
    private static boolean globalVerbose = false;

    public static void main(String[] args) {
        if (args.length == 0) {
            printUsage();
            System.exit(1);
        }

        // Проверяем команду scan
        if (!"scan".equals(args[0])) {
            System.out.println("❌ Unknown command: " + args[0]);
            printUsage();
            System.exit(1);
        }

        ScanConfig config = null;
        try {
            config = parseArguments(args);
            globalVerbose = config.isVerbose();
            
            // Установка значения по умолчанию для output file
            if (config.getOutputFile() == null || config.getOutputFile().isEmpty()) {
                config.setOutputFile("scan_results.json");
            }

            System.out.println("🚀 Starting API Security Scan");
            System.out.println("🔗 Target: " + config.getTargetUrl());
            if (config.getOpenApiSpecPath() != null) {
                System.out.println("📄 OpenAPI: " + config.getOpenApiSpecPath());
                // ✅ ДОБАВЛЕНО: Определяем формат OpenAPI файла
                String openApiFormat = getOpenApiFormat(config.getOpenApiSpecPath());
                System.out.println("📋 OpenAPI Format: " + openApiFormat);
            }
            if (config.isUseGost()) {
                System.out.println("🌐 GOST Gateway: Enabled");
            }
            System.out.println("💾 Output: " + config.getOutputFile());
            if (globalVerbose) {
                System.out.println("🔍 Verbose Mode: Enabled - Detailed logging activated");
            }

            // ✅ ДОБАВЛЕНО: Подробная информация в verbose mode
            if (globalVerbose) {
                logVerboseConfigInfo(config);
            }

            // Запуск сканера
            Scanner scanner = new Scanner(config);
            ScanResult result = scanner.scan(); // ✅ Получаем результат
            
            // ✅ Показываем результаты в консоли
            printResults(result, globalVerbose);
            
            // ✅ Сохранение в файл
            saveReport(result, config.getOutputFile(), globalVerbose);
            
            System.exit(0); // Успешное завершение
            
        } catch (Exception e) {
            System.err.println("❌ Error during scanning: " + e.getMessage());
            if (globalVerbose || isVerbose(args)) {
                System.err.println("🔍 Verbose Error Details:");
                e.printStackTrace();
            } else {
                System.err.println("💡 Use --verbose for detailed error information");
            }
            System.exit(1);
        }
    }

    /**
     * ✅ Парсит аргументы командной строки
     */
    private static ScanConfig parseArguments(String[] args) {
        ScanConfig config = new ScanConfig();
        
        for (int i = 1; i < args.length; i++) {
            switch (args[i]) {
                case "--target":
                    if (i + 1 < args.length) {
                        config.setTargetUrl(args[++i]);
                        System.out.println("✅ Set target: " + config.getTargetUrl());
                    }
                    break;
                case "--auth-header":
                    if (i + 1 < args.length) {
                        config.setAuthHeader(args[++i]);
                        System.out.println("✅ Set auth header: " + maskToken(config.getAuthHeader()));
                    }
                    break;
                case "--openapi":
                    if (i + 1 < args.length) {
                        String openApiFile = args[++i];
                        // ✅ ИСПРАВЛЕНИЕ: Проверяем существование файла и его формат
                        if (isValidOpenApiFile(openApiFile)) {
                            config.setOpenApiSpecPath(openApiFile);
                            System.out.println("✅ Set OpenAPI spec: " + config.getOpenApiSpecPath());
                        } else {
                            System.err.println("❌ Invalid OpenAPI file: " + openApiFile + 
                                " (must be .yaml, .yml, or .json and exist)");
                        }
                    }
                    break;
                case "--use-gost":
                    config.setUseGost(true);
                    System.out.println("✅ GOST gateway enabled");
                    break;
                case "--output-file":
                    if (i + 1 < args.length) {
                        config.setOutputFile(args[++i]);
                        System.out.println("✅ Set output file: " + config.getOutputFile());
                    }
                    break;
                case "--verbose":
                    // ✅ ДОБАВЛЕНО: Поддержка --verbose с установкой системного свойства
                    config.setVerbose(true);
                    System.setProperty("astf.verbose", "true");
                    System.out.println("✅ Verbose mode enabled");
                    break;
                case "--threads":
                    if (i + 1 < args.length) {
                        try {
                            config.setThreads(Integer.parseInt(args[++i]));
                            System.out.println("✅ Set threads: " + config.getThreads());
                        } catch (NumberFormatException e) {
                            System.err.println("⚠️  Invalid threads value: " + args[i]);
                        }
                    }
                    break;
                case "--timeout":
                    if (i + 1 < args.length) {
                        try {
                            config.setTimeoutMinutes(Integer.parseInt(args[++i]));
                            System.out.println("✅ Set timeout: " + config.getTimeoutMinutes() + " minutes");
                        } catch (NumberFormatException e) {
                            System.err.println("⚠️  Invalid timeout value: " + args[i]);
                        }
                    }
                    break;
                case "--output-format":
                    if (i + 1 < args.length) {
                        // ✅ ИСПРАВЛЕНИЕ: Преобразуем строку в enum с обработкой ошибок
                        try {
                            config.setOutputFormat(ScanConfig.OutputFormat.valueOf(args[++i].toUpperCase()));
                            System.out.println("✅ Set output format: " + config.getOutputFormat());
                        } catch (IllegalArgumentException e) {
                            System.err.println("⚠️ Unsupported output format. Using JSON.");
                            config.setOutputFormat(ScanConfig.OutputFormat.JSON);
                        }
                    }
                    break;
                default:
                    // Игнорируем неизвестные аргументы
                    System.out.println("⚠️  Unknown argument: " + args[i]);
            }
        }

        // Проверка обязательных параметров
        if (config.getTargetUrl() == null || config.getTargetUrl().isEmpty()) {
            throw new IllegalArgumentException("Target URL is required (--target)");
        }

        return config;
    }

    /**
     * ✅ ДОБАВЛЕНО: Логирует подробную информацию о конфигурации в verbose mode
     */
    private static void logVerboseConfigInfo(ScanConfig config) {
        System.out.println("\n🔍 VERBOSE CONFIGURATION DETAILS:");
        System.out.println("=================================");
        System.out.println("Target URL: " + config.getTargetUrl());
        System.out.println("OpenAPI Spec: " + (config.getOpenApiSpecPath() != null ? config.getOpenApiSpecPath() : "Not provided"));
        System.out.println("GOST Gateway: " + (config.isUseGost() ? "Enabled" : "Disabled"));
        System.out.println("Output File: " + config.getOutputFile());
        System.out.println("Output Format: " + config.getOutputFormat());
        System.out.println("Threads: " + config.getThreads());
        System.out.println("Timeout: " + config.getTimeoutMinutes() + " minutes");
        System.out.println("Discovery Enabled: " + config.isDiscoveryEnabled());
        System.out.println("Max RPS: " + config.getMaxRequestsPerSecond());
        System.out.println("Follow Redirects: " + config.isFollowRedirects());
        
        if (config.getAuthHeader() != null) {
            System.out.println("Auth Header: " + maskToken(config.getAuthHeader()));
        }
        
        System.out.println("=================================\n");
    }

    /**
     * ✅ ДОБАВЛЕНО: Проверяет валидность OpenAPI файла
     */
    private static boolean isValidOpenApiFile(String filePath) {
        if (filePath == null || filePath.trim().isEmpty()) {
            return false;
        }
        
        // Проверяем расширение файла
        String lowerCasePath = filePath.toLowerCase();
        boolean validExtension = lowerCasePath.endsWith(".yaml") || 
                                lowerCasePath.endsWith(".yml") || 
                                lowerCasePath.endsWith(".json");
        
        if (!validExtension) {
            System.err.println("❌ Invalid file extension. Supported: .yaml, .yml, .json");
            return false;
        }
        
        // Проверяем существование файла
        java.io.File file = new java.io.File(filePath);
        if (!file.exists()) {
            System.err.println("❌ OpenAPI file not found: " + filePath);
            System.err.println("💡 Current directory: " + System.getProperty("user.dir"));
            return false;
        }
        
        // Проверяем, что файл не пустой
        if (file.length() == 0) {
            System.err.println("❌ OpenAPI file is empty: " + filePath);
            return false;
        }
        
        return true;
    }

    /**
     * ✅ ДОБАВЛЕНО: Определяет формат OpenAPI файла
     */
    private static String getOpenApiFormat(String filePath) {
        if (filePath == null) return "Unknown";
        
        String lowerCasePath = filePath.toLowerCase();
        if (lowerCasePath.endsWith(".json")) {
            return "JSON";
        } else if (lowerCasePath.endsWith(".yaml") || lowerCasePath.endsWith(".yml")) {
            return "YAML";
        } else {
            return "Unknown (will try to auto-detect)";
        }
    }

    /**
     * ✅ Маскирует токен в логах для безопасности
     */
    private static String maskToken(String authHeader) {
        if (authHeader == null || authHeader.length() < 10) {
            return "[hidden]";
        }
        return authHeader.substring(0, 10) + "..." + authHeader.substring(authHeader.length() - 4);
    }

    /**
     * ✅ Выводит результаты сканирования в консоль
     */
    private static void printResults(ScanResult result, boolean verbose) {
        System.out.println("\n📊 SCAN RESULTS");
        System.out.println("================");
        
        if (result.getFindings().isEmpty()) {
            System.out.println("✅ No security vulnerabilities found!");
            System.out.println("💡 The API appears to be well-protected against tested attacks.");
        } else {
            System.out.println("⚠️  Found " + result.getFindings().size() + " security issues:");
            System.out.println();
            
            for (Finding finding : result.getFindings()) {
                String severityIcon = getSeverityIcon(finding.getSeverity());
                // ✅ ИСПРАВЛЕНИЕ: Используем правильные методы - getId() и getEndpoint()
                System.out.println(severityIcon + " [" + finding.getSeverity() + "] " + 
                    finding.getId() + ": " + finding.getEndpoint());
                
                if (verbose) {
                    // ✅ ДОБАВЛЕНО: Подробная информация в verbose mode
                    System.out.println("   Description: " + finding.getDescription());
                    System.out.println("   Remediation: " + finding.getRemediation());
                    System.out.println("   ---");
                } else {
                    System.out.println("   Description: " + finding.getDescription().split("\n")[0]);
                }
                System.out.println();
            }
        }
        
        // Показываем метрики
        System.out.println("📈 SCAN METRICS");
        System.out.println("===============");
        System.out.println("Start Time: " + result.getScanStartTime());
        System.out.println("End Time: " + result.getScanEndTime());
        if (result.getScanStartTime() != null && result.getScanEndTime() != null) {
            long duration = java.time.Duration.between(result.getScanStartTime(), result.getScanEndTime()).toSeconds();
            System.out.println("Duration: " + duration + " seconds");
        }

        // ✅ ДОБАВЛЕНО: Детальная статистика в verbose mode
        if (verbose) {
            printDetailedMetrics(result);
        }
    }

    /**
     * ✅ ДОБАВЛЕНО: Выводит детальную статистику сканирования
     */
    private static void printDetailedMetrics(ScanResult result) {
        System.out.println("\n🔍 DETAILED SCAN METRICS:");
        System.out.println("=========================");
        
        // Подсчитываем находки по уровням серьезности
        int critical = 0, high = 0, medium = 0, low = 0, info = 0;
        for (Finding finding : result.getFindings()) {
            switch (finding.getSeverity()) {
                case CRITICAL: critical++; break;
                case HIGH: high++; break;
                case MEDIUM: medium++; break;
                case LOW: low++; break;
                case INFO: info++; break;
            }
        }
        
        System.out.println("Findings by Severity:");
        System.out.println("  🔴 CRITICAL: " + critical);
        System.out.println("  🟠 HIGH: " + high);
        System.out.println("  🟡 MEDIUM: " + medium);
        System.out.println("  🟢 LOW: " + low);
        System.out.println("  🔵 INFO: " + info);
        
        System.out.println("\nScan Configuration:");
        System.out.println("  Target: " + result.getTargetUrl());
        System.out.println("  Total Findings: " + result.getFindings().size());
        System.out.println("  Scan Duration: " + 
            java.time.Duration.between(result.getScanStartTime(), result.getScanEndTime()).toSeconds() + " seconds");
        System.out.println("=========================");
    }

    /**
     * ✅ Возвращает иконку для уровня серьезности
     */
    private static String getSeverityIcon(org.owasp.astf.core.result.Severity severity) {
        switch (severity) {
            case CRITICAL: return "🔴";
            case HIGH: return "🟠"; 
            case MEDIUM: return "🟡";
            case LOW: return "🟢";
            case INFO: return "🔵";
            default: return "⚪";
        }
    }

    /**
     * ✅ Сохраняет отчёт в файл
     */
    private static void saveReport(ScanResult result, String outputFile, boolean verbose) {
        try {
            if (verbose) {
                System.out.println("💾 Generating detailed report: " + outputFile);
            } else {
                System.out.println("💾 Generating report: " + outputFile);
            }
            
            JsonReportGenerator reportGenerator = new JsonReportGenerator();
            
            // ✅ ИСПРАВЛЕНИЕ: Используем правильный метод generateReport()
            reportGenerator.generateReport(result, outputFile);
            
            System.out.println("✅ Report successfully saved to: " + outputFile);
            
            // ✅ Дополнительная информация о файле
            java.io.File file = new java.io.File(outputFile);
            if (file.exists()) {
                if (verbose) {
                    System.out.println("📁 File size: " + file.length() + " bytes");
                    System.out.println("📝 Findings in report: " + result.getFindings().size());
                    System.out.println("📁 Absolute path: " + file.getAbsolutePath());
                }
            } else {
                System.err.println("❌ Report file was not created: " + outputFile);
            }
            
        } catch (Exception e) {
            System.err.println("❌ Failed to save report: " + e.getMessage());
            System.err.println("💡 Check if the output directory exists and is writable");
            
            // ✅ ДОБАВЛЕНО: Более детальная диагностика в verbose mode
            if (verbose) {
                System.err.println("🔍 Detailed Diagnostic Info:");
                System.err.println("  - Output file: " + outputFile);
                System.err.println("  - Current directory: " + System.getProperty("user.dir"));
                System.err.println("  - File separator: " + java.io.File.separator);
                System.err.println("  - User home: " + System.getProperty("user.home"));
                System.err.println("  - Temp directory: " + System.getProperty("java.io.tmpdir"));
                
                e.printStackTrace();
            }
        }
    }

    /**
     * ✅ Проверяет наличие флага --verbose
     */
    private static boolean isVerbose(String[] args) {
        for (String arg : args) {
            if ("--verbose".equals(arg)) {
                return true;
            }
        }
        return false;
    }

    /**
     * ✅ Показывает справку по использованию
     */
    private static void printUsage() {
        System.out.println("OWASP API Security Testing Framework");
        System.out.println("=====================================");
        System.out.println();
        System.out.println("Usage:");
        System.out.println("  java -jar astf.jar scan --target <url> [OPTIONS]");
        System.out.println();
        System.out.println("Required:");
        System.out.println("  --target <url>              Target API URL (e.g., https://api.example.com)");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  --auth-header <header>      Authentication header (e.g., \"Authorization: Bearer token\")");
        System.out.println("  --openapi <file>            Load endpoints from OpenAPI specification (YAML or JSON)");
        System.out.println("  --use-gost                  Use GOST gateway for vbank.open.bankingapi.ru");
        System.out.println("  --output-file <file>        Output file for results (default: scan_results.json)");
        System.out.println("  --output-format <format>    Output format: json, html (default: json)");
        System.out.println("  --threads <number>          Number of concurrent threads (default: 10)");
        System.out.println("  --timeout <minutes>         Scan timeout in minutes (default: 30)");
        System.out.println("  --verbose                   Enable verbose logging with detailed output");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  java -jar astf.jar scan --target https://vbank.open.bankingapi.ru \\");
        System.out.println("    --auth-header \"Authorization: Bearer token\" --openapi spec.yaml --verbose");
        System.out.println();
        System.out.println("  java -jar astf.jar scan --target https://vbank.open.bankingapi.ru \\");
        System.out.println("    --use-gost --output-file my_scan.json --threads 5");
        System.out.println();
        System.out.println("  java -jar astf.jar scan --target https://vbank.open.bankingapi.ru \\");
        System.out.println("    --auth-header \"Authorization: Bearer token\" --openapi spec.json --output-file results.json --verbose");
        System.out.println();
        System.out.println("Verbose Mode Benefits:");
        System.out.println("  • Detailed configuration information");
        System.out.println("  • Full finding descriptions and remediation steps");
        System.out.println("  • Comprehensive scan metrics and statistics");
        System.out.println("  • Enhanced error diagnostics and debugging");
    }
}
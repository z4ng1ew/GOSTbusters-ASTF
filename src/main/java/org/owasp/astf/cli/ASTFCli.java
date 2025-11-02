package org.owasp.astf.cli;

import org.owasp.astf.core.Scanner;
import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.result.ScanResult;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.report.JsonReportGenerator;

public class ASTFCli {
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

        try {
            ScanConfig config = parseArguments(args);
            
            // Установка значения по умолчанию для output file
            if (config.getOutputFile() == null || config.getOutputFile().isEmpty()) {
                config.setOutputFile("scan_results.json");
            }

            System.out.println("🚀 Starting API Security Scan");
            System.out.println("🔗 Target: " + config.getTargetUrl());
            if (config.getOpenApiSpecPath() != null) {
                System.out.println("📄 OpenAPI: " + config.getOpenApiSpecPath());
            }
            if (config.isUseGost()) {
                System.out.println("🌐 GOST Gateway: Enabled");
            }

            // Запуск сканера
            Scanner scanner = new Scanner(config);
            ScanResult result = scanner.scan(); // ✅ Получаем результат
            
            // ✅ Показываем результаты в консоли
            printResults(result);
            
            // ✅ Сохранение в файл
            saveReport(result, config.getOutputFile());
            
        } catch (Exception e) {
            System.err.println("❌ Error during scanning: " + e.getMessage());
            if (isVerbose(args)) {
                e.printStackTrace();
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
                    if (i + 1 < args.length) config.setTargetUrl(args[++i]);
                    break;
                case "--auth-header":
                    if (i + 1 < args.length) config.setAuthHeader(args[++i]);
                    break;
                case "--openapi":
                    if (i + 1 < args.length) config.setOpenApiSpecPath(args[++i]);
                    break;
                case "--use-gost":
                    config.setUseGost(true);
                    break;
                case "--output-file":
                    if (i + 1 < args.length) config.setOutputFile(args[++i]);
                    break;
                case "--verbose":
                    config.setVerbose(true);
                    break;
                case "--threads":
                    if (i + 1 < args.length) config.setThreads(Integer.parseInt(args[++i]));
                    break;
                case "--timeout":
                    if (i + 1 < args.length) config.setTimeoutMinutes(Integer.parseInt(args[++i]));
                    break;
                case "--output-format":
                    if (i + 1 < args.length) config.setOutputFormat(args[++i]);
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
     * ✅ Выводит результаты сканирования в консоль
     */
    private static void printResults(ScanResult result) {
        System.out.println("\n📊 SCAN RESULTS");
        System.out.println("================");
        
        if (result.getFindings().isEmpty()) {
            System.out.println("✅ No security vulnerabilities found!");
            System.out.println("💡 The API appears to be well-protected against tested attacks.");
        } else {
            System.out.println("⚠️  Found " + result.getFindings().size() + " security issues:");
            System.out.println();
            
            for (Finding finding : result.getFindings()) {
                System.out.println("🔍 [" + finding.getSeverity() + "] " + finding.getId());
                System.out.println("   " + finding.getName());
                System.out.println("   URL: " + finding.getAffectedResource());
                System.out.println("   Description: " + finding.getDescription().split("\n")[0]);
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
    }

    /**
     * ✅ Сохраняет отчёт в файл
     */
    private static void saveReport(ScanResult result, String outputFile) {
        try {
            JsonReportGenerator reportGenerator = new JsonReportGenerator();
            reportGenerator.generate(result, outputFile);
            System.out.println("💾 Report saved to: " + outputFile);
        } catch (Exception e) {
            System.err.println("❌ Failed to save report: " + e.getMessage());
            // Не прерываем выполнение, т.к. сканирование уже завершено
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
        System.out.println("  --openapi <file>            Load endpoints from OpenAPI specification");
        System.out.println("  --use-gost                  Use GOST gateway for vbank.open.bankingapi.ru");
        System.out.println("  --output-file <file>        Output file for results (default: scan_results.json)");
        System.out.println("  --output-format <format>    Output format: json, html (default: json)");
        System.out.println("  --threads <number>          Number of concurrent threads (default: 10)");
        System.out.println("  --timeout <minutes>         Scan timeout in minutes (default: 30)");
        System.out.println("  --verbose                   Enable verbose logging");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  java -jar astf.jar scan --target https://vbank.open.bankingapi.ru \\");
        System.out.println("    --auth-header \"Authorization: Bearer token\" --openapi spec.yaml --verbose");
        System.out.println();
        System.out.println("  java -jar astf.jar scan --target https://vbank.open.bankingapi.ru \\");
        System.out.println("    --use-gost --output-file my_scan.json --threads 5");
    }
}
package org.owasp.astf.cli;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.Scanner;
import org.owasp.astf.core.config.ConfigLoader; // ✅ ИМПОРТ ДОБАВЛЕН
import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.result.ScanResult;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.IOException;
import java.util.concurrent.Callable;

/**
 * Command line interface for running API security scans in CI/CD environments.
 * This command provides a simplified interface for automated security testing.
 */
@Command(
        name = "scan",
        description = "Run API security scan",
        mixinStandardHelpOptions = true
)
public class CICommand implements Callable<Integer> {
    private static final Logger logger = LogManager.getLogger(CICommand.class);

    @Option(names = {"-c", "--config"}, description = "Path to configuration file (YAML/JSON)")
    private String configFile;

    @Option(names = {"-t", "--target"}, description = "Target API URL")
    private String targetUrl;

    @Option(names = {"--client-id"}, description = "Open Banking client ID (e.g., team179)")
    private String clientId;

    @Option(names = {"--client-secret"}, description = "Open Banking client secret")
    private String clientSecret;

    @Option(names = {"--bank-id"}, description = "Bank ID for Open Banking (vbank, abank, sbank)")
    private String bankId;

    @Option(names = {"--gost"}, description = "Enable GOST gateway integration")
    private boolean useGost = false;

    @Option(names = {"--output"}, description = "Output file path (JSON, HTML, PDF)")
    private String outputFile;

    @Option(names = {"--format"}, description = "Output format (json, html, pdf)")
    private String outputFormat = "json";

    @Option(names = {"--verbose", "-v"}, description = "Enable verbose logging")
    private boolean verbose = false;

    @Option(names = {"--threads"}, description = "Number of concurrent threads", defaultValue = "10")
    private int threads = 10;

    @Option(names = {"--timeout"}, description = "Scan timeout in minutes", defaultValue = "30")
    private int timeoutMinutes = 30;

    @Override
    public Integer call() throws Exception {
        logger.info("🚀 Starting API security scan (GOSTbusters ASTF)");

        ScanConfig config = null;

        try {
            // ✅ ЗАГРУЗКА КОНФИГУРАЦИИ
            if (configFile != null) {
                // Загружаем из файла
                config = ConfigLoader.load(configFile);
                System.out.println("✅ Configuration loaded from: " + configFile);
            } else {
                // Создаем из командной строки
                config = createConfigFromCommandLine();
                System.out.println("✅ Configuration created from command line arguments");
            }

            // ✅ ВАЛИДАЦИЯ КОНФИГУРАЦИИ
            if (config.getTargetUrl() == null || config.getTargetUrl().isEmpty()) {
                logger.error("❌ ERROR: Target URL is required. Use --target or --config option.");
                System.out.println("❌ ERROR: No target URL specified. Use --target option or provide config file.");
                return 1; // Exit with error code
            }

            // ✅ ПОКАЗ КОНФИГУРАЦИИ (для отладки)
            System.out.println("\n🔍 Scan Configuration:");
            System.out.println("   Target: " + config.getTargetUrl());
            System.out.println("   Bank: " + config.getBankId());
            System.out.println("   GOST: " + config.isUseGost());
            System.out.println("   Threads: " + config.getThreads());
            System.out.println("   Timeout: " + config.getTimeoutMinutes() + " minutes");
            System.out.println("   Verbose: " + config.isVerbose());

            // ✅ ВЫПОЛНЕНИЕ СКАНИРОВАНИЯ
            logger.info("Executing scan against {}", config.getTargetUrl());
            System.out.println("\n🔍 Starting scan...");
            
            Scanner scanner = new Scanner(config);
            ScanResult results = scanner.scan();

            // ✅ ГЕНЕРАЦИЯ ОТЧЁТА
            if (config.getOutputFile() != null) {
                generateReport(results, config.getOutputFile());
            }

            // ✅ ВЫВОД СТАТИСТИКИ
            printScanStatistics(results);

            // ✅ ОПРЕДЕЛЕНИЕ СТАТУСА ВЫПОЛНЕНИЯ
            boolean hasCriticalFindings = results.getFindings().stream()
                .anyMatch(finding -> finding.getSeverity() == org.owasp.astf.core.result.Severity.CRITICAL);

            if (hasCriticalFindings) {
                System.out.println("\n🚨 CRITICAL VULNERABILITIES FOUND!");
                System.out.println("   Build should fail due to security issues.");
                return 1; // Exit with error code
            } else {
                System.out.println("\n✅ Scan completed successfully!");
                System.out.println("   No critical vulnerabilities detected.");
                return 0; // Exit successfully
            }

        } catch (IOException e) {
            logger.error("❌ Configuration error: {}", e.getMessage());
            System.out.println("❌ Configuration error: " + e.getMessage());
            return 1;
        } catch (Exception e) {
            logger.error("❌ Scan execution error: {}", e.getMessage());
            System.out.println("❌ Scan execution error: " + e.getMessage());
            e.printStackTrace();
            return 1;
        }
    }

    /**
     * ✅ Создает конфигурацию из аргументов командной строки
     */
    private ScanConfig createConfigFromCommandLine() {
        ScanConfig config = new ScanConfig();
        
        // ✅ Основные параметры
        config.setTargetUrl(targetUrl);
        config.setThreads(threads);
        config.setTimeoutMinutes(timeoutMinutes);
        config.setVerbose(verbose);
        config.setUseGost(useGost);
        
        // ✅ Open Banking параметры
        config.setClientId(clientId);
        config.setClientSecret(clientSecret);
        config.setBankId(bankId);
        
        // ✅ Параметры вывода
        config.setOutputFormat(outputFormat);
        config.setOutputFile(outputFile);
        
        // ✅ Установка заголовков по умолчанию
        if (clientId != null && clientSecret != null) {
            // Эти заголовки будут заполнены через OpenBankingAuthenticator
            System.out.println("🔐 Open Banking credentials detected: " + clientId);
        }

        return config;
    }

    /**
     * ✅ Генерирует отчет в указанном формате
     */
    private void generateReport(ScanResult results, String outputPath) {
        try {
            if (outputPath.endsWith(".pdf")) {
                // Проверяем, есть ли PDF-генератор
                Class.forName("org.owasp.astf.reporting.PdfReportGenerator");
                org.owasp.astf.reporting.PdfReportGenerator.generate(results.getFindings(), outputPath);
                System.out.println("📄 PDF report saved: " + outputPath);
            } else if (outputPath.endsWith(".html")) {
                org.owasp.astf.reporting.HtmlReportGenerator generator = new org.owasp.astf.reporting.HtmlReportGenerator();
                generator.generateReport(results, outputPath);
                System.out.println("🌐 HTML report saved: " + outputPath);
            } else if (outputPath.endsWith(".json")) {
                org.owasp.astf.reporting.JsonReportGenerator generator = new org.owasp.astf.reporting.JsonReportGenerator();
                generator.generateReport(results, outputPath);
                System.out.println("📄 JSON report saved: " + outputPath);
            } else {
                System.out.println("⚠️ Unknown output format: " + outputPath);
            }
        } catch (Exception e) {
            System.out.println("❌ Error generating report: " + e.getMessage());
            logger.error("Error generating report: {}", e.getMessage());
        }
    }

    /**
     * ✅ Выводит статистику сканирования
     */
    private void printScanStatistics(ScanResult results) {
        long totalFindings = results.getFindings().size();
        long criticalCount = results.getFindings().stream()
            .mapToLong(f -> f.getSeverity() == org.owasp.astf.core.result.Severity.CRITICAL ? 1 : 0).sum();
        long highCount = results.getFindings().stream()
            .mapToLong(f -> f.getSeverity() == org.owasp.astf.core.result.Severity.HIGH ? 1 : 0).sum();
        long mediumCount = results.getFindings().stream()
            .mapToLong(f -> f.getSeverity() == org.owasp.astf.core.result.Severity.MEDIUM ? 1 : 0).sum();
        long lowCount = results.getFindings().stream()
            .mapToLong(f -> f.getSeverity() == org.owasp.astf.core.result.Severity.LOW ? 1 : 0).sum();
        long infoCount = results.getFindings().stream()
            .mapToLong(f -> f.getSeverity() == org.owasp.astf.core.result.Severity.INFO ? 1 : 0).sum();

        System.out.println("\n📊 SCAN RESULTS SUMMARY:");
        System.out.println("┌─────────────────────────────────────────────┐");
        System.out.println("│ • Total Findings:        " + String.format("%-18s", totalFindings) + "│");
        System.out.println("│ • Critical:              " + String.format("%-18s", criticalCount) + "│");
        System.out.println("│ • High:                  " + String.format("%-18s", highCount) + "│");
        System.out.println("│ • Medium:                " + String.format("%-18s", mediumCount) + "│");
        System.out.println("│ • Low:                   " + String.format("%-18s", lowCount) + "│");
        System.out.println("│ • Info:                  " + String.format("%-18s", infoCount) + "│");
        
        long durationSeconds = java.time.Duration.between(results.getScanStartTime(), results.getScanEndTime()).getSeconds();
        long minutes = durationSeconds / 60;
        long seconds = durationSeconds % 60;
        
        if (minutes > 0) {
            System.out.println("│ • Duration:              " + String.format("%-18s", minutes + "m " + seconds + "s") + "│");
        } else {
            System.out.println("│ • Duration:              " + String.format("%-18s", seconds + " seconds") + "│");
        }
        
        System.out.println("└─────────────────────────────────────────────┘");
    }
}
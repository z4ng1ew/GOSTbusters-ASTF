package org.owasp.astf.cli;

import org.owasp.astf.core.Scanner;
import org.owasp.astf.core.config.ConfigLoader; // ✅ ИМПОРТ ДОБАВЛЕН
import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.result.ScanResult;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.reporting.JsonReportGenerator;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.Callable;

/**
 * Command Line Interface for the GOSTbusters API Security Testing Framework.
 * 
 * This CLI provides a unified interface for running API security scans with support for:
 * - Configuration file loading (YAML/JSON)
 * - Command-line parameter overrides
 * - Open Banking Russia authentication
 * - GOST gateway integration
 * - Multi-bank API testing
 * - Professional reporting
 */
@Command(
    name = "astf",
    description = "GOSTbusters API Security Testing Framework - OWASP API Top 10 2023 compliant scanner",
    mixinStandardHelpOptions = true,
    version = "1.0.0"
)
public class ASTFCli implements Callable<Integer> {
    
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

    @Option(names = {"--format"}, description = "Output format (json, html, pdf)", defaultValue = "json")
    private String outputFormat = "json";

    @Option(names = {"--verbose", "-v"}, description = "Enable verbose logging")
    private boolean verbose = false;

    @Option(names = {"--threads"}, description = "Number of concurrent threads", defaultValue = "10")
    private int threads = 10;

    @Option(names = {"--timeout"}, description = "Scan timeout in minutes", defaultValue = "30")
    private int timeoutMinutes = 30;

    @Option(names = {"--openapi"}, description = "Path to OpenAPI specification file")
    private String openApiSpecPath;

    @Option(names = {"--auth-header"}, description = "Authentication header value")
    private String authHeader;

    public static void main(String[] args) {
        CommandLine cmd = new CommandLine(new ASTFCli());
        int exitCode = cmd.execute(args);
        System.exit(exitCode);
    }

    @Override
    public Integer call() throws Exception {
        System.out.println("🚀 GOSTbusters API Security Testing Framework (ASTF) v1.0");
        System.out.println("   OWASP API Security Top 10 2023 compliant");
        System.out.println("   Open Banking Russia v2.1 integration");
        System.out.println("   GOST cryptographic standards support");
        System.out.println();

        ScanConfig config = null;

        try {
            // ✅ ИСПРАВЛЕНО: Загрузка конфига из файла С ПОСЛЕДУЮЩИМ ПЕРЕОПРЕДЕЛЕНИЕМ CLI-ПАРАМЕТРАМИ
            if (configFile != null) {
                config = ConfigLoader.load(configFile); // ✅ Загрузка из YAML/JSON
                System.out.println("✅ Configuration loaded from: " + configFile);
            } else {
                config = new ScanConfig(); // ✅ Пустая конфигурация для CLI-аргументов
                System.out.println("📋 Using command-line configuration only");
            }

            // ✅ ПЕРЕОПРЕДЕЛЕНИЕ параметров из CLI (если указаны)
            if (targetUrl != null) config.setTargetUrl(targetUrl);
            if (clientId != null) config.setClientId(clientId);
            if (clientSecret != null) config.setClientSecret(clientSecret);
            if (bankId != null) config.setBankId(bankId);
            if (outputFile != null) config.setOutputFile(outputFile);
            if (outputFormat != null) config.setOutputFormat(outputFormat);
            if (openApiSpecPath != null) config.setOpenApiSpecPath(openApiSpecPath);
            if (authHeader != null) config.setAuthHeader(authHeader);
            config.setUseGost(useGost);
            config.setVerbose(verbose);
            config.setThreads(threads);
            config.setTimeoutMinutes(timeoutMinutes);

            // ✅ ВАЛИДАЦИЯ КОНФИГУРАЦИИ
            if (config.getTargetUrl() == null || config.getTargetUrl().isEmpty()) {
                System.err.println("❌ ERROR: Target URL is required. Use --target or --config option.");
                System.out.println("💡 Example: java -jar astf.jar --config configs/vbank.yaml");
                System.out.println("💡 Or: java -jar astf.jar --target https://vbank.open.bankingapi.ru --client-id team179 --client-secret ...");
                return 1;
            }

            // ✅ ПОКАЗ КОНФИГУРАЦИИ (для отладки)
            System.out.println("🔍 Scan Configuration:");
            System.out.println("   Target: " + config.getTargetUrl());
            System.out.println("   Bank: " + (config.getBankId() != null ? config.getBankId() : "unknown"));
            System.out.println("   GOST: " + config.isUseGost());
            System.out.println("   Threads: " + config.getThreads());
            System.out.println("   Timeout: " + config.getTimeoutMinutes() + " minutes");
            System.out.println("   Verbose: " + config.isVerbose());
            if (config.getOpenApiSpecPath() != null) {
                System.out.println("   OpenAPI: " + config.getOpenApiSpecPath());
            }
            System.out.println();

            // ✅ ЗАПУСК СКАНИРОВАНИЯ
            System.out.println("🔍 Starting API security scan...");
            Scanner scanner = new Scanner(config);
            ScanResult results = scanner.scan();

            // ✅ ВЫВОД РЕЗУЛЬТАТОВ
            printScanResults(results);

            // ✅ СОХРАНЕНИЕ ОТЧЁТА
            if (config.getOutputFile() != null) {
                saveReport(results, config.getOutputFile());
            }

            // ✅ ОПРЕДЕЛЕНИЕ СТАТУСА ВЫПОЛНЕНИЯ
            long criticalCount = results.getFindings().stream()
                .mapToLong(f -> f.getSeverity() == org.owasp.astf.core.result.Severity.CRITICAL ? 1 : 0).sum();
            
            if (criticalCount > 0) {
                System.out.println("\n🚨 CRITICAL VULNERABILITIES FOUND!");
                System.out.println("   Build should fail due to security issues.");
                return 1; // Exit with error code
            } else {
                System.out.println("\n✅ Scan completed successfully!");
                System.out.println("   No critical vulnerabilities detected.");
                return 0; // Exit successfully
            }

        } catch (IOException e) {
            System.err.println("❌ Configuration error: " + e.getMessage());
            e.printStackTrace();
            return 1;
        } catch (Exception e) {
            System.err.println("❌ Scan execution error: " + e.getMessage());
            if (verbose) {
                e.printStackTrace();
            } else {
                System.out.println("💡 Use --verbose for detailed error information");
            }
            return 1;
        }
    }

    /**
     * ✅ Выводит результаты сканирования в консоль
     */
    private void printScanResults(ScanResult results) {
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
        System.out.println("│ • Total findings:        " + String.format("%-18s", totalFindings) + "│");
        System.out.println("│ • 🔴 Critical:           " + String.format("%-18s", criticalCount) + "│");
        System.out.println("│ • 🟠 High:               " + String.format("%-18s", highCount) + "│");
        System.out.println("│ • 🟡 Medium:             " + String.format("%-18s", mediumCount) + "│");
        System.out.println("│ • 🟢 Low:                " + String.format("%-18s", lowCount) + "│");
        System.out.println("│ • 🔵 Info:               " + String.format("%-18s", infoCount) + "│");

        if (results.getScanStartTime() != null && results.getScanEndTime() != null) {
            long durationSeconds = java.time.Duration.between(results.getScanStartTime(), results.getScanEndTime()).getSeconds();
            long minutes = durationSeconds / 60;
            long seconds = durationSeconds % 60;
            if (minutes > 0) {
                System.out.println("│ • Duration:              " + String.format("%-18s", minutes + "m " + seconds + "s") + "│");
            } else {
                System.out.println("│ • Duration:              " + String.format("%-18s", seconds + " seconds") + "│");
            }
        }

        String outputFile = results.getConfig().getOutputFile() != null ? 
                           results.getConfig().getOutputFile() : "scan_results.json";
        System.out.println("│ • Report saved to:       " + String.format("%-18s", outputFile) + "│");
        System.out.println("└─────────────────────────────────────────────┘");

        // ✅ Вывод найденных уязвимостей (если есть)
        if (!results.getFindings().isEmpty()) {
            System.out.println("\n🔍 DETECTED SECURITY FINDINGS:");
            for (Finding finding : results.getFindings()) {
                String severityIcon = getSeverityIcon(finding.getSeverity());
                System.out.println(severityIcon + " [" + finding.getSeverity() + "] " + 
                                 finding.getTitle() + ": " + finding.getDescription().split("\n")[0]);
            }
        } else {
            System.out.println("\n✅ No security vulnerabilities detected!");
        }
    }

    /**
     * ✅ Возвращает эмодзи для уровня серьезности
     */
    private String getSeverityIcon(org.owasp.astf.core.result.Severity severity) {
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
    private void saveReport(ScanResult result, String outputFile) {
        try {
            System.out.println("💾 Generating report: " + outputFile);
            
            // ✅ ИСПРАВЛЕНО: Используем ReportGeneratorFactory для поддержки разных форматов
            org.owasp.astf.reporting.ReportGenerator generator = 
                org.owasp.astf.reporting.ReportGeneratorFactory.create(outputFile);
            generator.generateReport(result, outputFile);
            
            System.out.println("✅ Report saved successfully: " + outputFile);
            
        } catch (Exception e) {
            System.err.println("❌ Failed to save report: " + e.getMessage());
            e.printStackTrace();
        }
    }
}
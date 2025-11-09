package org.owasp.astf.integrations.providers.github;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.ScanResult;
import org.owasp.astf.core.result.Severity;
import org.owasp.astf.integrations.core.CIEnvironment;
import org.owasp.astf.integrations.core.ResultProcessor;
import org.owasp.astf.reporting.ReportGenerator;
import org.owasp.astf.reporting.ReportGeneratorFactory;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

/**
 * Processes and publishes scan results in GitHub Actions.
 * This class handles result formatting, reporting, and integration
 * with GitHub's annotation and check system.
 */
public class GitHubActionsResultProcessor implements ResultProcessor {
    private static final Logger logger = LogManager.getLogger(GitHubActionsResultProcessor.class);
    private static final DateTimeFormatter timeFormatter = DateTimeFormatter.ISO_LOCAL_DATE_TIME; // ✅ Уже объявлен

    @Override
    public boolean processResults(ScanResult results, CIEnvironment environment) {
        logger.info("Processing scan results for GitHub Actions");

        try {
            // ✅ ИСПРАВЛЕНО: Используем System.getenv() для workspace
            String workspaceDir = System.getenv("GITHUB_WORKSPACE");
            if (workspaceDir == null) {
                workspaceDir = Paths.get("").toAbsolutePath().toString(); // Текущая директория
            }
            
            Path outputDir = Paths.get(workspaceDir, "scan-results");
            if (!Files.exists(outputDir)) {
                Files.createDirectories(outputDir);
            }

            // Write summary as markdown
            writeSummaryMarkdown(results, outputDir);

            // ✅ ИСПРАВЛЕНО: Используем ScanConfig.OutputFormat вместо ReportGeneratorFactory.OutputFormat
            // Write detailed results as JSON
            createReport(results, ScanConfig.OutputFormat.JSON, outputDir.resolve("results.json").toFile());

            // Write SARIF format for GitHub Code Scanning
            createReport(results, ScanConfig.OutputFormat.SARIF, outputDir.resolve("results.sarif").toFile());

            // Write HTML report for detailed view
            createReport(results, ScanConfig.OutputFormat.HTML, outputDir.resolve("report.html").toFile());

            return true;
        } catch (Exception e) {
            logger.error("Failed to process scan results: {}", e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    @Override
    public boolean publishResults(ScanResult results, CIEnvironment environment) {
        logger.info("Publishing scan results in GitHub Actions");

        try {
            // ✅ ИСПРАВЛЕНО: Используем System.getenv() для GitHub Actions переменных
            String stepSummaryFile = System.getenv("GITHUB_STEP_SUMMARY");
            if (stepSummaryFile != null) {
                logger.info("Writing step summary to {}", stepSummaryFile);
                try (BufferedWriter writer = new BufferedWriter(new FileWriter(stepSummaryFile, true))) {
                    writer.write(generateSummary(results));
                }
            }

            // Create GitHub Actions annotations
            createAnnotations(results);

            // ✅ ИСПРАВЛЕНО: Проверяем, является ли окружение GitHub Actions
            if ("true".equalsIgnoreCase(System.getenv("GITHUB_ACTIONS"))) {
                String eventName = System.getenv("GITHUB_EVENT_NAME");
                if (eventName != null && eventName.contains("pull_request")) {
                    // This would be implemented using the GitHub API, but requires additional dependencies
                    logger.info("Skipping PR comment (requires GitHub API integration)");
                }
            }

            return true;
        } catch (Exception e) {
            logger.error("Failed to publish scan results: {}", e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    @Override
    public boolean shouldFailBuild(ScanResult results) { // ✅ ИСПРАВЛЕНО: только 1 параметр
        // ✅ ИСПРАВЛЕНО: Используем стандартные пороги (не переданные)
        Map<Severity, Integer> defaultThresholds = new HashMap<>();
        defaultThresholds.put(Severity.CRITICAL, 0);  // Любая критическая уязвимость = FAIL
        defaultThresholds.put(Severity.HIGH, 1);      // Более 1 высокой = FAIL
        defaultThresholds.put(Severity.MEDIUM, 5);    // Более 5 средних = FAIL
        defaultThresholds.put(Severity.LOW, 10);      // Более 10 низких = FAIL
        defaultThresholds.put(Severity.INFO, 100);    // Более 100 инфо = FAIL

        // ✅ ИСПРАВЛЕНО: Проверяем переменные окружения для переопределения порогов
        String criticalThreshold = System.getenv("ASTF_THRESHOLD_CRITICAL");
        String highThreshold = System.getenv("ASTF_THRESHOLD_HIGH");
        String mediumThreshold = System.getenv("ASTF_THRESHOLD_MEDIUM");
        String lowThreshold = System.getenv("ASTF_THRESHOLD_LOW");

        if (criticalThreshold != null) {
            try {
                defaultThresholds.put(Severity.CRITICAL, Integer.parseInt(criticalThreshold));
            } catch (NumberFormatException e) {
                logger.warn("Invalid critical threshold: {}", criticalThreshold);
            }
        }
        if (highThreshold != null) {
            try {
                defaultThresholds.put(Severity.HIGH, Integer.parseInt(highThreshold));
            } catch (NumberFormatException e) {
                logger.warn("Invalid high threshold: {}", highThreshold);
            }
        }
        if (mediumThreshold != null) {
            try {
                defaultThresholds.put(Severity.MEDIUM, Integer.parseInt(mediumThreshold));
            } catch (NumberFormatException e) {
                logger.warn("Invalid medium threshold: {}", mediumThreshold);
            }
        }
        if (lowThreshold != null) {
            try {
                defaultThresholds.put(Severity.LOW, Integer.parseInt(lowThreshold));
            } catch (NumberFormatException e) {
                logger.warn("Invalid low threshold: {}", lowThreshold);
            }
        }

        // ✅ ИСПРАВЛЕНО: Подсчитываем уязвимости
        Map<Severity, AtomicInteger> severityCounts = new HashMap<>();
        for (Severity severity : Severity.values()) {
            severityCounts.put(severity, new AtomicInteger(0));
        }
        
        for (Finding finding : results.getFindings()) {
            severityCounts.get(finding.getSeverity()).incrementAndGet();
        }

        // ✅ ИСПРАВЛЕНО: Проверяем пороги
        for (Map.Entry<Severity, Integer> threshold : defaultThresholds.entrySet()) {
            Severity severity = threshold.getKey();
            int maxAllowed = threshold.getValue();
            int actualCount = severityCounts.get(severity).get();
            
            if (actualCount > maxAllowed) {
                logger.info("Build should fail: Found {} {} severity issues (threshold: {})",
                        actualCount, severity, maxAllowed);
                return true;
            }
        }

        logger.info("Build should pass: All findings are within thresholds");
        return false;
    }

    @Override
    public String generateSummary(ScanResult results) {
        StringBuilder sb = new StringBuilder();

        // Add header
        sb.append("# API Security Scan Results\n\n");

        // Add scan metadata
        sb.append("## Scan Information\n\n");
        sb.append("- **Target URL**: ").append(results.getTargetUrl()).append("\n");
        // ✅ ИСПРАВЛЕНО: Используем локальный timeFormatter из класса
        sb.append("- **Scan Time**: ").append(results.getScanStartTime().format(timeFormatter)).append("\n");
        
        // ✅ ИСПРАВЛЕНО: Подсчёт длительности
        long durationSeconds = java.time.Duration.between(results.getScanStartTime(), results.getScanEndTime()).getSeconds();
        sb.append("- **Duration**: ").append(durationSeconds).append(" seconds\n\n");

        // Add findings summary
        sb.append("## Findings Summary\n\n");
        
        // ✅ ИСПРАВЛЕНО: Подсчёт по уровням серьёзности
        long criticalCount = results.getFindings().stream().filter(f -> f.getSeverity() == Severity.CRITICAL).count();
        long highCount = results.getFindings().stream().filter(f -> f.getSeverity() == Severity.HIGH).count();
        long mediumCount = results.getFindings().stream().filter(f -> f.getSeverity() == Severity.MEDIUM).count();
        long lowCount = results.getFindings().stream().filter(f -> f.getSeverity() == Severity.LOW).count();
        long infoCount = results.getFindings().stream().filter(f -> f.getSeverity() == Severity.INFO).count();

        sb.append("| Severity | Count |\n");
        sb.append("|----------|-------|\n");
        sb.append("| **🔴 Critical** | ").append(criticalCount).append(" |\n");
        sb.append("| **🟠 High**     | ").append(highCount).append(" |\n");
        sb.append("| **🟡 Medium**   | ").append(mediumCount).append(" |\n");
        sb.append("| **🟢 Low**      | ").append(lowCount).append(" |\n");
        sb.append("| **🔵 Info**     | ").append(infoCount).append(" |\n");
        sb.append("\n");

        // Add top findings
        sb.append("## Top Findings\n\n");
        List<Finding> topFindings = getHighlightedFindings(results, 10);

        if (topFindings.isEmpty()) {
            sb.append("✅ **Excellent! No security vulnerabilities detected.**\n\n");
        } else {
            for (Finding finding : topFindings) {
                sb.append("### ").append(finding.getSeverity()).append(" ").append(finding.getTitle()).append("\n\n");
                sb.append("- **Severity**: ").append(finding.getSeverity()).append("\n");
                sb.append("- **Endpoint**: `").append(finding.getEndpoint()).append("`\n");
                sb.append("- **Description**: ").append(finding.getDescription().split("\n")[0]).append("\n");
                sb.append("- **Remediation**: ").append(finding.getRemediation().split("\n")[0]).append("\n\n");
            }
        }

        return sb.toString();
    }

    @Override
    public boolean createReport(ScanResult results, ScanConfig.OutputFormat format, File outputFile) { // ✅ ИСПРАВЛЕНО: используем ScanConfig.OutputFormat
        try {
            // ✅ ИСПРАВЛЕНО: Используем ReportGeneratorFactory.createGenerator()
            ReportGenerator generator = ReportGeneratorFactory.createGenerator(format);

            // Generate the report
            generator.generateReport(results, outputFile.getAbsolutePath());

            logger.info("Created {} report at {}", format, outputFile.getAbsolutePath());
            return true;
        } catch (Exception e) {
            logger.error("Failed to create {} report: {}", format, e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    @Override
    public List<Finding> getHighlightedFindings(ScanResult results, int limit) {
        // Sort findings by severity (highest first)
        return results.getFindings().stream()
                .sorted((f1, f2) -> {
                    // First by severity (high to low)
                    int severityCompare = f2.getSeverity().compareTo(f1.getSeverity());
                    if (severityCompare != 0) {
                        return severityCompare;
                    }
                    // Then by title (alphabetically)
                    return f1.getTitle().compareTo(f2.getTitle());
                })
                .limit(limit)
                .collect(Collectors.toList());
    }

    @Override
    public String formatFinding(Finding finding) {
        StringBuilder sb = new StringBuilder();

        String severityEmoji = switch(finding.getSeverity()) {
            case CRITICAL -> "🔴";
            case HIGH -> "🟠";
            case MEDIUM -> "🟡";
            case LOW -> "🟢";
            case INFO -> "🔵";
            default -> "⚪";
        };

        sb.append(severityEmoji).append(" ")
          .append(finding.getSeverity()).append(": ")
          .append(finding.getTitle())
          .append(" (").append(finding.getEndpoint()).append(")");

        return sb.toString();
    }

    @Override
    public ScanResult sanitizeResults(ScanResult results) {
        // ✅ ИСПРАВЛЕНО: Возвращаем копию результатов с очищенными чувствительными данными
        ScanResult sanitized = new ScanResult(results.getTargetUrl(), results.getFindings());
        sanitized.setScanStartTime(results.getScanStartTime());
        sanitized.setScanEndTime(results.getScanEndTime());
        
        // Sanitize sensitive information in findings
        for (Finding finding : sanitized.getFindings()) {
            // Mask sensitive details in remediation, description, etc.
            if (finding.getRemediation() != null) {
                String sanitizedRemediation = finding.getRemediation()
                    .replaceAll("client_id: .*", "client_id: [MASKED]")
                    .replaceAll("client_secret: .*", "client_secret: [MASKED]")
                    .replaceAll("token: .*", "token: [MASKED]");
                finding.setRemediation(sanitizedRemediation);
            }
        }
        
        return sanitized;
    }

    /**
     * ✅ ИСПРАВЛЕНО: Создаёт GitHub Actions аннотации для уязвимостей
     */
    private void createAnnotations(ScanResult results) {
        // Get top findings to annotate (limit by severity to avoid too many annotations)
        List<Finding> findings = results.getFindings().stream()
                .filter(f -> f.getSeverity() == Severity.CRITICAL || f.getSeverity() == Severity.HIGH)
                .limit(20)
                .collect(Collectors.toList());

        // If we don't have any critical or high findings, include some medium ones
        if (findings.isEmpty()) {
            findings = results.getFindings().stream()
                    .filter(f -> f.getSeverity() == Severity.MEDIUM)
                    .limit(10)
                    .collect(Collectors.toList());
        }

        for (Finding finding : findings) {
            String level = finding.getSeverity() == Severity.CRITICAL || finding.getSeverity() == Severity.HIGH
                    ? "error" : "warning";

            // ✅ ИСПРАВЛЕНО: Формат для GitHub Actions аннотаций
            System.out.println(String.format("::%s file=%s,line=1,col=1::%s", 
                level, 
                finding.getEndpoint().replace(" ", "%20"), // URL-encode spaces
                escapeAnnotation(formatFinding(finding))));
        }
    }

    /**
     * ✅ ИСПРАВЛЕНО: Экранирует строки для GitHub Actions аннотаций
     */
    private String escapeAnnotation(String s) {
        return s.replace("%", "%25")
                .replace("\r", "%0D")
                .replace("\n", "%0A")
                .replace(":", "%3A")
                .replace(",", "%2C")
                .replace("[", "%5B")
                .replace("]", "%5D");
    }

    /**
     * ✅ ИСПРАВЛЕНО: Записывает сводку сканирования в markdown файл
     */
    private void writeSummaryMarkdown(ScanResult results, Path outputDir) throws IOException {
        Path outputFile = outputDir.resolve("summary.md");

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(outputFile.toFile()))) {
            writer.write(generateSummary(results));
        }

        logger.info("Wrote summary markdown to {}", outputFile);
    }
}
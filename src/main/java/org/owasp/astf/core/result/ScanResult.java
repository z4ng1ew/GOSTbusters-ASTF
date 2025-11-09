package org.owasp.astf.core.result;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import org.owasp.astf.core.config.ScanConfig;

/**
 * Contains the complete results of a security scan.
 * <p>
 * This class holds all information about a completed security scan including:
 * <ul>
 *   <li>Target API information</li>
 *   <li>Scan timing (start and end times)</li>
 *   <li>Security findings with details</li>
 *   <li>Statistics and metrics</li>
 * </ul>
 * </p>
 */
public class ScanResult {
    private final String targetUrl;
    private final List<Finding> findings;
    private LocalDateTime scanStartTime;
    private LocalDateTime scanEndTime;
    
    // ✅ ДОБАВЛЕНО: Конфигурация для отчётов
    private ScanConfig config;

    public ScanResult(String targetUrl, List<Finding> findings) {
        this.targetUrl = targetUrl;
        this.findings = findings;
        this.scanStartTime = LocalDateTime.now();
        this.scanEndTime = LocalDateTime.now();
    }

    public String getTargetUrl() {
        return targetUrl;
    }

    public LocalDateTime getScanStartTime() {
        return scanStartTime;
    }

    public void setScanStartTime(LocalDateTime scanStartTime) {
        this.scanStartTime = scanStartTime;
    }

    public LocalDateTime getScanEndTime() {
        return scanEndTime;
    }

    public void setScanEndTime(LocalDateTime scanEndTime) {
        this.scanEndTime = scanEndTime;
    }

    public List<Finding> getFindings() {
        return findings;
    }

    /**
     * Gets the total number of findings.
     *
     * @return The number of findings
     */
    public int getTotalFindingsCount() {
        return findings.size();
    }

    /**
     * Gets a summary of findings grouped by severity.
     *
     * @return A map of severity to count
     */
    public Map<Severity, Long> getSeveritySummary() {
        return findings.stream()
                .collect(Collectors.groupingBy(Finding::getSeverity, Collectors.counting()));
    }

    /**
     * ✅ Gets the count of findings for a specific severity level.
     *
     * @param severity The severity level
     * @return The number of findings with the specified severity
     */
    public long getCountBySeverity(Severity severity) {
        return findings.stream()
            .mapToLong(f -> f.getSeverity() == severity ? 1 : 0)
            .sum();
    }

    /**
     * ✅ Gets comprehensive statistics about the scan results.
     *
     * @return Scan statistics
     */
    public ScanStats getStats() {
        return new ScanStats(this);
    }

    /**
     * ✅ Gets the scan configuration used for this scan.
     *
     * @return The scan configuration
     */
    public ScanConfig getConfig() {
        return config;
    }

    /**
     * ✅ Sets the scan configuration used for this scan.
     *
     * @param config The scan configuration
     */
    public void setConfig(ScanConfig config) {
        this.config = config;
    }

    /**
     * ✅ Statistics about scan results.
     */
    public static class ScanStats {
        private final long totalFindings;
        private final long criticalFindings;
        private final long highFindings;
        private final long mediumFindings;
        private final long lowFindings;
        private final long infoFindings;
        private final long durationSeconds;

        public ScanStats(ScanResult result) {
            this.totalFindings = result.getTotalFindingsCount();
            this.criticalFindings = result.getCountBySeverity(Severity.CRITICAL);
            this.highFindings = result.getCountBySeverity(Severity.HIGH);
            this.mediumFindings = result.getCountBySeverity(Severity.MEDIUM);
            this.lowFindings = result.getCountBySeverity(Severity.LOW);
            this.infoFindings = result.getCountBySeverity(Severity.INFO);
            
            if (result.getScanStartTime() != null && result.getScanEndTime() != null) {
                this.durationSeconds = java.time.Duration.between(
                    result.getScanStartTime(), 
                    result.getScanEndTime()
                ).getSeconds();
            } else {
                this.durationSeconds = 0;
            }
        }

        public long getTotalFindings() { return totalFindings; }
        public long getCriticalFindings() { return criticalFindings; }
        public long getHighFindings() { return highFindings; }
        public long getMediumFindings() { return mediumFindings; }
        public long getLowFindings() { return lowFindings; }
        public long getInfoFindings() { return infoFindings; }
        public long getDurationSeconds() { return durationSeconds; }

        @Override
        public String toString() {
            return String.format(
                "Scan Stats: %d total (%d CRITICAL, %d HIGH, %d MED, %d LOW, %d INFO) in %ds",
                totalFindings, criticalFindings, highFindings, mediumFindings, lowFindings, infoFindings, durationSeconds
            );
        }
    }
}
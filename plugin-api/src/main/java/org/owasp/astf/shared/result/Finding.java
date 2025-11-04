package org.owasp.astf.shared.result;

/**
 * ✅ Результат теста, доступный плагинам
 */
public class Finding {
    private final String id;
    private final String title;
    private final String description;
    private final Severity severity;
    private final String testCaseId;
    private final String endpoint;
    private final String remediation;

    public Finding(String id, String title, String description, Severity severity, String testCaseId, String endpoint, String remediation) {
        this.id = id;
        this.title = title;
        this.description = description;
        this.severity = severity;
        this.testCaseId = testCaseId;
        this.endpoint = endpoint;
        this.remediation = remediation;
    }

    public String getId() { return id; }
    public String getTitle() { return title; }
    public String getDescription() { return description; }
    public Severity getSeverity() { return severity; }
    public String getTestCaseId() { return testCaseId; }
    public String getEndpoint() { return endpoint; }
    public String getRemediation() { return remediation; }
}

/**
 * ✅ Уровень серьёзности уязвимости
 */
enum Severity {
    INFO, LOW, MEDIUM, HIGH, CRITICAL
}
package org.owasp.astf.reporting;

/**
 * Поддерживаемые форматы вывода отчетов
 */
public enum OutputFormat {
    JSON("json"),
    HTML("html"),
    XML("xml"),
    SARIF("sarif");

    private final String format;

    OutputFormat(String format) {
        this.format = format;
    }

    public String getFormat() {
        return format;
    }

    /**
     * Получить OutputFormat из строки
     */
    public static OutputFormat fromString(String format) {
        for (OutputFormat of : OutputFormat.values()) {
            if (of.format.equalsIgnoreCase(format)) {
                return of;
            }
        }
        throw new IllegalArgumentException("Unknown output format: " + format);
    }

    @Override
    public String toString() {
        return format;
    }
}
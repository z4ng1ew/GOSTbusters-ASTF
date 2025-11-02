package org.owasp.astf.cli;  // ✅ ДОБАВЬТЕ ЭТУ СТРОКУ В САМОЕ НАЧАЛО!

import org.owasp.astf.core.config.ScanConfig;

public class ASTFCli {
    public static void main(String[] args) {
        if (args.length < 1) {
            System.out.println("Usage: java ASTFCli <targetUrl> [authHeader]");
            System.exit(1);
        }

        String targetUrl = args[0];
        String authHeader = args.length > 1 ? args[1] : null;

        try {
            // Создаём конфигурацию
            ScanConfig config = new ScanConfig();
            config.setTargetUrl(targetUrl);
            if (authHeader != null) {
                config.setAuthHeader(authHeader);
            }

            // ✅ Исправлено: используем полное имя класса для избежания конфликта
            org.owasp.astf.core.Scanner scanner = new org.owasp.astf.core.Scanner(config);
            scanner.scan(); // без аргументов
            
            System.out.println("Scan completed successfully");
            
        } catch (Exception e) {
            System.err.println("Error during scanning: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }
}
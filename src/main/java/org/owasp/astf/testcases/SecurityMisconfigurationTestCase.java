// src/main/java/org/owasp/astf/testcases/SecurityMisconfigurationTestCase.java
package org.owasp.astf.testcases;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.apache.http.client.methods.HttpGet;
import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.http.HttpResponse;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.Severity;

public class SecurityMisconfigurationTestCase implements TestCase {
    @Override
    public String getId() {
        return "API8:2023";
    }

    @Override
    public String getName() {
        return "Security Misconfiguration";
    }

    @Override
    public String getDescription() {
        return "Tests for security misconfigurations like missing headers, debug endpoints, etc.";
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient client) {
        List<Finding> findings = new ArrayList<>();
        
        try {
            // Проверяем безопасные заголовки
            HttpResponse response = client.executeRequest(new HttpGet(endpoint.getFullUrl()), Map.of());
            
            String serverHeader = response.getHeader("Server");
            String xPoweredBy = response.getHeader("X-Powered-By");
            
            if (serverHeader != null && !serverHeader.isEmpty()) {
                findings.add(new Finding(
                    "API8:2023",
                    "Information Disclosure via Server Header",
                    "Server header reveals technology stack: " + serverHeader,
                    Severity.MEDIUM,
                    getId(),
                    endpoint.getFullUrl(),
                    "Remove or obfuscate server headers to prevent information disclosure"
                ));
            }
            
            if (xPoweredBy != null && !xPoweredBy.isEmpty()) {
                findings.add(new Finding(
                    "API8:2023",
                    "Information Disclosure via X-Powered-By Header",
                    "X-Powered-By header reveals technology stack: " + xPoweredBy,
                    Severity.MEDIUM,
                    getId(),
                    endpoint.getFullUrl(),
                    "Remove X-Powered-By header to prevent information disclosure"
                ));
            }
            
        } catch (Exception e) {
            // Игнорируем ошибки
        }
        
        return findings;
    }
}
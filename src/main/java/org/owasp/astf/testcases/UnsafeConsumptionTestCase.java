// src/main/java/org/owasp/astf/testcases/UnsafeConsumptionTestCase.java
package org.owasp.astf.testcases;

import java.util.ArrayList;
import java.util.List;

import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.Severity;

public class UnsafeConsumptionTestCase implements TestCase {
    @Override
    public String getId() {
        return "API10:2023";
    }

    @Override
    public String getName() {
        return "Unsafe Consumption of APIs";
    }

    @Override
    public String getDescription() {
        return "Tests for unsafe consumption of external APIs";
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient client) {
        List<Finding> findings = new ArrayList<>();
        
        // Проверяем, есть ли в теле запроса или URL внешние API
        String path = endpoint.getPath();
        
        if (path.toLowerCase().contains("proxy") || path.toLowerCase().contains("forward") ||
            path.toLowerCase().contains("gateway")) {
            
            findings.add(new Finding(
                "API10:2023",
                "Unsafe API Consumption - Potential SSRF via Proxy",
                "Endpoint appears to act as a proxy/gateway, which may allow SSRF attacks to consume unsafe external APIs",
                Severity.HIGH,
                getId(),
                endpoint.getFullUrl(),
                "Implement proper validation and sanitization of external API URLs to prevent SSRF attacks."
            ));
        }
        
        return findings;
    }
}
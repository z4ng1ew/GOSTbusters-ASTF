// src/main/java/org/owasp/astf/testcases/ImproperInventoryManagementTestCase.java
package org.owasp.astf.testcases;

import java.util.ArrayList;
import java.util.List;

import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.Severity;

public class ImproperInventoryManagementTestCase implements TestCase {
    @Override
    public String getId() {
        return "API9:2023";
    }

    @Override
    public String getName() {
        return "Improper Inventory Management";
    }

    @Override
    public String getDescription() {
        return "Tests for exposed debug endpoints and undocumented API paths";
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient client) {
        List<Finding> findings = new ArrayList<>();
        
        String path = endpoint.getPath().toLowerCase();
        
        // Проверяем подозрительные пути
        if (path.contains("debug") || path.contains("admin") || path.contains("test") ||
            path.contains("v1-old") || path.contains("internal") || path.contains("health") ||
            path.contains("metrics") || path.contains("actuator")) {
            
            findings.add(new Finding(
                "API9:2023",
                "Improper Inventory Management - Exposed Endpoint",
                "Exposed potentially dangerous endpoint: " + endpoint.getPath() + 
                "\nThis endpoint might reveal internal information or be used for attacks.",
                Severity.HIGH,
                getId(),
                endpoint.getFullUrl(),
                "Ensure this endpoint is not accessible in production or properly secured."
            ));
        }
        
        return findings;
    }
}
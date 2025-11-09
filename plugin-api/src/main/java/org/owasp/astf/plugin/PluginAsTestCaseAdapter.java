// plugin-api/src/main/java/org/owasp/astf/plugin/PluginAsTestCaseAdapter.java
package org.owasp.astf.plugin;

import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.Severity;
import org.owasp.astf.testcases.TestCase;

import java.io.IOException;
import java.util.List;

/**
 * Adapter that allows Plugin implementations to be used as TestCase instances.
 * This adapter enables the framework to seamlessly integrate dynamically loaded plugins
 * as security test cases, maintaining compatibility with the existing TestCase interface.
 */
public class PluginAsTestCaseAdapter implements TestCase {
    private final Plugin plugin;

    public PluginAsTestCaseAdapter(Plugin plugin) {
        this.plugin = plugin;
    }

    @Override
    public String getId() {
        return plugin.getId();
    }

    @Override
    public String getName() {
        return plugin.getName();
    }

    @Override
    public String getDescription() {
        return plugin.getDescription();
    }

    @Override
    public void init(ScanConfig config) {
        // Plugins могут не нуждаться в инициализации
        // Или могут использовать конфиг для настройки
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient client) throws IOException {
        return plugin.execute(endpoint, client);
    }
}
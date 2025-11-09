package org.owasp.astf.testcases;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.Severity;
import org.owasp.astf.plugin.Plugin; // ✅ Убедись, что путь правильный

import java.io.IOException;
import java.util.Collections;
import java.util.List;

/**
 * Adapter that allows Plugin implementations to be used as TestCase instances.
 * <p>
 * This adapter enables the framework to seamlessly integrate dynamically loaded plugins
 * as security test cases, maintaining compatibility with the existing TestCase interface.
 * </p>
 */
public class PluginAsTestCaseAdapter implements TestCase {
    private static final Logger logger = LogManager.getLogger(PluginAsTestCaseAdapter.class);
    
    private final Plugin plugin;

    /**
     * Creates a new adapter for the specified plugin.
     *
     * @param plugin The plugin to adapt
     * @throws IllegalArgumentException if plugin is null
     */
    public PluginAsTestCaseAdapter(Plugin plugin) {
        if (plugin == null) {
            throw new IllegalArgumentException("Plugin cannot be null");
        }
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
    public List<Finding> execute(EndpointInfo endpoint, HttpClient client) throws IOException {
        try {
            logger.debug("Executing plugin {} on endpoint {}", plugin.getId(), endpoint.getPath());
            return plugin.execute(endpoint, client);
        } catch (Exception e) {
            logger.error("Plugin {} failed on endpoint {}: {}", plugin.getId(), endpoint.getPath(), e.getMessage());
            if (isVerboseLoggingEnabled()) {
                logger.debug("Plugin execution error details:", e);
            }
            // Return empty list instead of failing the entire scan
            return Collections.emptyList();
        }
    }

    /**
     * Checks if verbose logging is enabled for debugging plugin issues.
     *
     * @return true if verbose logging should be used
     */
    private boolean isVerboseLoggingEnabled() {
        // You can make this configurable via ScanConfig
        return System.getProperty("astf.verbose.plugins", "false").equals("true");
    }
}
package org.owasp.astf.plugin;

import java.util.ArrayList;
import java.util.List;
import java.util.ServiceLoader;
import java.util.stream.Collectors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.result.Finding;

/**
 * Manager for loading and managing security test plugins.
 * 
 * This class uses the Service Provider Interface (SPI) pattern to dynamically
 * load security test plugins at runtime. Plugins are discovered through the
 * META-INF/services mechanism and can be used to extend the framework's
 * vulnerability detection capabilities.
 * 
 * @see java.util.ServiceLoader
 */
public class PluginManager {
    private static final Logger logger = LogManager.getLogger(PluginManager.class);

    /**
     * Loads all available plugins from the classpath.
     *
     * @return A list of discovered plugins
     */
    public static List<Plugin> loadPlugins() {
        List<Plugin> plugins = new ArrayList<>();
        
        try {
            ServiceLoader<Plugin> loader = ServiceLoader.load(Plugin.class);
            
            for (Plugin plugin : loader) {
                plugins.add(plugin);
                logger.info("🔌 Plugin loaded: {} - {}", plugin.getId(), plugin.getName());
            }
            
            if (plugins.isEmpty()) {
                logger.info("ℹ️ No plugins found in classpath. Using built-in test cases only.");
            } else {
                logger.info("✅ Loaded {} plugins from classpath", plugins.size());
            }
            
        } catch (Exception e) {
            logger.error("❌ Error loading plugins: {}", e.getMessage());
            logger.debug("Plugin loading error details:", e);
        }
        
        return plugins;
    }

    /**
     * Executes all plugins against the specified endpoint and client.
     *
     * @param endpoint The endpoint to test
     * @param client The HTTP client to use
     * @param config The scan configuration
     * @return A list of findings from all plugins
     */
    public static List<Finding> executeAllPlugins(EndpointInfo endpoint, HttpClient client, ScanConfig config) {
        List<Finding> allFindings = new ArrayList<>();
        
        List<Plugin> plugins = loadPlugins();
        
        for (Plugin plugin : plugins) {
            try {
                logger.debug("Executing plugin {} on endpoint {}", plugin.getId(), endpoint.getPath());
                
                List<Finding> pluginFindings = plugin.execute(endpoint, client);
                allFindings.addAll(pluginFindings);
                
                if (!pluginFindings.isEmpty()) {
                    logger.info("Plugin {} found {} issues on {}", 
                        plugin.getName(), pluginFindings.size(), endpoint.getPath());
                }
                
            } catch (Exception e) {
                logger.error("Error executing plugin {}: {}", plugin.getName(), e.getMessage());
                logger.debug("Plugin execution error details:", e);
            }
        }
        
        return allFindings;
    }

    /**
     * Filters plugins based on scan configuration.
     *
     * @param plugins The list of all available plugins
     * @param config The scan configuration
     * @return A list of plugins that are enabled in the configuration
     */
    public static List<Plugin> filterPlugins(List<Plugin> plugins, ScanConfig config) {
        List<String> enabledIds = config.getEnabledTestCaseIds();
        List<String> disabledIds = config.getDisabledTestCaseIds();

        return plugins.stream()
            .filter(plugin -> {
                String pluginId = plugin.getId();
                
                // If specific IDs are enabled, only include those
                if (!enabledIds.isEmpty()) {
                    return enabledIds.contains(pluginId);
                }
                
                // Otherwise exclude disabled ones
                return !disabledIds.contains(pluginId);
            })
            .collect(Collectors.toList());
    }
}
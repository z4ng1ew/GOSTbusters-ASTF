package org.owasp.astf.plugin;

import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.result.Finding;

import java.io.IOException;
import java.util.List;

/**
 * Interface for API security testing plugins.
 * 
 * This interface allows external plugins to be dynamically loaded into the ASTF framework
 * through the Service Provider Interface (SPI) mechanism. Plugins implementing this
 * interface can add new vulnerability detection capabilities without modifying
 * the core framework.
 * 
 * @see java.util.ServiceLoader
 */
public interface Plugin {
    /**
     * Gets the unique identifier for this plugin.
     *
     * @return The plugin ID
     */
    String getId();

    /**
     * Gets the name of this plugin.
     *
     * @return The plugin name
     */
    String getName();

    /**
     * Gets the description of this plugin.
     *
     * @return The plugin description
     */
    String getDescription();

    /**
     * Executes this plugin against the specified endpoint.
     *
     * @param endpoint The endpoint to test
     * @param client The HTTP client to use for making requests
     * @return A list of findings, or an empty list if no issues were found
     * @throws IOException If the test execution fails
     */
    List<Finding> execute(EndpointInfo endpoint, HttpClient client) throws IOException;
}
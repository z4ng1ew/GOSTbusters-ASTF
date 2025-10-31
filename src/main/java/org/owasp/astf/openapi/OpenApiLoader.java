package org.owasp.astf.openapi;

import io.swagger.v3.parser.OpenAPIV3Parser;
import io.swagger.v3.parser.core.models.ParseOptions;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.servers.Server;

import java.util.ArrayList;
import java.util.List;

public class OpenApiLoader {
    public static OpenAPI load(String urlOrPath) {
        ParseOptions options = new ParseOptions();
        options.setResolve(true);
        options.setFlatten(true);
        var result = new OpenAPIV3Parser().readLocation(urlOrPath, null, options);
        if (result.getMessages() != null && !result.getMessages().isEmpty()) {
            System.err.println("OpenAPI parse warnings: " + result.getMessages());
        }
        return result.getOpenAPI();
    }

    public static List<String> getEndpointUrls(OpenAPI openAPI) {
        List<String> endpoints = new ArrayList<>();
        String baseUrl = openAPI.getServers().get(0).getUrl(); // Берём первый сервер
        for (String path : openAPI.getPaths().keySet()) {
            endpoints.add(baseUrl + path);
        }
        return endpoints;
    }
}
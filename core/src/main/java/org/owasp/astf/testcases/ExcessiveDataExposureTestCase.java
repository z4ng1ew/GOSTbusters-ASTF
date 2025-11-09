package org.owasp.astf.testcases;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.PathItem;
import io.swagger.v3.oas.models.Paths;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.responses.ApiResponses;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.media.Schema;
import org.apache.http.client.methods.HttpGet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.http.HttpResponse;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.Severity;
import org.owasp.astf.openapi.OpenApiLoader; // ✅ ИМПОРТ

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Tests for Excessive Data Exposure (API3:2023) and Broken Object Property Level Authorization.
 * Compares actual API response against OpenAPI specification and looks for sensitive fields.
 */
public class ExcessiveDataExposureTestCase implements TestCase {
    private static final Logger logger = LogManager.getLogger(ExcessiveDataExposureTestCase.class);

    private ScanConfig config;
    private final ObjectMapper objectMapper = new ObjectMapper(); // ✅ Jackson ObjectMapper

    // Sensitivity keywords to look for in responses
    private static final Set<String> SENSITIVE_KEYWORDS = new HashSet<>();
    static {
        SENSITIVE_KEYWORDS.add("password");
        SENSITIVE_KEYWORDS.add("secret");
        SENSITIVE_KEYWORDS.add("token");
        SENSITIVE_KEYWORDS.add("ssn");
        SENSITIVE_KEYWORDS.add("social_security_number");
        SENSITIVE_KEYWORDS.add("passport");
        SENSITIVE_KEYWORDS.add("pin");
        SENSITIVE_KEYWORDS.add("cvv");
        SENSITIVE_KEYWORDS.add("cvv2");
        SENSITIVE_KEYWORDS.add("credit_card");
        SENSITIVE_KEYWORDS.add("card_number");
        SENSITIVE_KEYWORDS.add("pan");
        SENSITIVE_KEYWORDS.add("internal_id");
        SENSITIVE_KEYWORDS.add("auth_code");
        SENSITIVE_KEYWORDS.add("private_key");
        SENSITIVE_KEYWORDS.add("encryption_key");
        SENSITIVE_KEYWORDS.add("dob");
        SENSITIVE_KEYWORDS.add("date_of_birth");
        SENSITIVE_KEYWORDS.add("full_name");
        SENSITIVE_KEYWORDS.add("email");
        SENSITIVE_KEYWORDS.add("phone");
        SENSITIVE_KEYWORDS.add("address");
    }

    @Override
    public String getId() {
        return "API3:2023";
    }

    @Override
    public String getName() {
        return "Excessive Data Exposure & Broken Object Property Level Authorization (API3:2023)";
    }

    @Override
    public String getDescription() {
        return "Tests for excessive data exposure and property-level authorization issues (OWASP API3:2023).";
    }

    @Override
    public void init(ScanConfig config) {
        this.config = config;
    }

    @Override
    public boolean supportsOpenApi(OpenAPI openAPI) {
        // This test case benefits from OpenAPI spec to compare response against schema
        return openAPI != null && openAPI.getPaths() != null;
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient client) throws IOException {
        List<Finding> findings = new ArrayList<>();

        // Only for GET requests that return data (e.g., /accounts, /users, etc.)
        if (!"GET".equalsIgnoreCase(endpoint.getMethod())) {
            logger.debug("Skipping non-GET endpoint for Excessive Data Exposure: {}", endpoint.getPath());
            return findings;
        }

        System.out.println("🔍 Testing excessive data exposure on: " + endpoint.getMethod() + " " + endpoint.getPath());

        // Try to execute the request with the current session's authentication
        Map<String, String> headers = config.getHeaders() != null ? config.getHeaders() : Collections.emptyMap();
        try {
            // ✅ ИСПРАВЛЕНО: Используем executeRequest с двумя параметрами
            HttpResponse httpResponse = client.executeRequest(new HttpGet(endpoint.getFullUrl()), headers);

            // We are interested in successful responses (200 OK) that contain data
            if (httpResponse.getStatusCode() == 200) {
                String responseBody = httpResponse.getResponseBody(); // ✅ ИСПРАВЛЕНО: getResponseBody() вместо getBody()

                // 1. Check for sensitive keywords in the response
                List<String> foundSensitiveFields = findSensitiveFieldsInResponse(responseBody);
                if (!foundSensitiveFields.isEmpty()) {
                    findings.add(new Finding(
                        getId(),
                        "Excessive Data Exposure (API3:2023)",
                        "Response contains sensitive fields: " + String.join(", ", foundSensitiveFields) + "\n" +
                        "Endpoint: " + endpoint.getFullUrl() + "\n" +
                        "This could lead to unauthorized access to sensitive information.",
                        Severity.HIGH,
                        getId(),
                        endpoint.getFullUrl(),
                        "Remove sensitive data from API responses. Use DTOs or serialization views to control what data is returned. " +
                        "Ensure that the API response schema in the OpenAPI spec accurately reflects the data returned."
                    ));
                    System.out.println("🚨 SENSITIVE DATA FOUND: " + String.join(", ", foundSensitiveFields));
                } else {
                    System.out.println("✅ No sensitive data detected in response");
                }

                // 2. Validate response structure against OpenAPI spec if available
                if (config.getOpenApiSpecPath() != null) { // ✅ ИСПРАВЛЕНО: Убедись, что поле есть в ScanConfig
                    try {
                        OpenAPI openAPI = OpenApiLoader.load(config.getOpenApiSpecPath());
                        List<String> extraFields = validateResponseAgainstOpenApi(responseBody, endpoint, openAPI);
                        if (!extraFields.isEmpty()) {
                            findings.add(new Finding(
                                getId(),
                                "API Response Mismatch (API3:2023)",
                                "API response contains fields not defined in OpenAPI spec: " + String.join(", ", extraFields) + "\n" +
                                "Endpoint: " + endpoint.getFullUrl() + "\n" +
                                "This indicates potential excessive data exposure or outdated documentation.",
                                Severity.MEDIUM,
                                getId(),
                                endpoint.getFullUrl(),
                                "Align the API response with the OpenAPI specification. " +
                                "Either update the API to remove the extra fields or update the OpenAPI spec to document them."
                            ));
                            System.out.println("📝 EXTRA FIELDS FOUND: " + String.join(", ", extraFields));
                        } else {
                            System.out.println("✅ Response matches OpenAPI specification");
                        }
                    } catch (Exception e) {
                        logger.warn("OpenAPI validation failed for endpoint {}: {}", endpoint.getFullUrl(), e.getMessage());
                        System.out.println("⚠️ OpenAPI validation skipped: " + e.getMessage());
                    }
                } else {
                    System.out.println("ℹ️ OpenAPI validation skipped (no spec path configured)");
                }

            } else {
                // Log non-200 responses but don't flag them as findings for this test
                logger.debug("Endpoint {} returned status {}, skipping Excessive Data check.", endpoint.getFullUrl(), httpResponse.getStatusCode());
                System.out.println("⏭️ Skipped (status " + httpResponse.getStatusCode() + ")");
            }

        } catch (Exception e) {
            logger.warn("Error during Excessive Data Exposure test for endpoint {}: {}", endpoint.getFullUrl(), e.getMessage());
            System.out.println("❌ Test failed: " + e.getMessage());
            // Do not add a finding for technical errors during the test
        }

        return findings;
    }

    private List<String> findSensitiveFieldsInResponse(String response) {
        List<String> foundFields = new ArrayList<>();
        try {
            // ✅ ИСПРАВЛЕНО: Используем Jackson ObjectMapper
            JsonNode jsonNode = objectMapper.readTree(response);
            if (jsonNode.isObject()) {
                // Use a recursive function to search for sensitive keys deeply nested
                searchSensitiveKeys(jsonNode, "", foundFields);
            }
            // Also check the raw string for keywords that might be in non-JSON parts or as values
            String lowerCaseResponse = response.toLowerCase();
            for (String keyword : SENSITIVE_KEYWORDS) {
                if (lowerCaseResponse.contains(keyword.toLowerCase())) {
                    // Check if it's a key in the JSON structure (more likely to be a real finding)
                    if (!foundFields.contains(keyword)) {
                        foundFields.add(keyword);
                    }
                }
            }
        } catch (Exception e) {
            logger.debug("Response is not valid JSON, skipping structured sensitive field check: {}", response);
        }
        return foundFields;
    }

    // ✅ ИСПРАВЛЕНО: Принимает JsonNode вместо JsonObject
    private void searchSensitiveKeys(JsonNode node, String prefix, List<String> foundFields) {
        if (node.isObject()) {
            // ✅ ИСПРАВЛЕНО: Итерация по полям объекта
            node.fields().forEachRemaining(entry -> {
                String key = entry.getKey().toLowerCase();
                if (SENSITIVE_KEYWORDS.contains(key) && !foundFields.contains(key)) {
                    foundFields.add(entry.getKey()); // Add original case
                }
                // Recurse into nested objects
                searchSensitiveKeys(entry.getValue(), prefix + key + ".", foundFields);
            });
        } else if (node.isArray()) {
            // ✅ ИСПРАВЛЕНО: Обработка массивов
            for (JsonNode element : node) {
                searchSensitiveKeys(element, prefix + "[].", foundFields);
            }
        }
        // Else: Просто значение (не объект и не массив) — пропускаем
    }

    private List<String> validateResponseAgainstOpenApi(String response, EndpointInfo endpoint, OpenAPI openAPI) {
        List<String> extraFields = new ArrayList<>();
        try {
            // ✅ ИСПРАВЛЕНО: Используем Jackson
            JsonNode jsonNode = objectMapper.readTree(response);
            if (!jsonNode.isObject()) {
                logger.debug("Response is not a JSON object, skipping OpenAPI validation: {}", response);
                return extraFields;
            }

            String path = endpoint.getPath();
            String httpMethod = endpoint.getMethod().toLowerCase();

            Paths paths = openAPI.getPaths();
            if (paths == null) {
                logger.warn("OpenAPI spec has no paths defined.");
                return extraFields;
            }

            PathItem pathItem = paths.get(path);
            if (pathItem == null) {
                logger.warn("Path {} not found in OpenAPI spec.", path);
                return extraFields; // Cannot validate against non-existent path
            }

            Operation operation = null;
            switch (httpMethod) {
                case "get": operation = pathItem.getGet(); break;
                case "post": operation = pathItem.getPost(); break;
                case "put": operation = pathItem.getPut(); break;
                case "delete": operation = pathItem.getDelete(); break;
                // Add other methods if needed
                default:
                    logger.warn("HTTP method {} not handled for OpenAPI validation.", httpMethod);
                    return extraFields;
            }

            if (operation == null) {
                logger.warn("Operation for {} {} not found in OpenAPI spec.", httpMethod.toUpperCase(), path);
                return extraFields; // Cannot validate against non-existent operation
            }

            // Get the response schema for status 200
            ApiResponses responses = operation.getResponses(); // ✅ Правильно: ApiResponses (множественное)
            if (responses == null) {
                logger.warn("No responses defined for operation {} {} in OpenAPI spec.", httpMethod.toUpperCase(), path);
                return extraFields;
            }

            ApiResponse apiResponse = responses.get("200"); // ✅ Правильно: ApiResponse (одиночное)
            if (apiResponse == null) {
                logger.warn("No 200 response defined for operation {} {} in OpenAPI spec.", httpMethod.toUpperCase(), path);
                return extraFields;
            }

            io.swagger.v3.oas.models.responses.ApiResponse contentResponse = apiResponse;
            io.swagger.v3.oas.models.media.Content content = contentResponse.getContent();
            if (content == null) {
                logger.warn("No content defined for 200 response of {} {} in OpenAPI spec.", httpMethod.toUpperCase(), path);
                return extraFields;
            }

            // Assuming application/json is the primary content type for validation
            MediaType mediaType = content.get("application/json");
            if (mediaType == null) {
                logger.warn("No 'application/json' content defined for 200 response of {} {} in OpenAPI spec.", httpMethod.toUpperCase(), path);
                return extraFields;
            }

            Schema<?> responseSchema = mediaType.getSchema();
            if (responseSchema == null) {
                logger.warn("No schema defined for 'application/json' content of 200 response for {} {} in OpenAPI spec.", httpMethod.toUpperCase(), path);
                return extraFields;
            }

            // Now, compare responseJson against responseSchema properties
            // This is a simplified check. A full validation would require a JSON Schema validator library.
            // For now, we'll check top-level properties.
            Set<String> allowedProperties = new HashSet<>();
            if (responseSchema.getProperties() != null) {
                allowedProperties.addAll(responseSchema.getProperties().keySet());
            }

            // ✅ ИСПРАВЛЕНО: Итерация по полям JsonNode
            jsonNode.fields().forEachRemaining(entry -> {
                if (!allowedProperties.contains(entry.getKey())) {
                    extraFields.add(entry.getKey());
                }
            });

        } catch (Exception e) {
            logger.warn("Error during OpenAPI validation for endpoint {}: {}", endpoint.getFullUrl(), e.getMessage());
            // Do not add a finding for validation errors, just log
        }
        return extraFields;
    }
}
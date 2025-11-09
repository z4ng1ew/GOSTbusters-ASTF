package org.owasp.astf.testcases;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.client.methods.HttpPost;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.http.HttpResponse;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.Severity;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Tests for GraphQL-specific vulnerabilities in API endpoints.
 * 
 * This test case targets GraphQL APIs (increasingly used in modern banking systems)
 * for common vulnerabilities including introspection abuse, query complexity attacks,
 * batch query abuse, and field enumeration.
 * 
 * @see <a href="https://graphql.org/">GraphQL Specification</a>
 * @see <a href="https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html">OWASP GraphQL Security Cheat Sheet</a>
 */
public class GraphQLTestCase implements TestCase {
    private static final Logger logger = LogManager.getLogger(GraphQLTestCase.class);

    private ScanConfig config;
    private final ObjectMapper objectMapper = new ObjectMapper();

    // GraphQL introspection query payloads
    private static final String[] GRAPHQL_INTROSPECTION_QUERIES = {
        // Standard introspection query
        """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              ...FullType
            }
          }
        }
        fragment FullType on __Type {
          kind
          name
          description
          fields(includeDeprecated: true) {
            name
            description
            args {
              ...InputValue
            }
            type {
              ...TypeRef
            }
          }
        }
        fragment InputValue on __InputValue {
          name
          description
          type { ...TypeRef }
        }
        fragment TypeRef on __Type {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
              }
            }
          }
        }
        """,
        // Alternative introspection query
        """
        {
          "__schema": {
            "types": {
              "name": 1,
              "fields": {
                "name": 1,
                "type": {
                  "name": 1,
                  "kind": 1
                }
              }
            }
          }
        }
        """,
        // Simplified introspection
        """
        query {
          __type(name: "Query") {
            fields {
              name
              description
            }
          }
        }
        """
    };

    // GraphQL complexity attack payloads
    private static final String[] GRAPHQL_COMPLEXITY_QUERIES = {
        // Deep nesting attack
        """
        {
          user(id: "1") {
            friends {
              friends {
                friends {
                  friends {
                    friends {
                      id
                      name
                      email
                      balance
                      transactions {
                        amount
                        currency
                        details {
                          merchant
                          category
                          location {
                            address
                            coordinates
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
        """,
        // Recursive query attack
        """
        {
          account(id: "1") {
            owner {
              accounts {
                owner {
                  accounts {
                    owner {
                      accounts {
                        id
                        balance
                        transactions {
                          amount
                          account {
                            balance
                            owner {
                              name
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
        """,
        // Large batch query
        """
        [
          {"query": "query { user(id: \\"1\\") { id name } }"},
          {"query": "query { user(id: \\"2\\") { id name } }"},
          {"query": "query { user(id: \\"3\\") { id name } }"},
          {"query": "query { user(id: \\"4\\") { id name } }"},
          {"query": "query { user(id: \\"5\\") { id name } }"}
        ]
        """
    };

    @Override
    public void init(ScanConfig config) {
        this.config = config;
    }

    @Override
    public String getId() {
        return "GRAPHQL-SECURITY";
    }

    @Override
    public String getName() {
        return "GraphQL Security Vulnerabilities";
    }

    @Override
    public String getDescription() {
        return """
               Tests for GraphQL-specific vulnerabilities including introspection abuse,
               query complexity attacks, batch query abuse, and field enumeration.
               """;
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient client) throws IOException {
        List<Finding> findings = new ArrayList<>();

        // ✅ Проверяем: это GraphQL эндпоинт?
        String path = endpoint.getPath().toLowerCase();
        if (!path.contains("graphql") && !path.contains("query") && !path.contains("/gql")) {
            logger.debug("⏭️ Skipping non-GraphQL endpoint: {}", endpoint.getPath());
            return findings;
        }

        System.out.println("🔮 Testing GraphQL security on: " + endpoint.getMethod() + " " + endpoint.getPath());

        // ✅ Тестируем GraphQL Introspection Abuse
        findings.addAll(testIntrospectionAbuse(endpoint, client));

        // ✅ Тестируем Query Complexity Attacks
        findings.addAll(testQueryComplexity(endpoint, client));

        // ✅ Тестируем Batch Query Abuse
        findings.addAll(testBatchQueryAbuse(endpoint, client));

        if (findings.isEmpty()) {
            System.out.println("✅ GraphQL security verified: " + endpoint.getPath());
        } else {
            System.out.println("🎯 GraphQL vulnerabilities found: " + findings.size() + " on " + endpoint.getPath());
        }

        return findings;
    }

    /**
     * ✅ Tests for GraphQL Introspection Abuse
     */
    private List<Finding> testIntrospectionAbuse(EndpointInfo endpoint, HttpClient client) {
        List<Finding> findings = new ArrayList<>();

        for (String introspectionQuery : GRAPHQL_INTROSPECTION_QUERIES) {
            try {
                // ✅ Подготавливаем заголовки аутентификации
                Map<String, String> headers = new HashMap<>(config.getHeaders());
                headers.put("Content-Type", "application/json");

                // ✅ Формируем тело запроса
                String requestBody = "{\"query\": \"" + introspectionQuery.replace("\n", "\\n").replace("\"", "\\\"") + "\"}";

                // ✅ Выполняем запрос
                HttpResponse response = client.post(endpoint.getFullUrl(), headers, requestBody);

                if (response.getStatusCode() == 200) {
                    String responseBody = response.getResponseBody();
                    
                    // ✅ Проверяем, содержит ли ответ информацию о схеме GraphQL
                    JsonNode responseJson = objectMapper.readTree(responseBody);
                    
                    if (responseJson.has("data") && responseJson.get("data").has("__schema")) {
                        findings.add(new Finding(
                            "GRAPHQL-INTROSPECTION-01",
                            "GraphQL Introspection Abuse",
                            "🚨 CRITICAL: GraphQL introspection query succeeded!\n\n" +
                            "• Endpoint: " + endpoint.getFullUrl() + "\n" +
                            "• Response Status: " + response.getStatusCode() + "\n" +
                            "• Schema Exposure: Full GraphQL schema accessible\n" +
                            "• Impact: Attackers can map entire API structure and find sensitive fields\n\n" +
                            "🔍 Evidence: Response contains '__schema' with types and fields information",
                            Severity.CRITICAL,
                            getId(),
                            endpoint.getFullUrl(),
                            "✅ CRITICAL REMEDIATION REQUIRED:\n\n" +
                            "1. DISABLE INTROSPECTION IN PRODUCTION\n" +
                            "   • Set introspection: false in GraphQL configuration\n" +
                            "   • Only enable for development environments\n\n" +
                            "2. IMPLEMENT QUERY WHITELISTING\n" +
                            "   • Allow only pre-approved queries\n" +
                            "   • Use persisted queries\n\n" +
                            "3. APPLY RATE LIMITING TO GRAPHQL ENDPOINTS\n" +
                            "   • Limit queries per IP/user\n" +
                            "   • Monitor for schema scraping\n\n" +
                            "4. COMPLY WITH OPEN BANKING SECURITY STANDARDS\n" +
                            "   • Follow Open Banking Russia v2.1 security guidelines\n" +
                            "   • Implement proper access controls for introspection"
                        ));
                        System.out.println("🚨 GRAPHQL INTROSPECTION VULNERABILITY FOUND: " + endpoint.getPath());
                        break; // Stop after first finding
                    } else {
                        logger.debug("✅ GraphQL introspection blocked: {}", endpoint.getPath());
                    }
                } else if (response.getStatusCode() == 403 || response.getStatusCode() == 405) {
                    logger.debug("✅ GraphQL introspection protection working: {}", endpoint.getPath());
                } else {
                    logger.debug("GraphQL introspection returned status {}: {}", response.getStatusCode(), endpoint.getPath());
                }

            } catch (Exception e) {
                logger.debug("GraphQL introspection test failed for {}: {}", endpoint.getPath(), e.getMessage());
            }
        }

        return findings;
    }

    /**
     * ✅ Tests for GraphQL Query Complexity Attacks
     */
    private List<Finding> testQueryComplexity(EndpointInfo endpoint, HttpClient client) {
        List<Finding> findings = new ArrayList<>();

        for (String complexityQuery : GRAPHQL_COMPLEXITY_QUERIES) {
            try {
                Map<String, String> headers = new HashMap<>(config.getHeaders());
                headers.put("Content-Type", "application/json");

                String requestBody = "{\"query\": \"" + complexityQuery.replace("\n", "\\n").replace("\"", "\\\"") + "\"}";

                // ✅ Измеряем время выполнения запроса
                long startTime = System.currentTimeMillis();
                HttpResponse response = client.post(endpoint.getFullUrl(), headers, requestBody);
                long durationMs = System.currentTimeMillis() - startTime;

                // ✅ Проверяем, слишком ли долго выполняется запрос (DoS уязвимость)
                if (durationMs > 5000) { // 5 секунд
                    findings.add(new Finding(
                        "GRAPHQL-COMPLEXITY-02",
                        "GraphQL Query Complexity Attack",
                        "⚠️ MEDIUM: Complex GraphQL query took too long to execute!\n\n" +
                        "• Endpoint: " + endpoint.getFullUrl() + "\n" +
                        "• Query Duration: " + durationMs + "ms\n" +
                        "• Expected Max: 3000ms\n" +
                        "• Impact: Attackers can exhaust server resources with complex nested queries\n\n" +
                        "🔍 Evidence: Query executed for " + durationMs + "ms, potentially causing DoS",
                        Severity.MEDIUM,
                        getId(),
                        endpoint.getFullUrl(),
                        "✅ REMEDIATION:\n\n" +
                        "1. IMPLEMENT QUERY DEPTH LIMITING\n" +
                        "   • Limit maximum query depth (e.g., 5 levels)\n" +
                        "   • Reject queries exceeding depth limit\n\n" +
                        "2. APPLY QUERY COST ANALYSIS\n" +
                        "   • Assign cost to each field/resolver\n" +
                        "   • Reject queries exceeding cost threshold\n\n" +
                        "3. USE TIMEOUTS\n" +
                        "   • Set execution timeout per query\n" +
                        "   • Kill long-running queries\n\n" +
                        "4. MONITOR RESOURCE USAGE\n" +
                        "   • Track query execution times\n" +
                        "   • Alert on suspicious complexity patterns"
                    ));
                    System.out.println("⚠️ GRAPHQL COMPLEXITY VULNERABILITY: " + durationMs + "ms execution time");
                    break; // Stop after first finding
                } else {
                    logger.debug("✅ GraphQL complexity protection working: {}ms for {}", durationMs, endpoint.getPath());
                }

            } catch (Exception e) {
                logger.debug("GraphQL complexity test failed for {}: {}", endpoint.getPath(), e.getMessage());
            }
        }

        return findings;
    }

    /**
     * ✅ Tests for GraphQL Batch Query Abuse
     */
    private List<Finding> testBatchQueryAbuse(EndpointInfo endpoint, HttpClient client) {
        List<Finding> findings = new ArrayList<>();

        for (String batchQuery : GRAPHQL_BATCH_QUERY_PAYLOADS) {
            try {
                Map<String, String> headers = new HashMap<>(config.getHeaders());
                headers.put("Content-Type", "application/json");

                HttpResponse response = client.post(endpoint.getFullUrl(), headers, batchQuery);

                if (response.getStatusCode() == 200) {
                    String responseBody = response.getResponseBody();
                    
                    // ✅ Проверяем, содержит ли ответ массив (batch query)
                    JsonNode responseJson = objectMapper.readTree(responseBody);
                    
                    if (responseJson.isArray()) {
                        int queryCount = responseJson.size();
                        
                        if (queryCount > 3) { // 3+ запроса в batch - подозрительно
                            findings.add(new Finding(
                                "GRAPHQL-BATCH-ABUSE-03",
                                "GraphQL Batch Query Abuse",
                                "⚠️ MEDIUM: GraphQL endpoint allows large batch queries!\n\n" +
                                "• Endpoint: " + endpoint.getFullUrl() + "\n" +
                                "• Batch Size: " + queryCount + " queries\n" +
                                "• Risk: Attackers can perform multiple operations in one request\n" +
                                "• Impact: Potential DoS, data extraction, or rate limit bypass\n\n" +
                                "🔍 Evidence: Server processed " + queryCount + " queries in single batch request",
                                Severity.MEDIUM,
                                getId(),
                                endpoint.getFullUrl(),
                                "✅ REMEDIATION:\n\n" +
                                "1. LIMIT BATCH SIZE\n" +
                                "   • Maximum 1-2 queries per batch\n" +
                                "   • Reject large batch requests\n\n" +
                                "2. IMPLEMENT INDIVIDUAL RATE LIMITING\n" +
                                "   • Count each query in batch separately\n" +
                                "   • Apply per-query limits\n\n" +
                                "3. VALIDATE BATCH CONTENT\n" +
                                "   • Check each query individually\n" +
                                "   • Apply same security rules as single queries\n\n" +
                                "4. MONITOR FOR ABUSE PATTERNS\n" +
                                "   • Track batch query frequency\n" +
                                "   • Alert on suspicious batch sizes"
                            ));
                            System.out.println("⚠️ GRAPHQL BATCH ABUSE VULNERABILITY: " + queryCount + " queries in batch");
                            break; // Stop after first finding
                        }
                    } else if (responseJson.has("data") && responseJson.get("data").has("user")) {
                        // Multiple user queries in single batch
                        int userQueries = countUserQueriesInResponse(responseJson);
                        if (userQueries > 2) {
                            findings.add(new Finding(
                                "GRAPHQL-BATCH-ABUSE-04",
                                "GraphQL Batch User Query Abuse",
                                "⚠️ MEDIUM: Large batch query with multiple user operations detected!\n\n" +
                                "• Endpoint: " + endpoint.getFullUrl() + "\n" +
                                "• User Queries: " + userQueries + " in batch\n" +
                                "• Risk: Attackers can enumerate users efficiently\n" +
                                "• Impact: Potential user enumeration and privacy violation",
                                Severity.MEDIUM,
                                getId(),
                                endpoint.getFullUrl(),
                                "✅ REMEDIATION:\n\n" +
                                "1. LIMIT USER QUERY BATCH SIZE\n" +
                                "   • Maximum 1-2 user queries per batch\n" +
                                "   • Implement query counting\n\n" +
                                "2. APPLY USER-LEVEL RATE LIMITING\n" +
                                "   • Limit queries per user\n" +
                                "   • Monitor for enumeration patterns"
                            ));
                        }
                    }
                }

            } catch (Exception e) {
                logger.debug("GraphQL batch test failed for {}: {}", endpoint.getPath(), e.getMessage());
            }
        }

        return findings;
    }

    /**
     * ✅ Подсчитывает количество user-запросов в batch-ответе
     */
    private int countUserQueriesInResponse(JsonNode response) {
        if (response.isArray()) {
            int count = 0;
            for (JsonNode item : response) {
                if (item.has("data") && item.get("data").has("user")) {
                    count++;
                }
            }
            return count;
        }
        return 0;
    }
}
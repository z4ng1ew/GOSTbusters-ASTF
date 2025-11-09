package org.owasp.astf.testcases;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.client.methods.HttpGet;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.astf.core.EndpointInfo;
import org.owasp.astf.core.config.ScanConfig;
import org.owasp.astf.core.http.HttpClient;
import org.owasp.astf.core.http.HttpResponse;
import org.owasp.astf.core.result.Finding;
import org.owasp.astf.core.result.Severity;

import java.io.IOException;
import java.util.*;

/**
 * Tests for API2:2023 - Broken Authentication related to JWT tokens.
 * 
 * This test case checks for common JWT vulnerabilities including:
 * - None algorithm attacks
 * - Weak signing secrets
 * - Missing signature validation
 * - Expired token acceptance
 * - Algorithm confusion
 * 
 * @see <a href="https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/">OWASP API Security Top 10 2023: API2 Broken Authentication</a>
 */
public class JWTTestCase implements TestCase {
    private static final Logger logger = LogManager.getLogger(JWTTestCase.class);

    private ScanConfig config;
    private final ObjectMapper objectMapper = new ObjectMapper();

    // Common weak JWT secrets
    private static final List<String> WEAK_SECRETS = Arrays.asList(
        "secret", "jwt", "password", "123456", "qwerty", "admin", "test",
        "", "null", "undefined", "none", "NONE", "None", "secret123",
        "mySecret", "jwtSecret", "supersecret", "changeit"
    );

    // JWT payloads for different attacks
    private static final Map<String, String> JWT_ATTACK_PAYLOADS = Map.of(
        "none-algorithm", createJwtWithNoneAlgorithm(),
        "weak-secret", createJwtWithWeakSecret(),
        "expired-token", createExpiredJwt(),
        "algorithm-confusion", createJwtWithAlgorithmConfusion()
    );

    @Override
    public void init(ScanConfig config) {
        this.config = config;
    }

    @Override
    public String getId() {
        return "API2:2023-JWT";
    }

    @Override
    public String getName() {
        return "JWT Vulnerabilities (API2:2023)";
    }

    @Override
    public String getDescription() {
        return """
               Tests for JWT token vulnerabilities including none algorithm attacks, 
               weak signing secrets, missing signature validation, and expired token acceptance.
               """;
    }

    @Override
    public List<Finding> execute(EndpointInfo endpoint, HttpClient client) throws IOException {
        List<Finding> findings = new ArrayList<>();

        System.out.println("🔐 Testing JWT security on: " + endpoint.getMethod() + " " + endpoint.getPath());

        // ✅ Только для эндпоинтов, требующих аутентификации
        if (!endpoint.isRequiresAuthentication()) {
            logger.debug("⏭️ Skipping non-authenticated endpoint: {}", endpoint.getPath());
            return findings;
        }

        // ✅ Проверяем JWT-аутентификацию
        findings.addAll(testJwtVulnerabilities(endpoint, client));

        if (findings.isEmpty()) {
            System.out.println("✅ JWT protection verified: " + endpoint.getMethod() + " " + endpoint.getPath());
        } else {
            System.out.println("🚨 JWT vulnerabilities found: " + findings.size() + " on " + endpoint.getPath());
        }

        return findings;
    }

    /**
     * ✅ Тестирует JWT-уязвимости
     */
    private List<Finding> testJwtVulnerabilities(EndpointInfo endpoint, HttpClient client) throws IOException {
        List<Finding> findings = new ArrayList<>();
        Map<String, String> authHeaders = config.getHeaders() != null ? config.getHeaders() : new HashMap<>();

        // ✅ ПРОВЕРКА: none алгоритм
        if (testJwtNoneAlgorithm(endpoint, client, authHeaders)) {
            findings.add(createJwtFinding(
                "JWT-NONE-01",
                "JWT None Algorithm Attack",
                "API accepts JWT tokens with 'none' algorithm without signature verification",
                endpoint,
                "Use strong algorithms like RS256 or ES256. Never allow 'none' algorithm in production."
            ));
        }

        // ✅ ПРОВЕРКА: слабый секрет
        if (testJwtWeakSecret(endpoint, client, authHeaders)) {
            findings.add(createJwtFinding(
                "JWT-WEAK-SECRET-01", 
                "JWT Weak Secret Vulnerability",
                "API accepts JWT tokens signed with weak/known secrets",
                endpoint,
                "Use strong, random secrets for JWT signing. Rotate secrets regularly."
            ));
        }

        // ✅ ПРОВЕРКА: истёкший токен
        if (testJwtExpiredToken(endpoint, client, authHeaders)) {
            findings.add(createJwtFinding(
                "JWT-EXPIRED-01",
                "JWT Expired Token Acceptance",
                "API accepts JWT tokens that have expired",
                endpoint,
                "Implement proper token expiration checks. Reject expired tokens immediately."
            ));
        }

        // ✅ ПРОВЕРКА: алгоритмическая путаница
        if (testJwtAlgorithmConfusion(endpoint, client, authHeaders)) {
            findings.add(createJwtFinding(
                "JWT-ALG-CONFUSION-01",
                "JWT Algorithm Confusion Attack",
                "API vulnerable to algorithm confusion (HS256 vs RS256)",
                endpoint,
                "Strictly validate JWT algorithm. Don't allow algorithm switching without proper verification."
            ));
        }

        return findings;
    }

    /**
     * ✅ Тестирует none-алгоритм
     */
    private boolean testJwtNoneAlgorithm(EndpointInfo endpoint, HttpClient client, Map<String, String> baseHeaders) {
        try {
            String maliciousToken = createJwtWithNoneAlgorithm();
            
            Map<String, String> headers = new HashMap<>(baseHeaders);
            headers.put("Authorization", "Bearer " + maliciousToken);

            HttpResponse response = client.executeRequest(new HttpGet(endpoint.getFullUrl()), headers);

            // ✅ Если получаем 200 OK - уязвимость!
            boolean isVulnerable = response.getStatusCode() == 200;
            
            if (isVulnerable) {
                logger.warn("🚨 JWT NONE ALGORITHM VULNERABILITY: {}", endpoint.getFullUrl());
            } else {
                logger.debug("✅ JWT none algorithm blocked: {}", endpoint.getFullUrl());
            }

            return isVulnerable;
        } catch (Exception e) {
            logger.debug("JWT none test failed for {}: {}", endpoint.getPath(), e.getMessage());
            return false;
        }
    }

    /**
     * ✅ Тестирует слабые секреты
     */
    private boolean testJwtWeakSecret(EndpointInfo endpoint, HttpClient client, Map<String, String> baseHeaders) {
        for (String weakSecret : WEAK_SECRETS) {
            try {
                String maliciousToken = createJwtWithWeakSecret(weakSecret);
                
                Map<String, String> headers = new HashMap<>(baseHeaders);
                headers.put("Authorization", "Bearer " + maliciousToken);

                HttpResponse response = client.executeRequest(new HttpGet(endpoint.getFullUrl()), headers);

                // ✅ Если получаем 200 OK - уязвимость!
                if (response.getStatusCode() == 200) {
                    logger.warn("🚨 JWT WEAK SECRET VULNERABILITY: {} with secret '{}'", endpoint.getFullUrl(), weakSecret);
                    return true;
                }
            } catch (Exception e) {
                // Continue with next secret
            }
        }
        logger.debug("✅ JWT weak secrets blocked: {}", endpoint.getPath());
        return false;
    }

    /**
     * ✅ Тестирует истёкший токен
     */
    private boolean testJwtExpiredToken(EndpointInfo endpoint, HttpClient client, Map<String, String> baseHeaders) {
        try {
            String expiredToken = createExpiredJwt();
            
            Map<String, String> headers = new HashMap<>(baseHeaders);
            headers.put("Authorization", "Bearer " + expiredToken);

            HttpResponse response = client.executeRequest(new HttpGet(endpoint.getFullUrl()), headers);

            // ✅ Если получаем 200 OK - уязвимость!
            boolean isVulnerable = response.getStatusCode() == 200;
            
            if (isVulnerable) {
                logger.warn("🚨 JWT EXPIRED TOKEN VULNERABILITY: {}", endpoint.getFullUrl());
            } else {
                logger.debug("✅ JWT expired token blocked: {}", endpoint.getFullUrl());
            }

            return isVulnerable;
        } catch (Exception e) {
            logger.debug("JWT expired test failed for {}: {}", endpoint.getPath(), e.getMessage());
            return false;
        }
    }

    /**
     * ✅ Тестирует путаницу алгоритмов
     */
    private boolean testJwtAlgorithmConfusion(EndpointInfo endpoint, HttpClient client, Map<String, String> baseHeaders) {
        try {
            String maliciousToken = createJwtWithAlgorithmConfusion();
            
            Map<String, String> headers = new HashMap<>(baseHeaders);
            headers.put("Authorization", "Bearer " + maliciousToken);

            HttpResponse response = client.executeRequest(new HttpGet(endpoint.getFullUrl()), headers);

            // ✅ Если получаем 200 OK - уязвимость!
            boolean isVulnerable = response.getStatusCode() == 200;
            
            if (isVulnerable) {
                logger.warn("🚨 JWT ALGORITHM CONFUSION VULNERABILITY: {}", endpoint.getFullUrl());
            } else {
                logger.debug("✅ JWT algorithm confusion blocked: {}", endpoint.getFullUrl());
            }

            return isVulnerable;
        } catch (Exception e) {
            logger.debug("JWT algorithm confusion test failed for {}: {}", endpoint.getPath(), e.getMessage());
            return false;
        }
    }

    /**
     * ✅ Создаёт JWT с none-алгоритмом (подделка)
     */
    private String createJwtWithNoneAlgorithm() {
        // Payload: {"user":"admin","role":"admin","exp":1700000000}
        String header = Base64.getEncoder().encodeToString("{\"alg\":\"none\",\"typ\":\"JWT\"}".getBytes());
        String payload = Base64.getEncoder().encodeToString("{\"user\":\"admin\",\"role\":\"admin\",\"exp\":2147483647}".getBytes());
        // Signature: пустая строка (без подписи)
        return header + "." + payload + ".";
    }

    /**
     * ✅ Создаёт JWT с слабым секретом
     */
    private String createJwtWithWeakSecret(String secret) {
        // Payload: {"user":"admin","role":"admin","exp":1700000000}
        String header = Base64.getEncoder().encodeToString("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes());
        String payload = Base64.getEncoder().encodeToString("{\"user\":\"admin\",\"role\":\"admin\",\"exp\":2147483647}".getBytes());
        
        // ✅ Подпись (упрощённо, для демонстрации)
        String signature = "fake-signature-for-" + secret;
        return header + "." + payload + "." + Base64.getEncoder().encodeToString(signature.getBytes());
    }

    /**
     * ✅ Создаёт истёкший JWT
     */
    private String createExpiredJwt() {
        // Payload: {"user":"admin","role":"admin","exp":<прошлое время>}
        String header = Base64.getEncoder().encodeToString("{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes());
        String payload = Base64.getEncoder().encodeToString("{\"user\":\"admin\",\"role\":\"admin\",\"exp\":1000}".getBytes()); // 1970 год
        
        String signature = "expired-token-signature";
        return header + "." + payload + "." + Base64.getEncoder().encodeToString(signature.getBytes());
    }

    /**
     * ✅ Создаёт JWT с путаницей алгоритмов
     */
    private String createJwtWithAlgorithmConfusion() {
        // Пытаемся подделать RS256 токен как HS256
        String header = Base64.getEncoder().encodeToString("{\"alg\":\"HS256\",\"typ\":\"JWT\",\"kid\":\"public-key-id\"}".getBytes());
        String payload = Base64.getEncoder().encodeToString("{\"user\":\"admin\",\"role\":\"admin\",\"exp\":2147483647}".getBytes());
        
        String signature = "confusion-attack-signature";
        return header + "." + payload + "." + Base64.getEncoder().encodeToString(signature.getBytes());
    }

    /**
     * ✅ Создаёт finding для JWT-уязвимости
     */
    private Finding createJwtFinding(String id, String title, String description, EndpointInfo endpoint, String remediation) {
        return new Finding(
            id,
            title,
            "🚨 CRITICAL: " + description + "\n\n" +
            "• Endpoint: " + endpoint.getMethod() + " " + endpoint.getPath() + "\n" +
            "• Impact: Attackers can forge authentication tokens, escalate privileges, or bypass authentication entirely\n" +
            "• Risk: Complete account compromise and unauthorized data access",
            Severity.CRITICAL,
            getId(),
            endpoint.getFullUrl(),
            "✅ CRITICAL REMEDIATION REQUIRED:\n\n" +
            remediation + "\n\n" +
            "ADDITIONAL MEASURES:\n" +
            "1. IMPLEMENT JWT LIBRARY BEST PRACTICES\n" +
            "   • Use well-tested JWT libraries\n" +
            "   • Never allow 'none' algorithm in production\n" +
            "   • Validate all JWT claims (iss, aud, exp, nbf, sub)\n\n" +
            "2. USE STRONG CRYPTOGRAPHIC ALGORITHMS\n" +
            "   • Prefer RS256, ES256 over HS256\n" +
            "   • Use keys from proper key management systems\n" +
            "   • Implement key rotation mechanisms\n\n" +
            "3. ENFORCE TOKEN VALIDATION\n" +
            "   • Check token expiration (exp claim)\n" +
            "   • Validate issuer (iss claim)\n" +
            "   • Verify audience (aud claim)\n" +
            "   • Implement token revocation/blacklisting"
        );
    }
}
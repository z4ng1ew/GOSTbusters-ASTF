package org.owasp.astf.testcases.bola.service;

import org.owasp.astf.core.http.HttpClient;

public interface ConsentService {
    String createConsent(String baseUrl, HttpClient client);
}
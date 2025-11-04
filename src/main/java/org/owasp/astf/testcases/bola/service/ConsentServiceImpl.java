package org.owasp.astf.testcases.bola.service;

import org.owasp.astf.core.http.HttpClient;

public class ConsentServiceImpl implements ConsentService {
    @Override
    public String createConsent(String baseUrl, HttpClient client) {
        // Ваша логика создания согласия
        return "consent-id";
    }
}
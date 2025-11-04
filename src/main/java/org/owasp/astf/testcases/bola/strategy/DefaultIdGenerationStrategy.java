package org.owasp.astf.testcases.bola.strategy;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class DefaultIdGenerationStrategy implements IdGenerationStrategy {
    @Override
    public List<String> generateIds(List<String> ourIds) {
        List<String> suspiciousIds = new ArrayList<>();
        // Ваша логика генерации ID
        // ...
        return suspiciousIds;
    }
}
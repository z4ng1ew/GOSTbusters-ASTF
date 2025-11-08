package org.owasp.astf.plugin;

import org.owasp.astf.shared.EndpointInfo;
import org.owasp.astf.shared.http.HttpClient;
import org.owasp.astf.shared.result.Finding;
import org.owasp.astf.testcases.TestCase;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.ArrayList;
import java.util.List;
import java.util.ServiceLoader;

/**
 * Manages the lifecycle of security test plugins.
 * <p>
 * This class is responsible for dynamically loading plugin JAR files,
 * discovering {@link TestCase} implementations within them, and providing
 * them to the scanner engine.
 * </p>
 */
public class PluginManager {

    /**
     * Loads security test cases from a list of plugin JAR file paths.
     *
     * @param jarPaths A list of file paths to plugin JAR files.
     * @return A list of {@link TestCase} instances loaded from the plugins.
     * @throws RuntimeException if there is an error loading the plugins.
     */
    public List<TestCase> loadPluginsFromJars(List<String> jarPaths) {
        List<TestCase> loadedTestCases = new ArrayList<>();

        if (jarPaths == null || jarPaths.isEmpty()) {
            System.out.println("🔍 No plugin JARs specified. Skipping plugin loading.");
            return loadedTestCases;
        }

        System.out.println("🔌 Loading " + jarPaths.size() + " plugin(s)...");

        for (String jarPathStr : jarPaths) {
            File jarFile = new File(jarPathStr);
            if (!jarFile.exists() || !jarFile.isFile() || !jarFile.canRead()) {
                System.err.println("❌ Plugin file does not exist or is not readable: " + jarPathStr);
                continue; // Skip invalid files
            }

            try {
                // 1. Создаем URLClassLoader для конкретного JAR
                URL jarUrl = jarFile.toURI().toURL();
                URLClassLoader loader = new URLClassLoader(new URL[]{jarUrl}, getClass().getClassLoader());

                // 2. Используем ServiceLoader с этим конкретным ClassLoader
                ServiceLoader<TestCase> serviceLoader = ServiceLoader.load(TestCase.class, loader);

                // 3. Собираем все TestCase из этого JAR
                int jarTestCaseCount = 0;
                for (TestCase testCase : serviceLoader) {
                    loadedTestCases.add(testCase);
                    System.out.println("✅ Loaded plugin: " + testCase.getId() + " - " + testCase.getName());
                    jarTestCaseCount++;
                }

                if (jarTestCaseCount == 0) {
                    System.out.println("⚠️ No TestCase implementations found in plugin JAR: " + jarPathStr);
                } else {
                    System.out.println("📊 Found " + jarTestCaseCount + " test case(s) in " + jarPathStr);
                }

            } catch (MalformedURLException e) {
                System.err.println("❌ Invalid JAR URL: " + jarPathStr + " - " + e.getMessage());
            } catch (Exception e) {
                System.err.println("❌ Error loading plugin from JAR: " + jarPathStr + " - " + e.getMessage());
                e.printStackTrace(); // Выводим стек трейс для отладки
            }
        }

        System.out.println("✅ Plugin loading completed. Total loaded: " + loadedTestCases.size());
        return loadedTestCases;
    }

    /**
     * Demonstrates how a plugin test case might be implemented.
     * This is an example that could reside inside a separate plugin JAR.
     * It's included here for reference on how plugins integrate.
     */
    public static class ExamplePluginTestCase implements TestCase {

        @Override
        public String getId() {
            return "EXAMPLE_PLUGIN";
        }

        @Override
        public String getName() {
            return "Example Plugin Test Case";
        }

        @Override
        public String getDescription() {
            return "An example test case loaded from a plugin JAR.";
        }

        @Override
        public List<Finding> execute(EndpointInfo endpoint, HttpClient client) {
            // Пример простой проверки - замените логикой вашего плагина
            List<Finding> findings = new ArrayList<>();
            // Например, проверка на определённый заголовок или паттерн в ответе
            if (endpoint.getPath().toLowerCase().contains("test")) {
                findings.add(new Finding(
                    getId(),
                    "Example Plugin Finding",
                    "This is a demonstration finding from a plugin.",
                    org.owasp.astf.shared.result.Severity.INFO,
                    endpoint.getFullUrl(),
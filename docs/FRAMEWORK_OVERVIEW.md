# GOSTbusters API Security Testing Framework (ASTF) Overview
```
## What This Framework Does

The **GOSTbusters API Security Testing Framework (ASTF)** is a comprehensive tool designed specifically for **Open Banking Russia v2.1** security testing with **GOST cryptographic standard support**. It identifies security vulnerabilities in banking APIs based on **OWASP API Security Top 10 2023**, focusing on **financial institution** security requirements.

**Developed by Team GOSTbusters for VTB API Security Hackathon 2025.**
```

### 1. Security Testing Coverage (OWASP API Top 10 2023)

The framework executes comprehensive tests targeting all 10 OWASP API Security Top 10 2023 categories:

- **API1:2023** - Broken Object Level Authorization (BOLA)
- **API2:2023** - Broken Authentication
- **API3:2023** - Broken Object Property Level Authorization & Excessive Data Exposure
- **API4:2023** - Lack of Resources & Rate Limiting
- **API5:2023** - Broken Function Level Authorization
- **API6:2023** - Mass Assignment
- **API7:2023** - Server-Side Request Forgery (SSRF)
- **API8:2023** - Security Misconfiguration
- **API9:2023** - Improper Inventory Management
- **API10:2023** - Unsafe Consumption of APIs

### 2. Open Banking Russia Integration

* **Team-based authentication** using `client_id` and `client_secret`
* **Cross-bank consent management** for accessing foreign accounts
* **RS256 token validation** for secure banking API communication
* **Multi-bank testing** (VBank, ABank, SBank)
* **Automatic consent creation** for testing scenarios
* **Compliance with Open Banking Russia v2.1 standards**


### 3. GOST Cryptographic Standards Support

* **GOST 28147-89** (DES-like encryption)
* **GOST R 34.10-2012** (digital signatures)
* **GOST R 34.11-2012** (hash functions)
* **Configurable GOST gateway integration**
* **Ready for deployment in Russian financial institutions**


### 4. Plugin Architecture

* **SPI-based** (Service Provider Interface) plugin system
* **Dynamic loading** of external test cases
* **Modular design** for easy extension
* **Ready for marketplace distribution**



## How It Works

The framework operates using a black-box testing approach:

1. **Endpoint Discovery**: Automatically discovers API endpoints through:
    - OpenAPI/Swagger specification parsing
    - Common endpoint pattern testing
    - Intelligent path traversal
    - Manual endpoint specification

2. **Security Testing**: Executes a comprehensive suite of tests targeting **all 10 OWASP API Security Top 10 2023**:
    - **API1:2023** - Broken Object Level Authorization
    - **API2:2023** - Broken Authentication
    - **API3:2023** - Broken Object Property Level Authorization & Excessive Data Exposure
    - **API4:2023** - Lack of Resources & Rate Limiting
    - **API5:2023** - Broken Function Level Authorization
    - **API6:2023** - Mass Assignment
    - **API7:2023** - Server-Side Request Forgery (SSRF)
    - **API8:2023** - Security Misconfiguration
    - **API9:2023** - Improper Inventory Management
    - **API10:2023** - Unsafe Consumption of APIs

3. **Vulnerability Reporting**: Provides detailed findings including:
    - Severity classification
    - Vulnerability details
    - Evidence capture
    - Remediation guidance
    - References to OWASP standards and Open Banking Russia requirements

## Key Capabilities

### Dynamic API Testing

* Tests live API endpoints without needing source code
* Detects vulnerabilities through intelligent request manipulation
* Identifies security issues that affect banking APIs specifically

### Open Banking Russia Integration

* **Team-based authentication** using `client_id` and `client_secret`
* **Cross-bank consent management** for accessing foreign accounts
* **RS256 token validation** for secure banking API communication
* **Multi-bank testing** (VBank, ABank, SBank)
* **Automatic consent creation** for testing scenarios
* **Compliance with Open Banking Russia v2.1 standards**

### GOST Cryptographic Standards Support

* **GOST 28147-89** (DES-like encryption)
* **GOST R 34.10-2012** (digital signatures)
* **GOST R 34.11-2012** (hash functions)
* **Configurable GOST gateway integration**
* **Ready for deployment in Russian financial institutions**

### Authentication & Authorization Testing

* Tests for improper access controls
* Detects weak authentication mechanisms
* Identifies JWT vulnerabilities
* Tests for privilege escalation
* Validates consent management systems

### Data Protection Analysis

* Identifies sensitive data exposure
* Detects missing encryption
* Finds excessive data in responses
* Validates OpenAPI contract compliance

### Resource Protection

* Tests for missing rate limiting
* Identifies DoS vulnerabilities
* Detects resource consumption issues
* Validates API quota management

### Plugin Architecture

* **SPI-based** (Service Provider Interface) plugin system
* **Dynamic loading** of external test cases
* **Modular design** for easy extension
* **Ready for marketplace distribution**

### Integration Capabilities

* CI/CD pipeline integration (GitHub Actions, Jenkins)
* SARIF output for security dashboards
* HTML reports for stakeholders
* Command-line interface for scripting
* **PDF reports** with OWASP API Top 10 compliance indicators

## Use Cases

### Financial Institutions

* Test banking APIs during development
* Validate Open Banking compliance
* Perform regular security assessments
* Generate regulatory compliance evidence

### Security Teams

* Assess API security posture
* Validate vendor API security
* Identify cross-bank security issues
* Monitor for GOST standard compliance

### DevSecOps

* Automate API security testing in pipelines
* Generate compliance evidence for CBR
* Track security improvements over time
* Integrate with existing security tools

## Technical Architecture

The framework is built on a modular Java 21 architecture:

* **Core Engine**: Manages test execution and coordination using virtual threads
* **HTTP Client**: Handles API communications and request manipulation (OkHttp3)
* **Test Cases**: Modular, extensible security tests implementing `TestCase` interface
* **Reporting Engine**: Generates findings in multiple formats (JSON, HTML, PDF, SARIF)
* **CLI Interface**: Provides user interaction and configuration
* **Plugin API**: ServiceLoader-based dynamic extension system

## Intended Audience

The ASTF is designed for:

* **Banking security engineers**
* **Open Banking API developers**
* **DevOps engineers** (in financial institutions)
* **Security consultants** (specializing in fintech)
* **Quality assurance testers**

No deep security expertise is required to run basic scans, but security knowledge helps interpret results and implement fixes.

## Business Impact

* **Reduces manual security testing effort by 90%**
* **Ensures Open Banking Russia v2.1 compliance**
* **Supports GOST cryptographic standards for Russian market**
* **Enables automated security in CI/CD pipelines**
* **Provides OWASP API Top 10 2023 compliance evidence**
* **Ready for commercial deployment in financial institutions**

---

**Developed with ❤️ by Team GOSTbusters for VTB API Security Hackathon 2025**

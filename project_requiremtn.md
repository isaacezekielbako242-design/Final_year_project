# PROJECT DEVELOPMENT PROMPT: DESIGN AND IMPLEMENTATION OF A VULNERABILITY SCANNER FOR E-COMMERCE WEBSITES

Act as a senior Python software developer, web application security engineer, and software architect. I am developing a final-year academic project titled **"Design and Implementation of a Vulnerability Scanner."**

I have attached my Chapter Three document, which contains the System Analysis and Design for the project. Read the document carefully and use it as the primary technical specification for the implementation.

Your task is to DESIGN, DEVELOP, IMPLEMENT, AND TEST a complete, functional vulnerability scanning application that follows the requirements in my document.

Do not simply provide an explanation, pseudocode, or isolated code examples. Build a working project with properly organized source files, functional modules, a database-backed testbed, a user interface, reports, and instructions for running everything.

## 1. PROJECT OVERVIEW

The project involves developing an automated vulnerability testing application for e-commerce websites and a controlled e-commerce testbed for evaluating the scanner.

The scanner should examine a target e-commerce website for five selected categories of vulnerabilities:

1. SQL Injection (SQLi).
2. Cross-Site Scripting (XSS).
3. Cross-Site Request Forgery (CSRF).
4. Broken Access Control.
5. Security Misconfiguration.

The application should crawl the target website, identify accessible pages, forms, links, and input parameters, perform the appropriate security checks, analyse responses, record confirmed findings, and generate a structured security report.

A separate controlled e-commerce testbed must also be developed. This testbed should contain deliberately introduced examples of the five selected vulnerability categories so that the scanner can be evaluated against known vulnerabilities.

The application must be designed primarily for educational and authorized security testing.

## 2. REQUIRED TECHNOLOGIES

Use the following technologies as specified in my system design:

**Scanner application:**
- Python 3.10 or later.
- Requests for HTTP requests and authenticated sessions.
- BeautifulSoup for HTML parsing and website crawling.
- Jinja2 for generating HTML reports.
- JSON for exporting scan results.

**E-commerce testbed:**
- Python Flask.
- SQLite database.
- HTML, CSS, and JavaScript for the interface.

**Development environment:**
- Visual Studio Code.
- Git for version control.
- Browser developer tools for inspecting requests, responses, and cookies.

Use simple, maintainable technologies. Avoid unnecessary frameworks, complicated configurations, and paid services.

## 3. APPLICATION INTERFACE

Develop a clean, modern, professional interface that allows a user to interact with the vulnerability scanner easily.

The interface should include:

- A dashboard displaying the application name and a brief description.
- A target URL input field.
- An authorization confirmation checkbox that must be selected before scanning.
- Fields for entering test credentials.
- Support for at least two test-user accounts for authenticated access-control testing.
- A button to start vulnerability scanning.
- A scanning progress indicator.
- A summary of detected vulnerabilities.
- A results section showing the vulnerability category, affected URL, parameter, severity, and evidence.
- A button for viewing the full HTML report.
- An option to download the findings in JSON format.

Make the interface responsive and easy to understand, even for users with limited cybersecurity experience.

Do not make the dashboard merely decorative. All buttons, forms, and displayed results must work.

## 4. WEBSITE CRAWLER

Develop a website crawler that:

- Accepts a valid target website URL.
- Checks that the target is reachable.
- Restricts scanning to the authorized target host.
- Discovers internal links and accessible pages.
- Identifies HTML forms and their input fields.
- Extracts relevant URL parameters.
- Identifies pages that require authentication.
- Supports authenticated crawling using supplied test credentials.
- Records discovered pages, forms, and parameters for the detection modules.

The crawler must not follow links to unrelated external domains.

Implement request timeouts, error handling, a configurable crawl limit, and reasonable request delays.

## 5. VULNERABILITY DETECTION MODULES

Implement five independent detection modules. Each module should have its own Python file or clearly separated component so that it can be maintained independently.

### A. SQL Injection Detection

Develop a module that:

- Identifies parameters that accept user input.
- Sends controlled SQL injection test inputs.
- Checks responses for recognizable database error messages.
- Uses basic true/false Boolean-based response comparisons.
- Compares test responses with normal baseline responses.
- Records supporting evidence when a potential vulnerability is confirmed.

Do not implement destructive database operations, data extraction, or database modification.

### B. Cross-Site Scripting (XSS) Detection

Develop a module that:

- Identifies forms and URL parameters that accept input.
- Submits unique, harmless XSS marker strings.
- Checks whether submitted markers are reflected in the response.
- Examines whether HTML-significant characters are properly encoded.
- Reports reflected XSS only when the evidence supports the finding.

Clearly state that the implemented checks focus on reflected XSS and do not claim to detect all stored or DOM-based XSS vulnerabilities.

### C. Cross-Site Request Forgery (CSRF) Detection

Develop a module that:

- Identifies forms that perform state-changing operations.
- Checks whether anti-CSRF tokens are present.
- Examines whether requests without valid tokens are accepted.
- Uses safe test accounts and reversible operations in the controlled testbed.
- Records evidence supporting any confirmed CSRF finding.

Do not perform unauthorized state-changing operations on third-party websites.

### D. Broken Access Control Detection

Develop a module that:

- Supports at least two authenticated user sessions.
- Identifies user-specific resources, such as profile pages and order details.
- Attempts controlled access to one user's resources using another user's session.
- Checks whether the application properly enforces ownership restrictions.
- Reports a finding when one user can access another user's protected information.

Use only test accounts and fictitious information.

### E. Security Misconfiguration Detection

Develop a module that examines HTTP responses for:

- Missing Content-Security-Policy headers.
- Missing X-Content-Type-Options headers.
- Missing X-Frame-Options headers.
- Session cookies without HttpOnly attributes.
- Session cookies without SameSite attributes.
- Verbose error messages and exposed stack traces.

Each module must produce structured findings containing the vulnerability category, affected URL, affected parameter where applicable, test input, supporting evidence, and severity.

## 6. CONTROLLED E-COMMERCE TESTBED

Develop a separate Flask-based e-commerce website that serves as the controlled environment for testing the scanner.

The testbed should include the following functions:

- User registration.
- User login and logout.
- Product listing.
- Product search.
- Product details.
- Shopping cart.
- Cart updates.
- Checkout.
- Order history.
- Customer profile.

Create at least two test-user accounts with separate orders and profile information.

Use fictitious customer details and sample products.

### Deliberately Vulnerable Version

Create a vulnerable version of the testbed containing documented examples of all five selected vulnerability categories.

Include the following test cases:

1. SQL Injection in product search.
2. SQL Injection in product details.
3. Reflected XSS in search results.
4. Reflected XSS in a cart status message.
5. CSRF in the profile update function.
6. CSRF in the order placement function.
7. Broken access control in order details.
8. Broken access control in profile viewing.
9. Missing security headers.
10. Insecure session cookie attributes.
11. Verbose error messages containing technical details.

These vulnerabilities should be deliberately implemented only within the isolated local testbed.

### Patched Control Version

Also develop a patched version of the testbed with the same functionality but with the vulnerabilities corrected.

Use:

- Parameterized SQL queries.
- Proper output encoding.
- CSRF protection.
- Ownership checks for customer profiles and orders.
- Appropriate security headers.
- Secure session cookie attributes.
- Generic error messages.

The vulnerable and patched versions must have the same basic application structure and functionality so that the scanner can be evaluated against both.

Make it easy to switch between the two versions.

## 7. DATABASE DESIGN

Use SQLite for the e-commerce testbed.

Create the following database tables:

**Users**
- user_id
- username
- password_hash
- email
- address

**Products**
- product_id
- name
- description
- category
- price
- stock

**Cart Items**
- cart_item_id
- user_id
- product_id
- quantity

**Orders**
- order_id
- user_id
- total_amount
- status
- order_date

**Order Items**
- order_item_id
- order_id
- product_id
- quantity
- unit_price

Implement the appropriate primary keys, foreign keys, and relationships.

Passwords must be securely hashed, including in the vulnerable testbed. The deliberate vulnerabilities should be limited to the specific test cases described above.

Create a database initialization and seeding script that automatically creates the required tables, sample products, and test accounts.

## 8. SCAN RESULTS AND REPORT GENERATION

Implement a results-processing component that:

- Collects findings from all five detection modules.
- Removes duplicate findings where appropriate.
- Classifies findings by vulnerability category.
- Assigns High, Medium, or Low severity ratings.
- Stores the affected URL, parameter, test input, and supporting evidence.

Generate a professional HTML security report containing:

- Scan date and time.
- Target website.
- Scan summary.
- Total vulnerabilities identified.
- Vulnerabilities grouped by category.
- Severity classification.
- Affected URLs and parameters.
- Evidence supporting each finding.
- Brief remediation recommendations.

Also provide JSON export functionality.

The scanner's findings should be stored in memory during the scan and exported to JSON when the scan is completed. The scanner itself does not require a separate database.

## 9. GROUND-TRUTH REGISTER AND EVALUATION

Create a ground-truth register containing the known vulnerabilities deliberately introduced into the vulnerable testbed.

The register should record:

- Vulnerability identifier.
- Vulnerability category.
- Affected URL.
- Affected parameter or function.
- Description of the weakness.
- Expected detection evidence.

Implement an evaluation process that compares the scanner's findings with the ground-truth register.

Calculate:

**True Positive (TP):** A reported finding that matches a documented vulnerability.

**False Positive (FP):** A reported finding that does not match a documented vulnerability.

**False Negative (FN):** A documented vulnerability that the scanner fails to detect.

Calculate the following metrics:

Precision = TP / (TP + FP)

Recall = TP / (TP + FN)

F1 Score = 2 × (Precision × Recall) / (Precision + Recall)

Also calculate detection coverage for each vulnerability category.

Display the evaluation results in a clear summary.

Run the scanner against both the vulnerable and patched versions of the testbed. Findings reported against the patched version should be examined as possible false positives.

Do not fabricate evaluation results. The metrics must be calculated from actual scan results and the documented ground truth.

## 10. SECURITY AND ETHICAL SAFEGUARDS

The scanner must include the following safeguards:

- Require authorization confirmation before every scan.
- Restrict requests to the specified target host.
- Do not follow external-domain links.
- Apply request timeouts and rate limits.
- Use non-destructive testing techniques.
- Do not include exploitation, data theft, or destructive attack features.
- Use fictitious data in the testbed.
- Do not save supplied login credentials in scan reports.
- Make it clear that the scanner is intended for authorized testing only.

Default testing should use the local controlled testbed.

## 11. SOFTWARE ARCHITECTURE

Organize the project using a modular structure.

Use a clear separation between:

- Scanner interface.
- Target configuration and scope control.
- Website crawler.
- Authentication and session management.
- SQL injection detection module.
- XSS detection module.
- CSRF detection module.
- Broken access control detection module.
- Security misconfiguration detection module.
- Results processing.
- Report generation.
- JSON export.
- E-commerce testbed.
- Database initialization.
- Ground-truth register.
- Evaluation module.

Avoid putting the entire application into one Python file.

## 12. TESTING AND QUALITY ASSURANCE

Implement tests to verify:

- The scanner can accept and validate a target URL.
- Authorization is required before scanning.
- The crawler identifies internal pages and forms.
- Each vulnerability detection module performs its intended checks.
- Authenticated scanning works with two user accounts.
- The report generator displays findings correctly.
- JSON export works.
- The vulnerable testbed exposes the documented test cases.
- The patched testbed corrects the documented vulnerabilities.
- Evaluation metrics are calculated correctly.

Include error handling for unavailable websites, failed logins, malformed responses, and inaccessible pages.

The scanner should not crash simply because a page cannot be reached.

## 13. EXPECTED PROJECT FOLDER STRUCTURE

Use a clean folder structure similar to the following. You may improve it if there is a good technical reason.

vulnerability-scanner/

- app.py
- config.py
- requirements.txt
- README.md

- scanner/
  - crawler.py
  - target_validation.py
  - authentication.py
  - detection_engine.py
  - sql_injection.py
  - xss.py
  - csrf.py
  - broken_access_control.py
  - security_misconfiguration.py
  - results_processor.py
  - report_generator.py
  - evaluator.py

- testbed/
  - app.py
  - database.py
  - models.py
  - vulnerable_routes.py
  - patched_routes.py
  - templates/
  - static/

- evaluation/
  - ground_truth.json
  - evaluation_results/

- reports/

- tests/

You may adjust the structure where necessary, but maintain a clear separation between the scanner and the testbed.

## 14. IMPORTANT DEVELOPMENT INSTRUCTIONS

Follow these instructions carefully:

1. Read my attached Chapter Three before beginning implementation.
2. Treat the chapter as the primary specification. Do not introduce unrelated features or change the five selected vulnerability categories.
3. Build a genuinely functional application, not a user-interface mock-up.
4. Ensure that all buttons, modules, forms, scanning operations, and report-generation functions work.
5. Do not claim that a vulnerability has been detected unless the implemented checks produce supporting evidence.
6. Do not hardcode successful scan results.
7. Do not fabricate evaluation metrics.
8. Do not silently replace the custom Flask e-commerce testbed with OWASP Juice Shop or another benchmark. If you identify a conflict between the document's reference to OWASP Juice Shop and its detailed custom Flask testbed design, explain the difference and retain the custom Flask testbed as the primary implementation unless I explicitly request otherwise.
9. Keep the implementation understandable enough for a final-year computer science student to explain, maintain, and defend.
10. Include comments in important parts of the code.
11. Provide a complete README with installation, configuration, database initialization, starting the scanner, starting the testbed, and running the tests.
12. Do not leave essential modules as placeholders or empty functions.
13. If a feature cannot be implemented reliably within the project scope, explain the limitation rather than pretending it works.

## 15. HOW I WANT YOU TO WORK

Do not try to generate the entire project in one enormous response.

Work in stages:

**Stage 1:** Analyse my Chapter Three and produce a technical implementation plan. Identify the application components, data flow, development stages, and any contradictions or unclear requirements.

**Stage 2:** Create the project folder structure and implement the Flask e-commerce testbed, including its vulnerable and patched versions.

**Stage 3:** Implement the scanner interface, target validation, scope control, crawler, and authentication/session handling.

**Stage 4:** Implement and test the five independent vulnerability detection modules.

**Stage 5:** Implement results processing, HTML reporting, JSON export, ground-truth comparison, and evaluation metrics.

**Stage 6:** Integrate all components, run tests, fix errors, and provide complete setup and usage instructions.

At the end of each stage, explain what has been completed, list the files created or modified, and identify anything that remains unfinished.

Where your environment supports creating project files, create the actual files rather than merely printing their contents. If you cannot create files directly, provide the complete code in clearly labelled files and explain how to assemble the project.

Do not move to the next stage while essential errors in the current stage remain unresolved.

**FINAL EXPECTATION:** I want a working, modular Python vulnerability scanner and a separate controlled e-commerce testbed that follow my Chapter Three design. The application must be testable, produce genuine scan findings, generate reports, and allow me to evaluate its detection performance against known vulnerabilities.
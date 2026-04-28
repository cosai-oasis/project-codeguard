# Security Code Review Guidelines

## **1. Purpose**

The purpose of this guideline is to define a standardized, comprehensive process for conducting security code reviews of application codebases. This guideline enables AI agents to systematically identify security vulnerabilities, assess risk severity, and provide actionable remediation guidance aligned with industry best practices (OWASP, CWE, NIST, CIS).

Automated security code review should combine **static analysis**, **contextual code understanding**, and **security rule correlation** to identify vulnerabilities that could lead to data breaches, unauthorized access, or system compromise.

**Security rules for code review are sourced from [Project CodeGuard](https://github.com/cosai-oasis/project-codeguard), organized in two primary directories:**

- **[`sources/core/`](https://github.com/cosai-oasis/project-codeguard/tree/main/sources/core)** - Core security playbooks (foundational rules)
- **[`sources/owasp/`](https://github.com/cosai-oasis/project-codeguard/tree/main/sources/owasp)** - OWASP-based best practices

**CRITICAL REQUIREMENT:** AI agents must follow a prioritized rule-loading strategy to optimize context window usage while ensuring comprehensive security coverage.

**Rule Loading Priority:**

**MANDATORY (Load ALL - Non-Negotiable):**

1. **Core Rules** - Foundational security guardrails applicable to all codebases

   ```text
   https://github.com/cosai-oasis/project-codeguard/tree/main/sources/core/*.md
   ```

**SELECTIVE (Load Based on Target Tech Stack):**

2. **OWASP Rules** - Technology-specific security guidance (load only relevant files)

   ```text
   https://github.com/cosai-oasis/project-codeguard/tree/main/sources/owasp/*.md
   ```

**Rule Loading Strategy:**

1. **Phase 1a: Load Mandatory Core Rules**
   - Fetch or read ALL `*.md` files from Project CodeGuard `sources/core/`
   - Read ALL discovered files in parallel batches (15-20 per batch)
   - These rules are NON-NEGOTIABLE and must be 100% loaded

2. **Phase 1b: Identify Target Tech Stack**
   - Quick scan of target repository to identify languages/frameworks
   - Look for: `package.json` (Node.js), `requirements.txt` (Python), `pom.xml` (Java), `go.mod` (Go), etc.
   - List primary technologies: Python, JavaScript, Java, Go, Ruby, PHP, etc.

3. **Phase 1c: Load Relevant OWASP Rules**
   - Discover all `*.md` files from Project CodeGuard `sources/owasp/`
   - Read ONLY rules matching the identified tech stack
   - Examples:
     - If Python detected -> read OWASP rules related to Python, Django, Flask
     - If JavaScript detected -> read OWASP rules for Node.js, React, Express
     - If SQL files detected -> read SQL injection prevention rules
     - If APIs detected -> read API security rules
   - Skip unrelated rules (e.g., don't read Ruby rules if no Ruby code exists)

**Context Window Optimization:**

- **Priority 1**: Core rules (~22 files = ~45K tokens)
- **Priority 2**: Target repository source code (THIS IS THE MOST IMPORTANT)
- **Priority 3**: Relevant OWASP rules (selective, ~10-20 files = ~25K tokens)
- **Total Budget**: ~70K tokens for rules, leaving 900K+ tokens for code analysis

**Agent Context Window:** The agent has 1,000,000 tokens available. The goal is to maximize space for reading the TARGET CODEBASE, not rule files.

---

## **2. Quick Start for AI Agents**

**WARNING: Read Section 3.2 "Agent Thinking Patterns That Signal Failure" FIRST**

If you find yourself thinking "this is too large" or "I'll use a shortcut approach," you are about to fail. Section 3.2 addresses these exact thoughts and provides solutions.

**If you are an AI agent beginning a security code review, follow this sequence:**

### **Step 1: Load Mandatory Security Rules**

**1a. Load Core Rules (MANDATORY - 100% Required):**

Fetch all `*.md` files from Project CodeGuard's core directory:

```text
https://github.com/cosai-oasis/project-codeguard/tree/main/sources/core
```

Read ALL discovered files in parallel batches of 15-20 files.

**1b. Identify Target Tech Stack:**

Quick reconnaissance of target repo:

```text
glob_file_search("package.json")    # Node.js/JavaScript
glob_file_search("requirements*.txt") # Python
glob_file_search("go.mod")          # Go
glob_file_search("pom.xml")         # Java
glob_file_search("Gemfile")         # Ruby
glob_file_search("composer.json")   # PHP
glob_file_search("*.csproj")        # .NET
```

List detected languages/frameworks.

**1c. Load Relevant OWASP Rules (SELECTIVE):**

Fetch the file listing from Project CodeGuard's OWASP directory:

```text
https://github.com/cosai-oasis/project-codeguard/tree/main/sources/owasp
```

Read ONLY rules matching your detected tech stack. Skip unrelated rules.

Record: "Loaded X core rules + Y relevant OWASP rules"

### **Step 2: Discover ALL Files in Target Repository** -- **HIGHEST PRIORITY**

**CRITICAL: The target codebase is the most important part of the review. Maximize time and context spent reading YOUR application code, not rule files.**

Execute comprehensive file discovery using glob patterns (see Phase 2, Step 1 for complete list). Minimum patterns:

```text
Source Code: **/*.py, **/*.js, **/*.java, **/*.go, **/*.c, **/*.cpp, etc.
Configs: **/*.yml, **/*.json, **/*.toml, **/.env*
IaC: **/Dockerfile*, **/*.tf, **/*k8s*.yaml
Dependencies: **/requirements*.txt, **/package.json, **/pom.xml, **/go.mod
Security: **/*.pem, **/*.crt, **/*.key
```

**IMPORTANT: Ignore Binary Files** - Skip non-text files that cannot be analyzed:

```text
SKIP: **/*.pyc, **/*.so, **/*.dll, **/*.exe, **/*.bin, **/*.jar, **/*.war
SKIP: **/*.png, **/*.jpg, **/*.jpeg, **/*.gif, **/*.ico, **/*.svg
SKIP: **/*.pdf, **/*.zip, **/*.tar, **/*.gz, **/*.woff, **/*.ttf
SKIP: **/node_modules/**, **/.git/**, **/venv/**, **/__pycache__/**
```

Record total files discovered by category.

### **Step 3: Categorize Files by Risk**

- **Critical Risk**: Files with auth, password, credential, secret, token, crypto in name/path + all certs + all .env files
- **High Risk**: Files with database, sql, api, admin, permission, upload, exec, command + all IaC
- **Medium Risk**: Business logic, data processing, dependency manifests
- **Low Risk**: Tests, docs, static assets

### **Step 4: Read Files Systematically**

In parallel batches of 15-20:

1. Read 100% of Critical Risk files
2. Read 100% of High Risk files
3. Read 80%+ of Medium Risk files
4. Selectively read Low Risk files

Track progress: "Read X/Y critical, X/Y high, X/Y medium"

### **Step 5: Apply Rules & Generate Findings**

- Cross-reference every code section against loaded security rules
- Validate findings as true positives (not test code)
- Assign severity, extract code snippets, provide remediation

### **Step 6: Generate Comprehensive Report**

Include: Executive summary, detailed findings, remediation guidance, completeness metrics

**Remember:** You have 1,000,000 tokens. Use parallel tool calls. Track progress. Verify completeness.

---

## **3. Scope**

This document applies to **AI-based security review systems** performing comprehensive security assessments of:

- Application source code (all programming languages)
- Configuration files (environment variables, deployment configs, IaC)
- Dependency manifests (package managers, third-party libraries)
- Infrastructure as Code (IaC) templates
- Build and deployment scripts

The review covers all stages of the secure development lifecycle (SDLC) and addresses vulnerabilities across the OWASP Top 10, CWE Top 25, and industry security requirements.

---

## **3. Critical Success Factors**

### **3.1. Non-Negotiable Requirements**

**The following are MANDATORY for a valid security review:**

1. **Prioritized Rule Loading** (Optimized for Context Window)
   - **100% of core rules** MUST be read (non-negotiable)
   - **Only relevant OWASP rules** for your tech stack (selective)
   - Verify mandatory rules loaded = mandatory rules discovered
   - Document OWASP rules skipped with justification (tech not applicable)

2. **Comprehensive Target Codebase Analysis** -- **PRIMARY OBJECTIVE**
   - **100% of Critical Risk files** MUST be read
   - **100% of High Risk files** MUST be read
   - **Minimum 80% of Medium Risk files** MUST be read
   - Track and report what was read vs. skipped
   - **This is the most important requirement** - maximize code reading

3. **True Positive Verification**
   - Every finding must be validated as exploitable
   - Filter out test code, examples, and false alarms
   - Provide exploit path for each vulnerability

### **3.2. Agent Thinking Patterns That Signal Failure**

**If you find yourself thinking any of these thoughts, STOP and re-read this guideline:**

**"The guidelines are too extensive to read fully"**

- **WRONG**: Thinking all OWASP rules must be read regardless of relevance
- **CORRECT**: Read ALL core rules, then ONLY relevant OWASP rules for your tech stack
- **Math**: ~22 core rules + 10 relevant OWASP rules = ~32 files / 20 per batch = 2 parallel batches
- **Priority**: Save context window space for reading the TARGET CODEBASE (most important)

**"I'll use a minimal approach to show compliance"**

- **WRONG**: Half-measures create false confidence and miss critical vulnerabilities
- **CORRECT**: Either do a complete review or clearly state you cannot perform the task
- **Impact**: Incomplete reviews are worse than no review -- they create blind spots

**"I'll focus on key high-risk directories and skip others"**

- **WRONG**: You don't know what's high-risk until you've analyzed the code
- **CORRECT**: Use glob patterns to discover ALL files, categorize by risk, then read 100% of critical/high
- **Reality**: Vulnerabilities hide in unexpected places -- assumptions create gaps

**"I'll use grep/rg to search for patterns instead of reading files"**

- **WRONG**: Grep finds known patterns but misses context, logic flaws, and novel vulnerabilities
- **CORRECT**: Use grep for specific targeted searches AFTER comprehensive file reading
- **Example**: Grep finds `password =`, but misses weak crypto, auth bypass, and injection flaws

**"The repo is too large, I'll process guidelines incrementally"**

- **WRONG**: You're thinking sequentially (one file at a time) instead of in parallel
- **CORRECT**: Read 15-20 rules simultaneously, then 15-20 code files simultaneously
- **Tool Usage**: `read_file(file1) + read_file(file2) + ... + read_file(file20)` in ONE call

**"I'll mark guideline review as pending and move forward"**

- **WRONG**: Phase 1 (rule loading) is MANDATORY before Phase 2 (code analysis)
- **CORRECT**: Complete Phase 1 fully, then proceed to Phase 2
- **Reason**: You can't identify vulnerabilities without knowing what to look for

**"I'll note coverage limits in the final report"**

- **WRONG**: The guideline specifies minimum coverage requirements (100% critical, 100% high, 80% medium)
- **CORRECT**: Meet the coverage requirements, or state the review is incomplete/invalid
- **Transparency**: Better to say "cannot complete" than deliver a flawed review

### **3.3. How to Overcome "Too Large" Objections**

**Problem**: "There are 200 files to read, this is too much"

**Solution**:

1. **Batch 1**: Read files 1-20 in parallel (20 `read_file()` calls in one request)
2. **Batch 2**: Read files 21-40 in parallel
3. **Batch 3**: Read files 41-60 in parallel
4. ... continue for 10 batches total = 200 files read

**Time Reality**: 10 batches of parallel reads is completely feasible and efficient.

**Problem**: "Reading sequentially will take forever"

**Solution**: DON'T read sequentially! Use parallel tool calls:

```text
BAD (Sequential - 200 separate calls):
read_file("file1.py")
<wait for result>
read_file("file2.py")
<wait for result>
... 198 more individual calls

GOOD (Parallel - 10 batches):
Batch 1: read_file("file1.py") + read_file("file2.py") + ... + read_file("file20.py")
Batch 2: read_file("file21.py") + read_file("file22.py") + ... + read_file("file40.py")
... 8 more batches
```

**Problem**: "I'll run out of context window space"

**Solution**: You have 1,000,000 tokens with optimized allocation:

**Optimized Token Budget:**
- Core rules: ~22 files x 2KB = ~44KB = ~11K tokens
- Selective OWASP rules: ~15 files x 2KB = ~30KB = ~7.5K tokens
- **Target codebase**: ~350 files x 3KB = ~1MB = ~250K tokens -- **PRIORITY**
- Total: ~270K tokens (only 27% of context window)
- **Remaining**: 730K tokens for additional files or context refresh

**Context Optimization Strategy:**

1. Load core rules first (mandatory)
2. Identify tech stack from target repo
3. Load only relevant OWASP rules (skip unrelated ones)
4. Maximize space for TARGET CODEBASE (the most important part)
5. Don't waste context on irrelevant OWASP rules
6. Don't waste context on binary files (`.pyc`, images, `node_modules/`)
7. Don't waste context on third-party dependencies

**Result**: More room for comprehensive analysis of YOUR application's security-relevant files

### **3.3. Success Indicators**

**A high-quality security review demonstrates:**

- **Complete Rule Coverage**: All rules from both directories loaded and documented
- **Systematic File Discovery**: Glob patterns used for all file types
- **Parallel Execution**: Multiple batches of 15-20 files read simultaneously
- **Risk-Based Prioritization**: Critical and high-risk files analyzed first
- **Comprehensive Analysis**: 100% of critical/high, 80%+ of medium files read
- **Verified Findings**: All vulnerabilities validated as true positives
- **Actionable Remediation**: Specific fixes provided for each issue
- **Progress Tracking**: Metrics documented throughout the review

### **3.4. Common Pitfalls to Avoid**

**These mistakes invalidate security reviews:**

**PITFALL #1**: "I'll just read a sample of files to save time"

- **Why this fails**: Security vulnerabilities can exist anywhere
- **Correct approach**: Use risk-based prioritization, but read ALL critical/high-risk files

**PITFALL #2**: "I'll skip reading rules that don't seem relevant"

- **Why this fails**: You can't know what's relevant until you read the rules
- **Correct approach**: Load ALL core rules first, then apply relevant ones during analysis

**PITFALL #3**: "I'll read files one at a time to be thorough"

- **Why this fails**: Wastes time, doesn't improve quality
- **Correct approach**: Read 15-20 files in parallel for speed and efficiency

**PITFALL #4**: "I found 50 issues, that's probably enough"

- **Why this fails**: Stopping early misses critical vulnerabilities
- **Correct approach**: Complete the full analysis before counting findings

**PITFALL #5**: "This file is probably safe based on its name"

- **Why this fails**: Assumptions lead to blind spots
- **Correct approach**: Use risk categorization, but verify with actual file content

**PITFALL #6**: "I'm running out of context, better stop reading files"

- **Why this fails**: You have 1M tokens - insufficient use of available resources
- **Correct approach**: Load aggressively, context will auto-refresh if needed

---

## **4. Prerequisites**

Before conducting a security code review, ensure:

1. **Access & Authorization**
   - Read access to the target codebase repository
   - Access to Project CodeGuard security rules (public GitHub repository)
   - Understanding of the application's architecture and technology stack

2. **Security Rules & Knowledge Base**
   - Access to security scanning rules from Project CodeGuard, organized in two primary directories:
     - **[`sources/core/`](https://github.com/cosai-oasis/project-codeguard/tree/main/sources/core)** - Core security playbooks following the pattern `codeguard-<tier>-<topic>.md` (e.g., `codeguard-0-authentication-mfa.md`, `codeguard-1-crypto-algorithms.md`)
     - **[`sources/owasp/`](https://github.com/cosai-oasis/project-codeguard/tree/main/sources/owasp)** - OWASP-based security guidance (e.g., `codeguard-0-sql-injection-prevention.md`, `codeguard-0-cross-site-scripting-prevention.md`)
   - Understanding of each rule's intent, detection patterns, and remediation guidance

3. **Baseline Understanding**
   - Application purpose and functionality
   - Authentication and authorization model
   - Data sensitivity and classification
   - External integrations and dependencies
   - Deployment environment (cloud, on-premises, hybrid)

---

## **4. Security Review Process**

The AI agent should follow a systematic, multi-phase approach to ensure comprehensive coverage.

### **Phase 1: Preparation & Rule Analysis**

**CRITICAL:** This phase uses a prioritized approach to maximize context for target code analysis.

**Step 1a: Load Mandatory Core Rules (100% Required)**

1. **Discover Core Rule Files**

   Fetch the listing of all `*.md` files from:

   ```text
   https://github.com/cosai-oasis/project-codeguard/tree/main/sources/core
   ```

   - Record total file count
   - These are NON-NEGOTIABLE core security rules

2. **Read ALL Core Rules in Parallel Batches**
   - Use parallel tool calls to read 15-20 files simultaneously
   - Example: If you found 22 core rules, read them in 2 parallel batches
   - Batch 1: read_file() calls for files 1-15 (parallel)
   - Batch 2: read_file() calls for files 16-22 (parallel)
   - **DO NOT** skip any core rules

**Step 1b: Identify Target Technology Stack**

3. **Quick Reconnaissance of Target Repository**
   - Use glob patterns to identify dependency manifests:

     ```text
     glob_file_search("package.json")       # Node.js/JavaScript
     glob_file_search("requirements*.txt")  # Python
     glob_file_search("go.mod")            # Go
     glob_file_search("pom.xml")           # Java/Maven
     glob_file_search("build.gradle")      # Java/Gradle
     glob_file_search("Gemfile")           # Ruby
     glob_file_search("composer.json")     # PHP
     glob_file_search("*.csproj")          # .NET/C#
     glob_file_search("Cargo.toml")        # Rust
     ```

   - List detected languages/frameworks/databases
   - Note if APIs, web frameworks, or specific libraries are present

**Step 1c: Load Relevant OWASP Rules (Selective)**

4. **Discover All OWASP Rules**

   Fetch the listing of all `*.md` files from:

   ```text
   https://github.com/cosai-oasis/project-codeguard/tree/main/sources/owasp
   ```

5. **Read ONLY Technology-Relevant OWASP Rules**
   - Based on Step 1b findings, read ONLY applicable rules:
     - **If Python detected**: Read OWASP rules for Python, Django, Flask, SQL injection, etc.
     - **If JavaScript detected**: Read rules for Node.js, React, Express, XSS, etc.
     - **If Java detected**: Read rules for Spring, Struts, deserialization, etc.
     - **If APIs detected**: Read API security, authentication, authorization rules
     - **If SQL detected**: Read SQL injection prevention rules
   - **SKIP** rules for technologies NOT in your target repo
   - Example: If no Ruby code exists, skip Ruby-specific OWASP rules

6. **Verify Rule Loading Completeness**
   - Confirm 100% of core rules loaded
   - Confirm relevant OWASP rules loaded (selective based on tech stack)
   - Document: "Loaded X core rules + Y relevant OWASP rules"

**Step 1d: Analyze Loaded Rules**

7. **Extract Key Information from Rules**
   - For each loaded rule, note:
     - Detection patterns (what to look for)
     - Vulnerability context (why it's dangerous)
     - Remediation guidance (how to fix it)
     - Technology/language applicability
   - Build a mental index of rules by category
   - Cross-reference related rules across directories

### **Phase 2: Comprehensive Code Analysis** -- **THIS IS THE MOST IMPORTANT PHASE**

**CRITICAL PRIORITY: Reading and analyzing the TARGET CODEBASE is the primary objective. Rules are just tools -- the real security value comes from comprehensively analyzing YOUR application's code.**

Conduct a thorough, systematic examination of the entire codebase:

**STEP 1: Complete File Discovery**

Use `glob_file_search` to discover ALL files in the repository. Execute these searches in parallel:

1. **Discover Source Code Files (Language-Specific Patterns)**

   ```text
   Python:     glob_file_search("**/*.py")
   JavaScript: glob_file_search("**/*.js") + glob_file_search("**/*.jsx")
   TypeScript: glob_file_search("**/*.ts") + glob_file_search("**/*.tsx")
   Java:       glob_file_search("**/*.java")
   Go:         glob_file_search("**/*.go")
   C/C++:      glob_file_search("**/*.c") + glob_file_search("**/*.cpp") + glob_file_search("**/*.h")
   Ruby:       glob_file_search("**/*.rb")
   PHP:        glob_file_search("**/*.php")
   C#:         glob_file_search("**/*.cs")
   Rust:       glob_file_search("**/*.rs")
   ```

2. **Discover Configuration & Infrastructure Files**

   ```text
   Config:         glob_file_search("**/*.yml") + glob_file_search("**/*.yaml") + glob_file_search("**/*.json")
   Environment:    glob_file_search("**/.env*") + glob_file_search("**/config/*")
   Docker:         glob_file_search("**/Dockerfile*") + glob_file_search("**/*docker-compose*.yml")
   Kubernetes:     glob_file_search("**/*k8s*.yaml") + glob_file_search("**/kustomization.yaml")
   Terraform:      glob_file_search("**/*.tf")
   CloudFormation: glob_file_search("**/*template*.yaml") + glob_file_search("**/*template*.json")
   ```

3. **Discover Dependency & Build Files**

   ```text
   Python:     glob_file_search("**/requirements*.txt") + glob_file_search("**/Pipfile*")
   JavaScript: glob_file_search("**/package*.json") + glob_file_search("**/yarn.lock")
   Java:       glob_file_search("**/pom.xml") + glob_file_search("**/build.gradle")
   Go:         glob_file_search("**/go.mod") + glob_file_search("**/go.sum")
   Ruby:       glob_file_search("**/Gemfile*")
   .NET:       glob_file_search("**/*.csproj") + glob_file_search("**/packages.config")
   ```

4. **Discover Security-Sensitive Files**

   ```text
   Certificates:   glob_file_search("**/*.pem") + glob_file_search("**/*.crt") + glob_file_search("**/*.key")
   SSH Keys:       glob_file_search("**/id_rsa*") + glob_file_search("**/*.pub")
   Scripts:        glob_file_search("**/*.sh") + glob_file_search("**/*.bash") + glob_file_search("**/*.ps1")
   ```

5. **Exclude Binary and Non-Analyzable Files**

   **DO NOT attempt to read or analyze these file types:**

   - **Compiled/Binary Code**: `*.pyc`, `*.pyo`, `*.so`, `*.dll`, `*.exe`, `*.bin`, `*.o`, `*.obj`, `*.class`
   - **Archives**: `*.jar`, `*.war`, `*.ear`, `*.zip`, `*.tar`, `*.gz`, `*.bz2`, `*.7z`, `*.rar`
   - **Images**: `*.png`, `*.jpg`, `*.jpeg`, `*.gif`, `*.bmp`, `*.ico`, `*.svg`, `*.webp`
   - **Fonts**: `*.woff`, `*.woff2`, `*.ttf`, `*.otf`, `*.eot`
   - **Media**: `*.mp4`, `*.avi`, `*.mov`, `*.mp3`, `*.wav`, `*.pdf`
   - **Lock Files** (optional skip): `package-lock.json`, `yarn.lock`, `poetry.lock`, `Pipfile.lock` (unless checking dependency versions)
   - **Dependency Directories**: `node_modules/`, `venv/`, `env/`, `.venv/`, `__pycache__/`, `vendor/`, `target/`, `dist/`, `build/`
   - **Version Control**: `.git/`, `.svn/`, `.hg/`

   **Why Exclude:**
   - Binary files cannot be read as text for security analysis
   - They consume context window space without providing value
   - Dependency directories contain third-party code (analyze manifests instead)
   - Security issues in binaries require different tools (binary analysis, not static code review)

   **What TO Analyze:**
   - Source code files (human-readable text)
   - Configuration files (YAML, JSON, TOML, INI, ENV)
   - Infrastructure as Code (Dockerfiles, Terraform, K8s manifests)
   - Dependency manifests (requirements.txt, package.json, pom.xml)
   - Scripts (shell, PowerShell, Python scripts)
   - Documentation files if they contain code examples or configurations

**STEP 2: File Categorization by Risk**

After discovery, categorize ALL files into risk levels:

- **CRITICAL RISK**: Files containing keywords in path or name:
  - `auth`, `login`, `password`, `credential`, `secret`, `key`, `token`, `oauth`, `jwt`, `session`, `crypto`, `encrypt`, `decrypt`, `sign`, `verify`
  - All certificate files (.pem, .crt, .key)
  - All environment configuration files (.env, config.*)
  - Database connection files
- **HIGH RISK**:
  - Files with `database`, `db`, `sql`, `query`, `api`, `endpoint`, `route`, `controller`, `admin`, `user`, `permission`, `role`, `access`, `file`, `upload`, `download`, `exec`, `command`, `shell`
  - All IaC files (Terraform, CloudFormation, K8s)
  - Docker and container configurations
- **MEDIUM RISK**:
  - Business logic files
  - Data processing files
  - All dependency manifests
- **LOW RISK**:
  - Tests (`test_*.py`, `*.test.js`, `*_spec.rb`)
  - Documentation (*.md, docs/)
  - Static assets (images, fonts, etc.)

**STEP 3: Systematic File Reading**

**CRITICAL:** Read files in parallel batches, prioritized by risk level.

1. **Read ALL CRITICAL RISK files first** (parallel batches of 15-20 files)
   - Do NOT skip any files
   - Read complete file contents (don't use offset/limit unless file is massive)
   - Example: If you have 40 critical files, read them in 2-3 parallel batches

2. **Read ALL HIGH RISK files** (parallel batches of 15-20 files)
   - Apply same approach as critical files
   - For very large files (>2000 lines), read in sections with offset/limit

3. **Read MEDIUM RISK files** (prioritize based on file names)
   - Focus on files related to discovered vulnerabilities
   - Read key business logic files completely

4. **Selectively read LOW RISK files**
   - Only if they reference high-risk functionality
   - Skip obvious test fixtures and documentation

**STEP 4: Line-by-Line Security Inspection**

For each file read:

1. **Apply ALL Relevant Security Rules**
   - Cross-reference each line/section against loaded rules
   - Check for patterns from both rule directories
   - Don't assume a rule doesn't apply - verify

2. **Analyze Code Context**
   - Understand surrounding lines, function purpose, data flow
   - Identify the "why" behind each code section
   - Note dependencies and imports

3. **Track Data Flows**
   - Trace user input from entry points (request parameters, form data, headers)
   - Follow data through validation, processing, storage
   - Identify where untrusted data reaches sensitive operations

**STEP 5: Contextual Analysis**

1. **Trust Boundaries**
   - Identify where untrusted data enters (API endpoints, user input, file uploads)
   - Verify validation and sanitization at boundaries
   - Check if validated data can be contaminated downstream

2. **Authentication & Authorization Checkpoints**
   - Map all authentication mechanisms
   - Verify authorization checks on sensitive operations
   - Check for bypass opportunities

3. **Sensitive Data Handling**
   - Track PII, credentials, financial data, health data
   - Verify encryption in transit and at rest
   - Check access controls and audit logging

**FILE READING METRICS TO TRACK:**

- Total files discovered: `___`
- Binary/non-text files excluded: `___`
- Analyzable text files: `___`
- Critical risk files: `___`
- High risk files: `___`
- Medium risk files: `___`
- Low risk files: `___`
- Files actually read: `___`
- Files skipped (with justification): `___`

**Common Exclusions (Binary/Non-Analyzable):**

- Compiled code (\*.pyc, \*.so, \*.dll, \*.exe)
- Archives (\*.jar, \*.zip, \*.tar.gz)
- Images/Media (\*.png, \*.jpg, \*.pdf)
- Dependency directories (node_modules/, venv/, \_\_pycache\_\_/)
- Version control (.git/)

**COMPLETENESS CHECK:** Before proceeding to report generation, confirm you have read AT LEAST:

- 100% of critical risk files
- 100% of high risk files
- 80%+ of medium risk files
- All dependency manifests
- All configuration files

---

## **5. Priority Vulnerability Categories**

Focus security analysis on these high-impact vulnerability classes (ordered by criticality):

### **5.1. Injection Flaws**

**Priority:** CRITICAL
**Types:** SQL injection, NoSQL injection, LDAP injection, OS command injection, code injection, XML injection, template injection

**Detection Criteria:**

- Unsanitized user input used in database queries
- Dynamic SQL/NoSQL query construction with string concatenation
- User input passed to `eval()`, `exec()`, `os.system()`, or similar functions
- Shell commands constructed with user-supplied data
- Template rendering with unescaped user content

**Example Patterns:**

```python
# SQL Injection - VULNERABLE
query = "SELECT * FROM users WHERE id = " + user_id  # BAD
cursor.execute(query)

# Command Injection - VULNERABLE
os.system("ping " + user_input)  # BAD

# Code Injection - VULNERABLE
eval(user_input)  # BAD
```

### **5.2. Authentication & Authorization**

**Priority:** CRITICAL
**Types:** Broken authentication, broken access control, session management issues, privilege escalation

**Detection Criteria:**

- Missing authentication checks on sensitive endpoints
- Hardcoded credentials or API keys
- Weak password policies or storage
- Insecure session management (no expiration, predictable tokens)
- Missing authorization checks (IDOR vulnerabilities)
- Role-based access control (RBAC) bypass opportunities
- JWT tokens without signature verification

**Example Patterns:**

```python
# Missing Authorization - VULNERABLE
@app.route('/admin/delete_user/<user_id>')
def delete_user(user_id):
    # No check if current user is admin!
    User.delete(user_id)  # BAD

# Hardcoded Credentials - VULNERABLE
DB_PASSWORD = "mySecretP@ssw0rd123"  # BAD
```

### **5.3. Hardcoded Secrets & Credentials**

**Priority:** CRITICAL
**Types:** API keys, passwords, tokens, private keys, connection strings, certificates

**Detection Criteria:**

- Variable names containing: `password`, `secret`, `key`, `token`, `auth`
- Strings matching known secret formats (AWS keys starting with `AKIA`, GitHub tokens `ghp_`)
- Private key blocks (`-----BEGIN PRIVATE KEY-----`)
- Connection strings with embedded credentials
- Long random-looking strings in authentication code
- Base64-encoded strings near authentication logic

**Example Patterns:**

```python
# Hardcoded API Key - VULNERABLE
API_KEY = "AIzaSyD8j3KJ8jf83jfJFK8j3fj3jf"  # BAD
AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"  # BAD

# Hardcoded Database Password - VULNERABLE
conn = psycopg2.connect("postgresql://admin:password123@localhost/db")  # BAD
```

### **5.4. Cryptographic Misuse**

**Priority:** CRITICAL
**Types:** Weak algorithms, insecure random number generation, improper key management, insecure TLS configuration

**Detection Criteria:**

- Use of broken/weak algorithms (MD5, SHA-1, DES, RC4)
- Weak encryption modes (ECB, CBC without authentication)
- Inadequate key sizes (RSA < 2048 bits)
- Predictable random number generation (`random` instead of `secrets`)
- Hardcoded encryption keys or IVs
- Missing certificate validation
- Insecure TLS versions (< TLS 1.2)

**Example Patterns:**

```python
# Weak Hashing - VULNERABLE
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()  # BAD - MD5 is broken

# Insecure Random - VULNERABLE
import random
token = random.randint(1000000, 9999999)  # BAD - predictable

# Weak Algorithm - VULNERABLE
cipher = DES.new(key, DES.MODE_ECB)  # BAD - DES is broken
```

### **5.5. Server-Side Request Forgery (SSRF)**

**Priority:** HIGH
**Types:** Internal network access, cloud metadata access, port scanning

**Detection Criteria:**

- User-controlled URLs passed to HTTP libraries
- Insufficient URL validation or allowlist
- Access to internal IP ranges or cloud metadata endpoints
- DNS rebinding vulnerabilities
- Missing protocol restrictions (allow `file://`, `gopher://`)

**Example Patterns:**

```python
# SSRF - VULNERABLE
import requests
url = request.args.get('url')
response = requests.get(url)  # BAD - no validation
```

### **5.6. Path Traversal & Directory Enumeration**

**Priority:** HIGH
**Types:** File system access, arbitrary file read/write, directory listing

**Detection Criteria:**

- User input used in file paths without validation
- Missing path normalization (allowing `../`)
- Inadequate allowlist of accessible files/directories
- Symbolic link following vulnerabilities
- Direct file serving without access control

**Example Patterns:**

```python
# Path Traversal - VULNERABLE
filename = request.args.get('file')
with open('/var/www/uploads/' + filename) as f:  # BAD - allows ../../../etc/passwd
    content = f.read()
```

### **5.7. Remote Code Execution (RCE)**

**Priority:** CRITICAL
**Types:** Unsafe deserialization, template injection, command injection, arbitrary code execution

**Detection Criteria:**

- Deserialization of untrusted data (`pickle`, `yaml.load`)
- Dynamic code evaluation (`eval`, `exec`, `compile`)
- Server-side template injection
- Unsafe reflection or dynamic imports
- Binary execution with user-controlled input

**Example Patterns:**

```python
# Unsafe Deserialization - VULNERABLE
import pickle
user_data = pickle.loads(request.data)  # BAD - RCE via __reduce__

# Template Injection - VULNERABLE
from jinja2 import Template
template = Template(user_input)  # BAD - SSTI
```

### **5.8. Cross-Site Scripting (XSS) & CSRF**

**Priority:** HIGH
**Types:** Reflected XSS, stored XSS, DOM XSS, CSRF, clickjacking

**Detection Criteria:**

- User input rendered in HTML without escaping
- Missing Content Security Policy (CSP)
- Lack of CSRF tokens on state-changing operations
- Unsafe JavaScript `eval()` or `innerHTML` usage
- Missing `X-Frame-Options` or `SameSite` cookie attributes

**Example Patterns:**

```python
# XSS - VULNERABLE (Flask)
@app.route('/search')
def search():
    query = request.args.get('q')
    return f"<h1>Results for: {query}</h1>"  # BAD - unescaped

# CSRF - VULNERABLE
@app.route('/transfer', methods=['POST'])
def transfer():
    # No CSRF token validation!
    amount = request.form.get('amount')
    transfer_money(amount)  # BAD
```

### **5.9. Unsafe Deserialization**

**Priority:** HIGH
**Types:** Object injection, arbitrary code execution via deserialization

**Detection Criteria:**

- Use of `pickle`, `yaml.load()`, `marshal`, `eval()` on untrusted data
- Java deserialization with `ObjectInputStream`
- .NET `BinaryFormatter` or `SoapFormatter`
- Missing integrity checks on serialized data

### **5.10. Insecure Defaults & Configurations**

**Priority:** MEDIUM
**Types:** Debug mode in production, overly permissive CORS, weak security headers, exposed admin interfaces

**Detection Criteria:**

- `DEBUG = True` in production code
- Overly permissive CORS (`Access-Control-Allow-Origin: *`)
- Missing security headers (HSTS, CSP, X-Content-Type-Options)
- Default credentials not changed
- Unnecessary services or endpoints enabled

**Example Patterns:**

```python
# Debug Mode - VULNERABLE
app = Flask(__name__)
app.config['DEBUG'] = True  # BAD in production

# Permissive CORS - VULNERABLE
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')  # BAD
    return response
```

### **5.11. Supply Chain Vulnerabilities**

**Priority:** MEDIUM to HIGH
**Types:** Outdated dependencies, known CVEs, dependency confusion, malicious packages

**Detection Criteria:**

- Dependencies with known security vulnerabilities
- Unmaintained or deprecated packages
- Packages without version pinning
- Dependencies from untrusted sources
- Transitive dependencies with vulnerabilities

---

## **6. Validation & Analysis Criteria**

For each potential security issue identified, the AI agent should:

### **6.1. Confirm True Positive**

A finding is a **TRUE POSITIVE** if:

- The vulnerability pattern matches security rule criteria
- The code path is reachable and exploitable
- User input or untrusted data flows to the vulnerable operation
- No compensating controls exist (validation, sanitization, WAF)
- The finding appears in production code (not tests or examples)

### **6.2. Identify False Positives**

A finding is a **FALSE POSITIVE** if:

- The code is in test files, examples, or documentation
- Input is validated/sanitized before reaching the operation
- The code path is unreachable or behind authentication
- Framework-level protections automatically prevent exploitation
- The pattern is used safely in context (e.g., static SQL with no user input)

### **6.3. Assess Severity**

Assign severity based on:

- **CRITICAL**: Direct RCE, authentication bypass, hardcoded production secrets
- **HIGH**: SQL injection, SSRF, path traversal, XSS, authorization bypass
- **MEDIUM**: Information disclosure, weak crypto, missing security headers
- **LOW**: Security best practice violations, minor configuration issues
- **INFO**: Recommendations, defensive improvements, code quality

---

## **7. Report Structure**

Generate a comprehensive markdown report with the following sections:

### **7.1. Executive Summary**

- Total number of findings by severity (Critical, High, Medium, Low, Info)
- Top 5 most critical issues requiring immediate attention
- Overall security posture assessment
- Risk summary and business impact

### **7.2. Detailed Findings**

For each security issue discovered, provide:

| Field | Description |
|-------|-------------|
| **Issue Title** | Clear, descriptive name of the vulnerability |
| **Severity** | Critical / High / Medium / Low / Info |
| **CWE Reference** | Applicable CWE identifier (e.g., CWE-89) |
| **Rule Reference** | Specific security rule(s) from Project CodeGuard |
| **Location** | Exact file path and line range(s) |
| **Code Snippet** | Relevant vulnerable code (5-10 lines) |
| **Description** | What the vulnerability is and why it's a problem |
| **Impact** | Potential security consequences if exploited |
| **Remediation** | Specific, actionable fix with secure code example |
| **References** | Links to OWASP, CWE, or authoritative guidance |

**Example Finding Format:**

#### Finding #1: SQL Injection in User Query Function

**Severity:** CRITICAL
**CWE:** CWE-89 (SQL Injection)
**Rule Reference:** `codeguard-0-input-validation-injection.md`

**Location:** `app/database/queries.py`, lines 45-47

**Code Snippet:**

```python
def get_user_by_id(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()
```

**Description:**
The function constructs a SQL query using string concatenation with user-supplied input (`user_id`) without parameterization or validation. This allows attackers to inject arbitrary SQL commands.

**Impact:**
An attacker can:

- Extract sensitive data from any database table
- Modify or delete database records
- Bypass authentication
- Execute administrative operations
- Potentially gain OS-level access via SQL extensions

**Remediation:**
Use parameterized queries (prepared statements) instead of string concatenation:

```python
def get_user_by_id(user_id):
    query = "SELECT * FROM users WHERE id = %s"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()
```

**References:**

- OWASP SQL Injection: <https://owasp.org/www-community/attacks/SQL_Injection>
- CWE-89: <https://cwe.mitre.org/data/definitions/89.html>

### **7.3. Findings by Category**

Group all findings by vulnerability type:

- Injection Flaws
- Authentication & Authorization
- Hardcoded Secrets & Credentials
- Cryptographic Misuse
- Server-Side Request Forgery (SSRF)
- Path Traversal & Directory Enumeration
- Remote Code Execution (RCE)
- Cross-Site Scripting (XSS) & CSRF
- Unsafe Deserialization
- Insecure Defaults & Configurations
- Supply Chain Vulnerabilities

### **7.4. Recommendations**

Provide actionable guidance organized by timeframe:

#### Immediate Actions Required (fix within 48 hours)

- Critical vulnerabilities requiring emergency patches
- Exposed production secrets that must be rotated
- Active exploitation vectors

#### Short-Term Improvements (1-3 months)

- High and medium severity fixes
- Security control implementation
- Code refactoring for security

#### Long-Term Security Enhancements

- Architecture improvements
- Security framework adoption
- Process and training improvements

#### Suggested Security Tooling & Processes

- SAST/DAST tools
- Dependency scanning automation
- Security testing in CI/CD
- Security training and awareness

### **7.5. Appendix**

#### Files Reviewed

- Total file count
- List of high-risk files analyzed
- Technology stack summary

#### Rules Applied

- List of security rules used from each Project CodeGuard directory:
  - Core rules (`sources/core/`)
  - OWASP rules (`sources/owasp/`)
- Coverage assessment by rule category
- Rules requiring updates or additions
- Technology-specific rules that were most relevant

#### Methodology Notes

- Review approach and scope
- Limitations or caveats
- Assumptions made during analysis

---

## **8. Code Analysis Best Practices**

### **8.1. Data Flow Analysis**

- Trace user input from entry points (HTTP requests, file uploads, API calls) to sensitive operations
- Identify trust boundaries where validation/sanitization should occur
- Map authentication/authorization checkpoints

### **8.2. Context-Aware Analysis**

- Understand the business logic and intended behavior
- Consider framework-level protections (e.g., Django's automatic SQL parameterization)
- Recognize compensating controls (WAF, input validation, rate limiting)

### **8.3. False Positive Reduction**

- Verify code paths are reachable and exploitable
- Check for validation/sanitization before vulnerable operations
- Distinguish between test code and production code
- Recognize safe usage patterns within context

### **8.4. Comprehensive Coverage**

- Don't skip files based on name alone
- Review configuration files and IaC templates
- Analyze build and deployment scripts
- Check dependency manifests for vulnerable packages

---

## **9. Output & Deliverables**

### **9.1. Primary Deliverable**

- Comprehensive security review report in markdown format
- Named with timestamp: `sec_review_<repo-name>_<YYYY-MM-DD_HH-mm-ss>.md`
- Saved to designated report directory

### **9.2. Supplementary Outputs**

- Machine-readable findings (JSON/SARIF format for tool integration)
- Severity metrics and statistics
- Remediation priority queue

### **9.3. Quality Standards**

- All findings must be verified and actionable
- Code snippets must show actual vulnerable code
- Remediation examples must be secure and tested
- References must be authoritative and current

---

## **10. Security & Compliance Notes**

- **Never log or expose actual secret values** discovered during review
- **Handle sensitive code snippets carefully** - sanitize before including in reports
- **Respect access controls** - only review code within authorized scope
- **Maintain confidentiality** - security findings are sensitive information
- **Follow responsible disclosure** - critical findings should be escalated appropriately
- **Document assumptions** - note any limitations in the analysis

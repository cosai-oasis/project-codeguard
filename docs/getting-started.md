# Getting Started

Get up and running with Project CodeGuard in just a few steps.

## Project CodeGuard Introduction Video
[This video](https://www.youtube.com/watch?v=O03MDxUWjsE) introduces Project CodeGuard and includes several demos on how to use it during code generation and code review with Claude Code, Codex, and other coding agents.

<div style="position: relative; width: 100%; padding-bottom: 56.25%; margin: 2em 0; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.2);">
  <iframe style="position: absolute; top: 0; left: 0; width: 100%; height: 100%;" src="https://www.youtube.com/embed/O03MDxUWjsE" title="Project CodeGuard Introduction Video and Demos" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowfullscreen></iframe>
</div>

## Prerequisites

Before you begin, familiarize yourself with how rules work in your AI coding tool:

=== "Cursor"

    Cursor uses `.cursor/rules` for rule configuration.
    
    :material-book-open-page-variant: [Cursor Rules Documentation](https://docs.cursor.com/en/context/rules)

=== "Windsurf"

    Windsurf uses `.windsurf/rules` for rule configuration.
    
    :material-book-open-page-variant: [Windsurf Rules Documentation](https://docs.windsurf.com/windsurf/cascade/memories#rules)

=== "GitHub Copilot"

    GitHub Copilot uses `.github/instructions` for rule configuration.
    
    :material-book-open-page-variant: [GitHub Copilot Instructions](https://docs.github.com/en/copilot/how-tos/configure-custom-instructions/add-repository-instructions)

=== "Antigravity"
    Antigravity uses `.agent/rules` for rule configuration.

    :material-book-open-page-variant: [Antigravity Instructions](https://codelabs.developers.google.com/getting-started-google-antigravity#8)

=== "OpenCode"
    OpenCode uses `.opencode/skills` for skill configuration.

    :material-book-open-page-variant: [OpenCode Skills Documentation](https://opencode.ai/docs/skills/)

## Installation

### Option 1: Install Pre-built Rules (Recommended)

Select your AI coding tool and follow the instructions:

=== "Cursor"

    1. **Download** [`ide-rules-cursor.zip`](https://github.com/cosai-oasis/project-codeguard/releases) from the Releases page
    2. **Extract** the ZIP file
    3. **Copy** the `.cursor/` directory to your project root:

        ```bash
        cp -r .cursor/ /path/to/your/project/
        ```

    4. **Restart** Cursor to load the rules

=== "Windsurf"

    1. **Download** [`ide-rules-windsurf.zip`](https://github.com/cosai-oasis/project-codeguard/releases) from the Releases page
    2. **Extract** the ZIP file
    3. **Copy** the `.windsurf/` directory to your project root:

        ```bash
        cp -r .windsurf/ /path/to/your/project/
        ```

    4. **Restart** Windsurf to load the rules

=== "GitHub Copilot"

    1. **Download** [`ide-rules-copilot.zip`](https://github.com/cosai-oasis/project-codeguard/releases) from the Releases page
    2. **Extract** the ZIP file
    3. **Copy** the `.github/` directory to your project root:

        ```bash
        cp -r .github/ /path/to/your/project/
        ```

    4. **Restart** your IDE to load the instructions

=== "Antigravity"

    1. **Download** [`ide-rules-antigravity.zip`](https://github.com/cosai-oasis/project-codeguard/releases) from the Releases page
    2. **Extract** the ZIP file
    3. **Copy** the `.agent/` directory to your project root:

        ```bash
        cp -r .agent/ /path/to/your/project/
        ```

    4. **Restart** Antigravity to load the rules

=== "OpenCode"

    **Option A: Skills (recommended)**

    Using skills is more context-efficient as only relevant rules are loaded per session based on the files you're working with.

    1. **Download** [`ide-rules-opencode.zip`](https://github.com/cosai-oasis/project-codeguard/releases) from the Releases page
    2. **Extract** the ZIP file
    3. **Copy** the `.opencode/` directory to your project root:

        ```bash
        cp -r .opencode/ /path/to/your/project/
        ```

    4. **Restart** OpenCode to load the skill

    **Option B: Remote Instructions (zero-maintenance)**

    All rules loaded every session, but always up to date: no local files to maintain.

    Create an [`opencode.json`](https://opencode.ai/docs/rules/#custom-instructions) in your project root:

    ??? example "opencode.json with remote URLs"

        ```json
        {
          "$schema": "https://opencode.ai/config.json",
          "instructions": [
            "https://raw.githubusercontent.com/cosai-oasis/project-codeguard/main/sources/core/codeguard-0-additional-cryptography.md",
            "https://raw.githubusercontent.com/cosai-oasis/project-codeguard/main/sources/core/codeguard-0-api-web-services.md",
            "https://raw.githubusercontent.com/cosai-oasis/project-codeguard/main/sources/core/codeguard-0-authentication-mfa.md",
            "https://raw.githubusercontent.com/cosai-oasis/project-codeguard/main/sources/core/codeguard-0-authorization-access-control.md",
            "https://raw.githubusercontent.com/cosai-oasis/project-codeguard/main/sources/core/codeguard-0-client-side-web-security.md",
            "https://raw.githubusercontent.com/cosai-oasis/project-codeguard/main/sources/core/codeguard-0-cloud-orchestration-kubernetes.md",
            "https://raw.githubusercontent.com/cosai-oasis/project-codeguard/main/sources/core/codeguard-0-data-storage.md",
            "https://raw.githubusercontent.com/cosai-oasis/project-codeguard/main/sources/core/codeguard-0-devops-ci-cd-containers.md",
            "https://raw.githubusercontent.com/cosai-oasis/project-codeguard/main/sources/core/codeguard-0-file-handling-and-uploads.md",
            "https://raw.githubusercontent.com/cosai-oasis/project-codeguard/main/sources/core/codeguard-0-framework-and-languages.md",
            "https://raw.githubusercontent.com/cosai-oasis/project-codeguard/main/sources/core/codeguard-0-iac-security.md",
            "https://raw.githubusercontent.com/cosai-oasis/project-codeguard/main/sources/core/codeguard-0-input-validation-injection.md",
            "https://raw.githubusercontent.com/cosai-oasis/project-codeguard/main/sources/core/codeguard-0-logging.md",
            "https://raw.githubusercontent.com/cosai-oasis/project-codeguard/main/sources/core/codeguard-0-mcp-security.md",
            "https://raw.githubusercontent.com/cosai-oasis/project-codeguard/main/sources/core/codeguard-0-mobile-apps.md",
            "https://raw.githubusercontent.com/cosai-oasis/project-codeguard/main/sources/core/codeguard-0-privacy-data-protection.md",
            "https://raw.githubusercontent.com/cosai-oasis/project-codeguard/main/sources/core/codeguard-0-safe-c-functions.md",
            "https://raw.githubusercontent.com/cosai-oasis/project-codeguard/main/sources/core/codeguard-0-session-management-and-cookies.md",
            "https://raw.githubusercontent.com/cosai-oasis/project-codeguard/main/sources/core/codeguard-0-supply-chain-security.md",
            "https://raw.githubusercontent.com/cosai-oasis/project-codeguard/main/sources/core/codeguard-0-xml-and-serialization.md",
            "https://raw.githubusercontent.com/cosai-oasis/project-codeguard/main/sources/core/codeguard-1-crypto-algorithms.md",
            "https://raw.githubusercontent.com/cosai-oasis/project-codeguard/main/sources/core/codeguard-1-digital-certificates.md",
            "https://raw.githubusercontent.com/cosai-oasis/project-codeguard/main/sources/core/codeguard-1-hardcoded-credentials.md"
          ]
        }
        ```

    !!! info "Tradeoff"
        The skills approach (Option A) uses glob-scoped rules so only relevant rules are loaded based on the files you're editing. Remote instructions load all 23 rules into every session regardless of language. Remote URLs point to the `main` branch -- pin to a release tag (e.g. `refs/tags/v1.3.0`) if you need a stable, auditable snapshot.

=== "Claude Code"

    Claude Code uses a plugin system instead of manual file installation:

    1. **Add** the Project CodeGuard marketplace:

        ```bash
        /plugin marketplace add cosai-oasis/project-codeguard
        ```

    2. **Install** the security plugin:

        ```bash
        /plugin install codeguard-security@project-codeguard
        ```

    The plugin automatically loads and applies security rules. See the [Claude Code Plugin documentation](claude-code-skill-plugin.md) for details.

=== "Codex"

    OpenAI Codex uses [agent skills](https://agentskills.io/) for task-specific instructions.

    !!! warning "Prerequisites"
        Make sure you're running the latest version of Codex before installing skills.

    **Option A: Skill installer**

    ```
    $skill-installer install from https://github.com/cosai-oasis/project-codeguard/tree/main/skills/software-security
    ```

    **Option B: Manual clone**

    ```bash
    mkdir -p .codex/skills
    cd .codex/skills
    git clone https://github.com/cosai-oasis/project-codeguard.git temp
    mv temp/skills/software-security ./
    rm -rf temp
    ```

    Once installed, invoke the skill with `$software-security` or let Codex use it automatically when writing or reviewing code.

    !!! info "Codex Skills Documentation"
        For more information, see the [OpenAI Codex Skills documentation](https://developers.openai.com/codex/skills/).

**Using multiple tools?** Download [`ide-rules-all.zip`](https://github.com/cosai-oasis/project-codeguard/releases) for all formats in one archive.

!!! tip "Repository Level Installation"
    Installing at the repository level ensures all team members benefit from the security rules automatically when they clone the repository.

!!! note "Hidden Files on macOS/Linux"
    On macOS/Linux, you may need to show hidden files:
    
    - **macOS Finder**: Press ++cmd+shift+period++ to toggle visibility
    - **Linux**: Use `ls -la` in terminal or enable "Show Hidden Files" in your file manager

### Option 2: Build from Source

If you want to customize or contribute to the rules:

```bash
# Clone the repository
git clone https://github.com/cosai-oasis/project-codeguard.git
cd rules

# Install dependencies (requires Python 3.11+)
uv sync

# Validate rules
uv run python src/validate_unified_rules.py sources/

# Convert rules (default: core rules only)
uv run python src/convert_to_ide_formats.py

# Or include all rules (core + owasp supplementary)
uv run python src/convert_to_ide_formats.py --source core owasp

# Copy the generated rules to your project
cp -r dist/.cursor/ /path/to/your/project/
cp -r dist/.windsurf/ /path/to/your/project/
cp -r dist/.github/ /path/to/your/project/
cp -r dist/.agent/ /path/to/your/project/
cp -r dist/.opencode/ /path/to/your/project/
```

## Core vs OWASP Sources

Project CodeGuard has two source rule sets:

- `sources/core/`: Official Project CodeGuard rules. These are the main rules packaged in releases and enabled by default.
- `sources/owasp/`: Supplementary rules originally derived from OWASP guidance. These are optional and are not enabled by default.

Use OWASP supplementary rules when you explicitly want broader coverage, such as deeper security reviews or reference-driven review workflows.

## Rule Types: Always-On vs Glob-Scoped

Project CodeGuard supports two rule activation types:

- **Always-on rules**: Apply to all files in the project. These rules are for baseline safeguards that should always be in context.
- **Glob-scoped rules**: Apply only to matching file patterns (derived from `languages` in source frontmatter). These rules are for language- or framework-specific guidance.

## Keeping Rules Updated (Automated)

For GitHub repositories, you can automate rule updates with a workflow that runs monthly and creates PRs when new versions are available.

### Supported Formats

- Cursor (`.cursor/rules/`)
- Windsurf (`.windsurf/rules/`)
- GitHub Copilot (`.github/instructions/`)
- Antigravity (`.agent/rules/`)
- OpenCode (`.opencode/skills/software-security/rules/`)

### Setup

1. Download [`update-codeguard-rules.yml`](https://raw.githubusercontent.com/cosai-oasis/project-codeguard/main/.github/workflows/update-codeguard-rules.yml)
2. Save to `.github/workflows/update-codeguard-rules.yml` in your repository
3. Commit and push

The workflow runs monthly (1st at 9:00 UTC) and can also be triggered manually from the **Actions** tab.

## Verify Installation

After installation, your project structure should include:

```
your-project/
├── .agent/
│   └── rules/
├── .cursor/
│   └── rules/
├── .github/
│   └── instructions/
├── .opencode/
│   └── skills/
│       └── software-security/
├── .windsurf/
│   └── rules/
└── ... (your project files)
```

## What's Included

The security rules cover essential areas:

### Core Security Rules

- **🔐 Cryptography**: Safe algorithms, secure key management, TLS configuration
- **🛡️ Input Validation**: SQL injection, XSS prevention, command injection defense
- **🔑 Authentication**: MFA, OAuth/OIDC, password security, session management
- **⚡ Authorization**: RBAC/ABAC, access control, privilege escalation prevention

### Platform-Specific Rules

- **📱 Mobile Apps**: iOS/Android security, secure storage, transport security
- **🌐 API Security**: REST/GraphQL/SOAP security, rate limiting, SSRF prevention
- **☁️ Cloud & Containers**: Docker/Kubernetes hardening, IaC security
- **🗄️ Data Storage**: Database security, encryption, backup protection

### DevOps & Supply Chain

- **📦 Dependencies**: Supply chain security, SBOM, vulnerability management
- **🔄 CI/CD**: Pipeline security, artifact signing, secrets management
- **📝 Logging**: Secure logging, monitoring, privacy-aware telemetry

## Testing the Integration

To verify the rules are working:

1. **Open your IDE** with the Project CodeGuard rules installed
2. **Start a new file** in a supported language (Python, JavaScript, Java, C/C++, etc.)
3. **Ask your AI assistant** to generate code that might have security implications:
   - "Create a function to hash a password"
   - "Write code to connect to a database"
   - "Generate an API endpoint with authentication"

4. **Observe the output** - The AI should automatically apply security best practices:
   - Using strong cryptographic algorithms (bcrypt/Argon2 for passwords)
   - Parameterized queries to prevent SQL injection
   - Proper authentication/authorization checks

## Next Steps

- **Review Rules**: Explore the security rules in your IDE's rules directory
- **Test Integration**: Generate some code and see the security guidance in action
- **Share Feedback**: Help us improve by [opening an issue](https://github.com/cosai-oasis/project-codeguard/issues)
- **Contribute**: See [CONTRIBUTING.md](https://github.com/cosai-oasis/project-codeguard/blob/main/CONTRIBUTING.md) to contribute new rules or improvements

!!! success "You're Ready!"
    Project CodeGuard is now protecting your development workflow. The security rules will automatically guide AI assistants to generate more secure code.

## Troubleshooting

### Rules Not Working

If the AI assistant doesn't seem to follow the rules:

1. **Restart your IDE** to ensure rules are loaded
2. **Check file location** - Ensure rules are in the correct directory for your IDE
3. **Verify file format** - Rules should be markdown files
4. **Test with explicit request** - Ask the AI directly: "Follow the security rules when generating this code"

### Performance Impact

The rules have minimal performance impact, but if you experience issues:

- **Reduce rule count**: Start with core rules (cryptography, input validation, authentication)
- **Combine rules**: Merge related rules into fewer files
- **Report issues**: Let us know via [GitHub Issues](https://github.com/cosai-oasis/project-codeguard/issues)

## Getting Help

- **Documentation**: You're reading it! Check the [FAQ](faq.md) for common questions
- **GitHub Issues**: [Report bugs or ask questions](https://github.com/cosai-oasis/project-codeguard/issues)
- **Discussions**: [Join the community discussion](https://github.com/cosai-oasis/project-codeguard/discussions)


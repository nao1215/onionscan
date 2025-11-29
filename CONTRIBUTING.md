# Contributing Guide

## Introduction

Thank you for considering contributing to OnionScan! This document explains how to contribute to the project. We welcome all forms of contributions, including code contributions, documentation improvements, bug reports, and feature suggestions.

## Setting Up Development Environment

### Prerequisites

#### Installing Go

OnionScan development requires Go 1.24 or later.

**macOS (using Homebrew)**
```bash
brew install go
```

**Linux (for Ubuntu)**
```bash
# Using snap
sudo snap install go --classic

# Or download from official site
wget https://go.dev/dl/go1.24.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.24.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.profile
source ~/.profile
```

**Windows**
Download and run the installer from the [official Go website](https://go.dev/dl/).

Verify installation:
```bash
go version
```

#### Installing Tor

OnionScan requires Tor to be installed on your system.

**Ubuntu/Debian**
```bash
sudo apt update && sudo apt install tor
```

**Fedora/RHEL**
```bash
sudo dnf install tor
```

**Arch Linux**
```bash
sudo pacman -S tor
```

**macOS (Homebrew)**
```bash
brew install tor
```

**Windows (Chocolatey)**
```bash
choco install tor
```

### Cloning the Project

```bash
git clone https://github.com/nao1215/onionscan.git
cd onionscan
```

### Verification

To verify that your development environment is set up correctly, run the following commands:

```bash
# Run tests
make test

# Run linter
make lint

# Build the project
make build
```

## Development Workflow

### Branch Strategy

- `main` branch is the latest stable version
- Create new branches from `main` for new features or bug fixes
- Branch naming examples:
  - `feature/add-new-analyzer` - New feature
  - `fix/issue-123` - Bug fix
  - `docs/update-readme` - Documentation update

### Coding Standards

This project follows these standards:

1. **Conform to [Effective Go](https://go.dev/doc/effective_go)**
2. **Avoid using global variables** (except for config package)
3. **Always add comments to public functions, variables, and structs**
4. **Keep functions as small as possible**
5. **Writing tests is encouraged**

### Writing Tests

Tests are important. Please follow these guidelines:

1. **Unit tests**: Aim for 80% or higher coverage
2. **Test readability**: Write clear test cases
3. **Parallel execution**: Use `t.Parallel()` whenever possible

Test example:
```go
func TestAnalyzer_Analyze(t *testing.T) {
    t.Parallel()

    t.Run("should detect email addresses", func(t *testing.T) {
        t.Parallel()

        analyzer := NewEmailAnalyzer()
        data := &AnalysisData{
            Pages: []PageData{
                {Content: "Contact: test@example.com"},
            },
        }

        findings, err := analyzer.Analyze(context.Background(), data)
        assert.NoError(t, err)
        assert.Len(t, findings, 1)
    })
}
```

## Using AI Assistants (LLMs)

We actively encourage the use of AI coding assistants to improve productivity and code quality. Tools like Claude Code, GitHub Copilot, and Cursor are welcome for:

- Writing boilerplate code
- Generating comprehensive test cases
- Improving documentation
- Refactoring existing code
- Finding potential bugs
- Suggesting performance optimizations

### Guidelines for AI-Assisted Development

1. **Review all generated code**: Always review and understand AI-generated code before committing
2. **Maintain consistency**: Ensure AI-generated code follows our coding standards
3. **Test thoroughly**: AI-generated code must pass all tests and linting (`make test` and `make lint`)

## Creating Pull Requests

### Preparation

1. **Check or Create Issues**
   - Check if there are existing issues
   - For major changes, we recommend discussing the approach in an issue first

2. **Write Tests**
   - Always add tests for new features
   - For bug fixes, create tests that reproduce the bug
   - AI tools can help generate comprehensive test cases

3. **Quality Check**
   ```bash
   # Ensure all tests pass
   make test

   # Linter check
   make lint

   # Check coverage (80% or higher)
   go test -cover ./...
   ```

### Submitting Pull Request

1. Create a Pull Request from your forked repository to the main repository
2. PR title should briefly describe the changes
3. Include the following in PR description:
   - Purpose and content of changes
   - Related issue number (if any)
   - Test method
   - Reproduction steps for bug fixes

### About CI/CD

GitHub Actions automatically checks the following items:

- **Cross-platform testing**: Test execution on Linux, macOS, and Windows
- **Linter check**: Static analysis with golangci-lint
- **Test coverage**: Maintain coverage metrics
- **Build verification**: Successful builds on each platform

Merging is not possible unless all checks pass.

## Bug Reports

When you find a bug, please create an issue with the following information:

1. **Environment Information**
   - OS (Linux/macOS/Windows) and version
   - Go version
   - OnionScan version
   - Tor version

2. **Reproduction Steps**
   - Minimal command or code example to reproduce the bug
   - Target .onion address (if applicable and safe to share)

3. **Expected and Actual Behavior**

4. **Error Messages or Stack Traces** (if any)

## Contributing Outside of Coding

The following activities are also greatly welcomed:

### Activities that Boost Motivation

- **Give a GitHub Star**: Show your interest in the project
- **Promote the Project**: Introduce it in blogs, social media, study groups, etc.
- **Become a GitHub Sponsor**: Support available at [https://github.com/sponsors/nao1215](https://github.com/sponsors/nao1215)

### Other Ways to Contribute

- **Documentation Improvements**: Fix typos, improve clarity of explanations
- **Add Examples**: Provide practical sample configurations
- **Feature Suggestions**: Share new analyzer ideas or feature requests in issues
- **Security Research**: Report security issues responsibly

## Security Considerations

When contributing to OnionScan, please keep in mind:

1. **Responsible Disclosure**: If you find security vulnerabilities, please report them privately
2. **Legal Compliance**: Ensure any test cases or examples don't target real services without authorization
3. **Privacy**: Don't include real .onion addresses or sensitive data in commits

## License

Contributions to this project are considered to be released under the project's license (MIT License).

---

Thank you again for considering contributing! We sincerely look forward to your participation.

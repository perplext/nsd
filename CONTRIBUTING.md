# Contributing to NSD

Thank you for your interest in contributing to NSD (Network Sniffing Dashboard)! This document provides guidelines and information for contributors.

## Table of Contents

1. [Code of Conduct](#code-of-conduct)
2. [Getting Started](#getting-started)
3. [Development Setup](#development-setup)
4. [Contributing Process](#contributing-process)
5. [Code Guidelines](#code-guidelines)
6. [Testing](#testing)
7. [Documentation](#documentation)
8. [Pull Request Process](#pull-request-process)
9. [Release Process](#release-process)
10. [Community and Support](#community-and-support)

## Code of Conduct

This project and everyone participating in it is governed by our [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

## Getting Started

### Ways to Contribute

There are many ways to contribute to NSD:

- **Bug Reports**: Report bugs using our [bug report template](.github/ISSUE_TEMPLATE/bug_report.yml)
- **Feature Requests**: Suggest new features using our [feature request template](.github/ISSUE_TEMPLATE/feature_request.yml)
- **Code Contributions**: Submit pull requests for bug fixes or new features
- **Documentation**: Improve documentation, guides, and examples
- **Testing**: Help test new features and report issues
- **Plugins**: Develop and share plugins for NSD
- **Translations**: Add or improve translations for internationalization
- **Community Support**: Help other users in discussions and issues

### First Time Contributors

If you're new to contributing to open source projects:

1. Look for issues labeled `good first issue` or `help wanted`
2. Start with documentation improvements or small bug fixes
3. Join our community discussions to get familiar with the project
4. Don't hesitate to ask questions!

## Development Setup

### Prerequisites

- **Go**: Version 1.19 or later
- **Git**: For version control
- **libpcap**: For packet capture functionality
  - Linux: `sudo apt-get install libpcap-dev` (Debian/Ubuntu) or `sudo yum install libpcap-devel` (CentOS/RHEL)
  - macOS: `brew install libpcap`
  - Windows: WinPcap or Npcap development libraries

### Setting Up Your Development Environment

1. **Fork the repository** on GitHub

2. **Clone your fork**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/nsd.git
   cd nsd
   ```

3. **Add the upstream repository**:
   ```bash
   git remote add upstream https://github.com/perplext/nsd.git
   ```

4. **Install dependencies**:
   ```bash
   go mod download
   ```

5. **Build the project**:
   ```bash
   make build
   ```

6. **Run tests**:
   ```bash
   make test
   ```

7. **Verify installation**:
   ```bash
   ./bin/nsd --version
   ```

### Development Tools

We recommend using:

- **Editor**: VS Code with Go extension, GoLand, or Vim with vim-go
- **Linting**: golangci-lint (configured in `.golangci.yml`)
- **Formatting**: gofmt (built into Go toolchain)
- **Testing**: Go's built-in testing framework

## Contributing Process

### Before You Start

1. **Check existing issues**: Search for existing issues or discussions related to your contribution
2. **Create an issue**: For new features or significant changes, create an issue first to discuss the approach
3. **Get feedback**: Engage with maintainers and community members on your proposed changes

### Development Workflow

1. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   # or
   git checkout -b fix/issue-number-description
   ```

2. **Make your changes**:
   - Follow our [code guidelines](#code-guidelines)
   - Write tests for new functionality
   - Update documentation as needed

3. **Test your changes**:
   ```bash
   make test
   make lint
   ```

4. **Commit your changes**:
   ```bash
   git add .
   git commit -m "feat: add new visualization component"
   ```

5. **Keep your branch updated**:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

6. **Push your changes**:
   ```bash
   git push origin feature/your-feature-name
   ```

7. **Create a pull request**

## Code Guidelines

### Go Code Style

- Follow the [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- Use `gofmt` for formatting
- Use `golangci-lint` for linting
- Write clear, self-documenting code
- Add comments for exported functions and complex logic

### Commit Message Format

We use [Conventional Commits](https://www.conventionalcommits.org/) format:

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or modifying tests
- `chore`: Build process or auxiliary tool changes

**Examples:**
```
feat(ui): add new theme selector component
fix(netcap): resolve memory leak in packet processing
docs: update installation instructions for macOS
test(api): add integration tests for REST endpoints
```

### File Structure

Follow the existing project structure:

```
nsd/
├── cmd/                    # Command line applications
│   ├── nsd/               # Main NSD application
│   └── i18n-scaffold/     # Translation scaffold tool
├── pkg/                    # Reusable packages
│   ├── api/               # REST API server
│   ├── alerts/            # Alert and notification system
│   ├── netcap/            # Network capture functionality
│   ├── ui/                # Terminal UI components
│   └── ...
├── web/                   # Web dashboard files
├── docs/                  # Documentation
├── examples/              # Example configurations and plugins
└── ...
```

### Error Handling

- Use Go's idiomatic error handling
- Wrap errors with context using `fmt.Errorf`
- Log errors appropriately based on severity
- Provide meaningful error messages to users

```go
// Good
if err := doSomething(); err != nil {
    return fmt.Errorf("failed to do something: %w", err)
}

// Better
if err := doSomething(); err != nil {
    log.Errorf("Failed to process packet on interface %s: %v", interfaceName, err)
    return fmt.Errorf("packet processing failed: %w", err)
}
```

### Package Guidelines

- Keep packages focused and cohesive
- Minimize dependencies between packages
- Use interfaces to define contracts
- Avoid circular dependencies
- Export only what's necessary

## Testing

### Testing Requirements

- **Unit Tests**: Required for all new functionality
- **Integration Tests**: Required for complex features
- **Benchmark Tests**: Required for performance-critical code
- **Manual Testing**: Required for UI changes

### Running Tests

```bash
# Run all tests
make test

# Run tests with coverage
make test-coverage

# Run specific package tests
go test -v ./pkg/netcap

# Run benchmarks
go test -bench=. ./pkg/...

# Run tests with race detection
go test -race ./...
```

### Test Guidelines

- Test both success and failure cases
- Use table-driven tests for multiple scenarios
- Mock external dependencies
- Keep tests independent and deterministic
- Use descriptive test names

```go
func TestNetworkMonitor_GetStats(t *testing.T) {
    tests := []struct {
        name     string
        packets  int64
        bytes    int64
        expected map[string]interface{}
    }{
        {
            name:    "zero stats",
            packets: 0,
            bytes:   0,
            expected: map[string]interface{}{
                "TotalPackets": int64(0),
                "TotalBytes":   int64(0),
            },
        },
        // More test cases...
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Test implementation
        })
    }
}
```

## Documentation

### Documentation Requirements

- **Code Comments**: For exported functions and complex logic
- **README Updates**: For new features or installation changes
- **User Documentation**: For new user-facing features
- **API Documentation**: For API changes
- **Examples**: For new functionality or configuration options

### Documentation Style

- Use clear, concise language
- Include practical examples
- Keep documentation up-to-date with code changes
- Use proper Markdown formatting
- Include screenshots for UI changes

### Where to Document

- **README.md**: Basic usage and installation
- **docs/**: Detailed guides and documentation
- **Code comments**: Implementation details
- **Examples/**: Configuration and usage examples
- **CHANGELOG.md**: Release notes and changes

## Pull Request Process

### Before Submitting

1. **Rebase on latest main**:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run all checks**:
   ```bash
   make test
   make lint
   make build
   ```

3. **Update documentation** if needed

4. **Write clear commit messages**

### Pull Request Requirements

- **Clear description** of changes and motivation
- **Tests** for new functionality
- **Documentation** updates
- **No breaking changes** without discussion
- **Passes CI checks**

### Review Process

1. **Automated checks** must pass (CI, linting, tests)
2. **Code review** by at least one maintainer
3. **Testing** by reviewers if needed
4. **Documentation review** for user-facing changes
5. **Final approval** by project maintainer

### Addressing Feedback

- Respond to all review comments
- Make requested changes promptly
- Push updates to the same branch
- Re-request review after changes

## Release Process

### Versioning

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Schedule

- **Patch releases**: As needed for critical bugs
- **Minor releases**: Monthly or when significant features are ready
- **Major releases**: When breaking changes are necessary

### Release Checklist

1. Update version numbers
2. Update CHANGELOG.md
3. Run full test suite
4. Build and test packages
5. Create GitHub release
6. Update package repositories

## Community and Support

### Communication Channels

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: General questions and community discussion
- **Pull Requests**: Code review and discussion

### Getting Help

- **Documentation**: Check the [docs/](docs/) directory
- **Troubleshooting**: See [TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md)
- **FAQ**: Common questions and answers
- **Community**: Ask questions in GitHub Discussions

### Maintainer Response Times

- **Critical bugs**: 24-48 hours
- **Bug reports**: 1-3 days
- **Feature requests**: 1-7 days
- **Pull requests**: 1-7 days

## Recognition

Contributors are recognized in several ways:

- **CONTRIBUTORS.md**: Listed in the contributors file
- **Release notes**: Acknowledged in release announcements
- **GitHub**: Contribution graphs and statistics
- **Special recognition**: For significant contributions

## Legal

### Contributor License Agreement

By contributing to NSD, you agree that your contributions will be licensed under the same license as the project (MIT License).

### Copyright

- You retain copyright to your contributions
- You grant the project a perpetual, irrevocable license to use your contributions
- Ensure you have the right to contribute any code you submit

## Questions?

If you have questions about contributing:

1. Check this document and other documentation
2. Search existing issues and discussions
3. Create a new discussion or issue
4. Contact the maintainers

Thank you for contributing to NSD! 🎉
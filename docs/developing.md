# ETR Pre-commit Setup

This project uses [pre-commit](https://pre-commit.com/) to run automated checks before commits.

## Installation

### Install pre-commit

```bash
# macOS
brew install pre-commit

# Or using pip
pip install pre-commit
```

### Install the git hooks

```bash
cd etr
pre-commit install
```

## What gets checked

- **golangci-lint**: Comprehensive Go linter
- **go test**: Runs all tests
- **go build**: Ensures the project builds
- **go mod tidy**: Ensures go.mod and go.sum are tidy
- **trailing-whitespace**: Removes trailing whitespace
- **end-of-file-fixer**: Ensures files end with a newline
- **check-yaml**: Validates YAML syntax
- **check-added-large-files**: Prevents accidentally committing large files (>1MB)
- **check-merge-conflict**: Detects merge conflict markers
- **detect-private-key**: Prevents committing private keys

## Manual run

To run all hooks manually:

```bash
pre-commit run --all-files
```

To run a specific hook:

```bash
pre-commit run go-test
```

## Skipping hooks

If you need to skip hooks (not recommended):

```bash
git commit --no-verify
```

# Developing ETR

Guidelines and help for developing ETR.

## End-to-End Tests

Simple end-to-end tests using Docker Compose are available in the `e2e` directory.

They're primarily intended for verifying functionality in CI but can be operated locally as well.

## ETR Pre-commit Setup

This project uses [pre-commit](https://pre-commit.com/) to run automated checks before commits.

### Installation

#### Install pre-commit

```bash
# macOS
brew install pre-commit

# Or using pip
pip install pre-commit
```

#### Install the git hooks

```bash
cd etr
pre-commit install
```

### What gets checked

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

### Manual run

To run all hooks manually:

```bash
pre-commit run --all-files
```

To run a specific hook:

```bash
pre-commit run go-test
```

### Skipping hooks

If you need to skip hooks (not recommended):

```bash
git commit --no-verify
```

## Using ETR as a Library

The probing engine lives in `pkg/etr` and can be imported by other Go
projects:

```sh
go get github.com/tkjaer/etr/pkg/etr
```

Create a `Tracer` from an `etr.Config` and pass a `Sink` to `Run` to receive
results. Building needs libpcap, and running needs raw packet access (usually
root). See the [package docs](https://pkg.go.dev/github.com/tkjaer/etr/pkg/etr)
and `pkg/etr/example_test.go` for a complete example.

The library API is new in v1.3 and may still change in future releases.

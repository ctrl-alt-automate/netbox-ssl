# Contributing to NetBox SSL

Thank you for your interest in contributing to NetBox SSL! This document provides guidelines for contributing to this project.

## Reporting Bugs

* First, ensure that you're running the [latest stable version](https://github.com/ctrl-alt-automate/netbox-ssl/releases) of this plugin and a [compatible NetBox version](./README.md#compatibility).

* Check the GitHub [issues list](https://github.com/ctrl-alt-automate/netbox-ssl/issues) to see if the bug has already been reported. If you find an existing issue, click "add a reaction" (+1) and optionally add a comment describing how it affects your installation.

* When submitting a new issue, please include:
  * NetBox version and plugin version
  * The environment in which NetBox is running (Docker, bare metal, etc.)
  * Exact steps to reproduce the issue
  * Expected and observed behavior
  * Any error messages or tracebacks
  * Screenshots (if applicable)

## Feature Requests

* Check the GitHub [issues list](https://github.com/ctrl-alt-automate/netbox-ssl/issues) (including closed issues) to see if the feature has already been requested.

* Good feature requests are narrowly defined. Please include:
  * A detailed description of the proposed functionality
  * A use case: who would use it and what value it adds
  * Any database schema changes required (if applicable)
  * Third-party libraries or resources involved

## Submitting Pull Requests

* **Open an issue first** before starting work on a pull request. Discuss your idea with the maintainers to prevent wasting time on something that might not be accepted.

* Ask to be assigned to the issue so others know it's being worked on.

* All pull requests should be based on the `dev` branch, not `main`.

* All new functionality must include relevant tests.

* All code submissions must pass CI checks:
  * Ruff linting (`ruff check`)
  * Ruff formatting (`ruff format --check`)
  * Unit tests (`pytest`)
  * Integration tests (NetBox 4.4 and 4.5)

## Development Setup

```bash
# Clone the repository
git clone https://github.com/ctrl-alt-automate/netbox-ssl.git
cd netbox-ssl

# Start development environment
docker-compose up -d

# Run tests locally
ruff check netbox_ssl/
python -m pytest tests/test_parser.py tests/test_models.py -v -p no:django
```

## Code Style

* We use [Ruff](https://github.com/astral-sh/ruff) for linting and formatting
* Follow PEP 8 guidelines
* Use descriptive variable and function names
* Add docstrings to functions and classes
* Keep code DRY (Don't Repeat Yourself)

## Commit Messages

* Use clear, descriptive commit messages
* Reference issue numbers where applicable (e.g., "Fixes #123")
* Follow conventional commit format when possible

## Commenting on Issues

Only comment on an issue if you are sharing a relevant idea or constructive feedback. **Do not** comment just to show support (use reactions instead) or ask for an ETA. Such comments will be removed to reduce noise.

## Questions?

If you have questions about contributing, feel free to open a discussion on GitHub or reach out to the maintainers.

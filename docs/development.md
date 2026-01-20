# Development Guide

Get your development environment set up and start contributing!

## Prerequisites

- **Python 3.10+**
- **Docker & Docker Compose**
- **Git**
- (Optional) **Nix with direnv** for reproducible environment

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/ctrl-alt-automate/netbox-ssl.git
cd netbox-ssl

# Start development environment
docker compose up -d

# View logs
docker compose logs -f netbox

# Access NetBox
open http://localhost:8000
# Login: admin / admin
```

The plugin is automatically installed and ready to use.

---

## Testing Different NetBox Versions

```bash
# NetBox 4.5 (default)
docker compose up -d

# NetBox 4.4
NETBOX_VERSION=v4.4 docker compose up -d

# Rebuild after changing version
docker compose down -v
NETBOX_VERSION=v4.4 docker compose up -d --build
```

---

## Project Structure

```
netbox-ssl/
├── netbox_ssl/              # Django app package
│   ├── __init__.py          # Plugin metadata
│   ├── models/              # Database models
│   │   ├── certificate.py
│   │   └── assignment.py
│   ├── views/               # List, Detail, Edit views
│   ├── tables/              # NetBox table definitions
│   ├── forms/               # Django forms
│   ├── filtersets/          # Filter definitions
│   ├── api/                 # REST API
│   │   ├── serializers.py
│   │   ├── views.py
│   │   └── urls.py
│   ├── graphql/             # GraphQL schema
│   ├── templates/           # HTML templates
│   ├── utils/               # Utilities
│   │   └── parser.py        # PEM certificate parser
│   └── migrations/          # Database migrations
├── tests/                   # Test suite
├── scripts/                 # Helper scripts
├── docs/                    # Documentation
├── .github/workflows/       # CI/CD
├── docker-compose.yml       # Development environment
├── pyproject.toml           # Package configuration
└── README.md
```

---

## Running Tests

### Unit Tests (Local)

Unit tests run without a full NetBox environment:

```bash
# Run parser and model tests
python -m pytest tests/test_parser.py tests/test_models.py -v -p no:django
```

### Integration Tests (Docker)

Integration tests require the full NetBox stack:

```bash
# Install pytest in the container
docker compose exec netbox bash -c \
    "curl -sS https://bootstrap.pypa.io/get-pip.py | /opt/netbox/venv/bin/python"
docker compose exec netbox /opt/netbox/venv/bin/pip install pytest

# Copy tests and run
docker cp tests/. $(docker compose ps -q netbox):/tmp/plugin_tests/
docker compose exec netbox /opt/netbox/venv/bin/python -m pytest /tmp/plugin_tests/ -v
```

### Django System Checks

```bash
docker compose exec netbox python manage.py check --tag netbox_ssl
```

---

## Code Quality

### Linting with Ruff

```bash
# Check for issues
ruff check netbox_ssl/

# Auto-fix issues
ruff check --fix netbox_ssl/

# Format code
ruff format netbox_ssl/

# Check formatting only
ruff format --check netbox_ssl/
```

### Ruff Configuration

From `pyproject.toml`:

```toml
[tool.ruff]
line-length = 120
target-version = "py310"

[tool.ruff.lint]
select = ["E", "F", "I", "UP", "B", "C4", "SIM"]
```

---

## Creating Test Data

Use the test data script to populate your development environment:

```bash
docker compose exec netbox python manage.py shell \
    -c "exec(open('/opt/netbox/netbox/netbox_ssl/scripts/create_test_data.py').read())"
```

This creates:
- Tenants (Production, Development)
- Sites, Device Types, Roles
- Devices and Virtual Machines
- Services on devices/VMs

---

## Making Changes

### Database Migrations

After modifying models:

```bash
# Generate migration
docker compose exec netbox python manage.py makemigrations netbox_ssl

# Apply migration
docker compose exec netbox python manage.py migrate netbox_ssl

# View migration status
docker compose exec netbox python manage.py showmigrations netbox_ssl
```

### Template Changes

Templates hot-reload automatically. If changes don't appear:

```bash
docker compose restart netbox
```

### Static Files

After changing CSS/JS:

```bash
docker compose exec netbox python manage.py collectstatic --no-input
```

---

## Contributing

### Workflow

1. **Fork** the repository on GitHub
2. **Clone** your fork locally
3. **Create** a feature branch from `dev`
4. **Make** your changes
5. **Test** thoroughly
6. **Submit** a pull request to `dev`

### Branch Strategy

| Branch | Purpose |
|--------|---------|
| `main` | Stable releases only |
| `dev` | Development branch (PR target) |
| `feature/*` | Feature branches |
| `fix/*` | Bug fix branches |

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add certificate renewal notification
fix: correct expiry calculation for leap years
docs: update API documentation
test: add tests for assignment validation
ci: improve CI workflow performance
refactor: simplify certificate parser logic
```

### Pull Request Guidelines

- **Tests:** Include tests for new functionality
- **Documentation:** Update docs if needed
- **CI:** Ensure all CI checks pass
- **Review:** Request review from maintainers
- **Description:** Explain what and why

---

## Release Process

1. Merge `dev` into `main`
2. Update version in `netbox_ssl/__init__.py`
3. Create and push git tag:
   ```bash
   git tag v0.1.0
   git push origin v0.1.0
   ```
4. CI will publish to PyPI automatically

---

## Troubleshooting

### Container Issues

```bash
# View all logs
docker compose logs

# Restart containers
docker compose restart

# Rebuild from scratch
docker compose down -v
docker compose up -d --build
```

### Database Issues

```bash
# Reset migrations
docker compose exec netbox python manage.py migrate netbox_ssl zero
docker compose exec netbox python manage.py migrate netbox_ssl

# Access database directly
docker compose exec postgres psql -U netbox
```

### Import Errors

```bash
# Check Django can load the plugin
docker compose exec netbox python -c "import netbox_ssl; print(netbox_ssl.__version__)"

# Verify plugin registration
docker compose exec netbox python manage.py shell \
    -c "from netbox.plugins import get_installed_plugins; print(get_installed_plugins())"
```

### Template Errors

```bash
# Check for template syntax errors
docker compose exec netbox python manage.py validate_templates
```

---

## Useful Resources

- [NetBox Plugin Development Docs](https://docs.netbox.dev/en/stable/plugins/development/)
- [Django Documentation](https://docs.djangoproject.com/)
- [Python cryptography Library](https://cryptography.io/)

---

**Next:** [Installation](installation.md) — Install the plugin

# NetBox SSL

**Project Janus** — Your Single Source of Truth for TLS/SSL certificate management in NetBox.

[![PyPI](https://img.shields.io/pypi/v/netbox-ssl)](https://pypi.org/project/netbox-ssl/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![NetBox](https://img.shields.io/badge/NetBox-4.4%20%7C%204.5-blue.svg)](https://github.com/netbox-community/netbox)
[![Status](https://img.shields.io/badge/Status-Stable-brightgreen.svg)](#)

---

## What is NetBox SSL?

NetBox SSL is a plugin that brings **visibility** and **control** to your certificate
lifecycle. Track every TLS certificate in your infrastructure, see where it's deployed,
and never let one expire unnoticed.

Named after Janus, the Roman god of doorways and transitions — because every certificate
guards a doorway, and every renewal is a transition.

## Pick your path

<div class="grid cards" markdown>

-   :material-rocket-launch:{ .lg .middle } __New to NetBox SSL?__

    ---

    Start with the **Tutorials** to learn step-by-step.

    [:octicons-arrow-right-24: First Import](tutorials/01-first-import.md)

-   :material-book-open-page-variant:{ .lg .middle } __Solving a specific problem?__

    ---

    Jump to **How-To Guides** for task-oriented help.

    [:octicons-arrow-right-24: How-To Guides](how-to/bulk-import.md)

-   :material-code-braces:{ .lg .middle } __Building integrations?__

    ---

    Browse the **Reference** for API, data models, and configuration.

    [:octicons-arrow-right-24: Reference](reference/api.md)

-   :material-cog:{ .lg .middle } __Operating NetBox SSL in production?__

    ---

    See **Operations** for installation, upgrades, and load testing.

    [:octicons-arrow-right-24: Operations](operations/installation.md)

-   :material-head-lightbulb:{ .lg .middle } __Understanding the design?__

    ---

    Read the **Explanation** docs for architecture and rationale.

    [:octicons-arrow-right-24: Explanation](explanation/architecture.md)

-   :material-source-commit:{ .lg .middle } __Contributing?__

    ---

    See the **Development** section for contributor setup and policies.

    [:octicons-arrow-right-24: Contributing](development/contributing.md)

</div>

## What can you do?

### Track all your certificates

Import certificates with a simple paste — the plugin extracts every X.509 attribute.
Private keys are rejected by design; only public metadata is stored.

### Seamless renewals with the Janus workflow

When you renew, all assignments transfer automatically from the old certificate to
the new one, and the old one is archived. Full audit trail, atomic operation.

### Know where every certificate lives

Assign certificates to Services, Devices, or Virtual Machines. See at a glance which
infrastructure depends on which certificate.

### Proactive expiry alerts

Scheduled scans + NetBox Event Rules + webhooks → Slack, Teams, or PagerDuty
notifications long before anything breaks.

### Compliance and analytics

Define compliance policies, monitor a score over time, visualise the expiry
forecast, and export reports in CSV or JSON.

## Community

- :material-github: [GitHub](https://github.com/ctrl-alt-automate/netbox-ssl) — source, issues, PRs
- :material-package: [PyPI](https://pypi.org/project/netbox-ssl/) — install with `pip install netbox-ssl`
- :material-scale-balance: Apache 2.0 licensed — free for commercial use

## Contributing

We welcome contributions! See the [Contributing guide](development/contributing.md)
to get started, or jump straight to [good first issues](https://github.com/ctrl-alt-automate/netbox-ssl/labels/good-first-issue).

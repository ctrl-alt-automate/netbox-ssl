# Load Testing

This runbook shows how to exercise NetBox SSL's API endpoints under load using
[Locust](https://locust.io/). Use it for capacity planning, regression detection
when upgrading NetBox, or validating plugin settings before rolling out to
production.

## When to run load tests

- Before adopting a new NetBox version (verify the plugin still meets your SLOs)
- When tuning `bulk_import_max_batch_size`, `max_export_size`, or other limits
- When scaling up your deployment (e.g., adding gunicorn workers)
- As part of periodic capacity planning (quarterly, annually)

Load tests are **not** run in CI — they require a full NetBox + PostgreSQL +
Redis stack and take several minutes per scenario. Run them on-demand against
a dedicated test environment.

## Install Locust

Locust is part of the `dev` optional-dependencies group:

```bash
pip install -e ".[dev]"
```

Verify:

```bash
locust --version
```

## Prepare a NetBox instance

Bring up a local NetBox via Docker Compose:

```bash
cd /path/to/netbox-ssl
docker-compose up -d
```

Wait ~60 seconds for NetBox to initialise. It listens on `http://localhost:8000`
with credentials `admin` / `admin`.

Create an API token:

```bash
docker exec netbox-ssl-netbox-1 python /opt/netbox/netbox/manage.py shell -c "
from users.models import Token, User
u = User.objects.get(username='admin')
t, _ = Token.objects.get_or_create(user=u)
print(t.key)
"
```

Copy the printed token — you'll use it via `NETBOX_TOKEN` env var.

Optionally pre-populate with test certificates:

```bash
python -m tests.load.seed_data > /tmp/sample.pem
# use the NetBox UI or API to import this PEM N times
```

## Run Locust (web UI)

Start Locust pointing at your NetBox:

```bash
NETBOX_TOKEN="nbt_xxx.yyy" locust \
  -f tests/load/locustfile.py \
  --host=http://localhost:8000
```

Open http://localhost:8089. Set:

- **Number of users**: 50 (start here, scale up incrementally)
- **Spawn rate**: 5 users/second
- **Host**: `http://localhost:8000` (already pre-filled from `--host`)

Click **Start swarm**. Watch the metrics: request rate, p50/p95/p99 latency,
failure rate.

## Run Locust (headless for CI-like reproducibility)

For scripted or comparable runs, use headless mode:

```bash
NETBOX_TOKEN="nbt_xxx.yyy" locust \
  -f tests/load/locustfile.py \
  --host=http://localhost:8000 \
  --users 50 \
  --spawn-rate 5 \
  --run-time 2m \
  --headless \
  --csv=/tmp/locust-baseline
```

This produces CSV files:

- `/tmp/locust-baseline_stats.csv` — per-endpoint aggregates
- `/tmp/locust-baseline_stats_history.csv` — time series
- `/tmp/locust-baseline_failures.csv` — per-failure records

## Interpreting results

Key metrics:

- **Request rate (req/s)**: throughput ceiling for the current configuration
- **p50 latency**: typical user experience
- **p95 latency**: tail experience — users at the edge feel this
- **p99 latency**: worst-case — watch for long-tail regressions
- **Failure rate**: should be under 1% in steady state; spikes indicate
  resource exhaustion

## Target SLOs

On a reference environment (Docker Desktop 8-core / 16 GB RAM, NetBox 4.5.x):

| Scenario | Users | Target success | p95 target | p99 target |
|----------|-------|----------------|------------|------------|
| List certificates | 50 | >= 99% | < 300ms | < 1s |
| Filter by status | 25 | >= 99% | < 400ms | < 1.5s |
| Import (Smart Paste) | 10 | >= 95% | < 500ms | < 2s |
| Diff API | 5 | >= 99% | < 200ms | < 500ms |

If your numbers are worse than these on equivalent hardware, investigate:

- Database connection pool: are requests queueing?
- Gunicorn workers: add more for CPU-bound work
- Redis: is it under pressure?
- Indexes: ensure the v0.9 Certificate indexes are in place (run
  `manage.py check --tag netbox_ssl`)

## Reference baseline

The following results are from the v1.0.0 reference run — use as a starting
point for comparison:

| Scenario | Users | Requests/s | Success | p50 | p95 | p99 |
|----------|-------|------------|---------|-----|-----|-----|
| List | 50 | TBD | TBD | TBD | TBD | TBD |
| Filter | 25 | TBD | TBD | TBD | TBD | TBD |
| Import | 10 | TBD | TBD | TBD | TBD | TBD |
| Diff | 5 | TBD | TBD | TBD | TBD | TBD |

!!! note "TBD values"
    These are filled in when the maintainer cuts a release — they're captured
    on the reference hardware defined above. Your results will vary based on
    CPU, memory, disk IO, and concurrent load on the host.

## Capacity planning tips

- **Gunicorn workers**: start with `(2 * CPU cores) + 1`; more helps with
  IO-bound requests but doesn't help with CPU-bound ones
- **Database connections**: NetBox uses connection pooling; ensure
  `CONN_MAX_AGE` in NetBox config matches your load profile
- **Redis**: for NetBox Event Rules with high-volume events, monitor Redis
  queue depth — if it grows, scale out the worker pool
- **PostgreSQL indexes**: v0.9 added 9 indexes to the Certificate table. If
  you have older migrations, run `manage.py migrate netbox_ssl` to bring
  them in.

## Customising scenarios

`tests/load/locustfile.py` has three user classes:

- `CertificateBrowseUser` — read-heavy list + filter (weight 5)
- `CertificateImportUser` — write-heavy import (weight 1)
- `CertificateDiffUser` — occasional diff calls (weight 1)

Adjust the weights to model your workload. For a read-only monitoring dashboard,
set `CertificateImportUser.weight = 0`. For a bulk import test, boost the
write user's weight.

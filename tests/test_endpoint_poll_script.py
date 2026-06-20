"""Tests for MonitoredEndpointPoll Script (#149).

Covers orchestration only — poll_endpoint is mocked so no network/poll logic runs.
Mirror of tests/test_expiry_scan.py pattern.
"""

import uuid
from unittest.mock import patch

import pytest


@pytest.mark.django_db
class TestMonitoredEndpointPollScript:
    def _ep(self):
        from netbox_ssl.models import MonitoredEndpoint

        return MonitoredEndpoint.objects.create(
            name=f"e{uuid.uuid4().hex[:6]}", url="https://e.example.com"
        )

    @patch("netbox_ssl.scripts.endpoint_monitor.poll_endpoint")
    def test_polls_all_endpoints(self, mock_poll):
        from netbox_ssl.models import MonitoredEndpointStatusChoices
        from netbox_ssl.scripts.endpoint_monitor import MonitoredEndpointPoll
        from netbox_ssl.utils.endpoint_monitor import PollResult

        _ep1, _ep2 = self._ep(), self._ep()
        mock_poll.side_effect = lambda ep, **kw: PollResult(
            ep, MonitoredEndpointStatusChoices.STATUS_OK, False, ()
        )
        script = MonitoredEndpointPoll()
        script.run({"tenant": None, "dry_run": False}, commit=True)
        assert mock_poll.call_count == 2

    @patch("netbox_ssl.scripts.endpoint_monitor.poll_endpoint")
    def test_dry_run_does_not_poll(self, mock_poll):
        from netbox_ssl.scripts.endpoint_monitor import MonitoredEndpointPoll

        self._ep()
        MonitoredEndpointPoll().run({"tenant": None, "dry_run": True}, commit=False)
        mock_poll.assert_not_called()

    @patch("netbox_ssl.scripts.endpoint_monitor.poll_endpoint")
    def test_tenant_filter_applied(self, mock_poll):
        """When a tenant is given, only endpoints for that tenant are polled."""
        from tenancy.models import Tenant

        from netbox_ssl.models import MonitoredEndpoint, MonitoredEndpointStatusChoices
        from netbox_ssl.scripts.endpoint_monitor import MonitoredEndpointPoll
        from netbox_ssl.utils.endpoint_monitor import PollResult

        tenant = Tenant.objects.create(name=f"t{uuid.uuid4().hex[:6]}", slug=f"t{uuid.uuid4().hex[:6]}")
        ep_with = MonitoredEndpoint.objects.create(
            name=f"e{uuid.uuid4().hex[:6]}", url="https://a.example.com", tenant=tenant
        )
        _ep_without = MonitoredEndpoint.objects.create(
            name=f"e{uuid.uuid4().hex[:6]}", url="https://b.example.com"
        )
        mock_poll.side_effect = lambda ep, **kw: PollResult(
            ep, MonitoredEndpointStatusChoices.STATUS_OK, False, ()
        )
        MonitoredEndpointPoll().run({"tenant": tenant, "dry_run": False}, commit=True)
        assert mock_poll.call_count == 1
        assert mock_poll.call_args[0][0] == ep_with

    @patch("netbox_ssl.scripts.endpoint_monitor.poll_endpoint")
    def test_summary_string_returned(self, mock_poll):
        """run() returns a non-empty summary string."""
        from netbox_ssl.models import MonitoredEndpointStatusChoices
        from netbox_ssl.scripts.endpoint_monitor import MonitoredEndpointPoll
        from netbox_ssl.utils.endpoint_monitor import PollResult

        self._ep()
        mock_poll.side_effect = lambda ep, **kw: PollResult(
            ep, MonitoredEndpointStatusChoices.STATUS_OK, False, ()
        )
        result = MonitoredEndpointPoll().run({"tenant": None, "dry_run": False}, commit=True)
        assert isinstance(result, str)
        assert len(result) > 0

    @patch("netbox_ssl.scripts.endpoint_monitor.poll_endpoint")
    def test_rotated_count_in_summary(self, mock_poll):
        """Rotated count appears in summary when at least one cert rotated."""
        from netbox_ssl.models import MonitoredEndpointStatusChoices
        from netbox_ssl.scripts.endpoint_monitor import MonitoredEndpointPoll
        from netbox_ssl.utils.endpoint_monitor import PollResult

        self._ep()
        mock_poll.side_effect = lambda ep, **kw: PollResult(
            ep, MonitoredEndpointStatusChoices.STATUS_OK, True, ("endpoint_cert_rotated",)
        )
        result = MonitoredEndpointPoll().run({"tenant": None, "dry_run": False}, commit=True)
        assert "rotated=1" in result

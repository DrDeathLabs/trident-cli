from __future__ import annotations

import httpx

from trident.calibration.feeds import nvd


class _RetryingClient:
    def __init__(self, failures):
        self.failures = list(failures)
        self.calls = 0

    def get(self, *args, **kwargs):
        self.calls += 1
        if self.failures:
            failure = self.failures.pop(0)
            if isinstance(failure, BaseException):
                raise failure
            return httpx.Response(
                failure,
                request=httpx.Request("GET", "https://example.test/cves"),
            )
        return httpx.Response(
            200,
            json={"vulnerabilities": []},
            request=httpx.Request("GET", "https://example.test/cves"),
        )


def test_fetch_page_retries_transient_transport_failure(monkeypatch):
    client = _RetryingClient([httpx.ReadTimeout("temporary timeout")])
    monkeypatch.setattr(nvd.time, "sleep", lambda _seconds: None)

    result = nvd._fetch_page(client, {"startIndex": 0, "resultsPerPage": 1000})

    assert result == {"vulnerabilities": []}
    assert client.calls == 2


def test_fetch_page_retries_server_error(monkeypatch):
    client = _RetryingClient([503])
    monkeypatch.setattr(nvd.time, "sleep", lambda _seconds: None)

    result = nvd._fetch_page(client, {"startIndex": 1000, "resultsPerPage": 1000})

    assert result == {"vulnerabilities": []}
    assert client.calls == 2

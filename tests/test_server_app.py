import pytest

pytest.importorskip("starlette")
from starlette.testclient import TestClient

from stationchief.server.app import create_app
from stationchief.server.store import MemoryStore
from server_helpers import AUTH, TOKEN, server_config


@pytest.fixture
def client():
    return TestClient(create_app(server_config(), MemoryStore()))


def test_healthz_needs_no_token(client):
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


@pytest.mark.parametrize("path", ["/otel/v1/logs", "/otel/v1/metrics", "/otel/v1/traces", "/check"])
def test_every_other_route_requires_a_token(client, path):
    response = client.post(path, json={})
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize(
    "header",
    ["Bearer wrong", f"Basic {TOKEN}", "Bearer", TOKEN, f"bearer{TOKEN}"],
)
def test_bad_credentials_are_rejected(client, header):
    assert client.post("/otel/v1/metrics", json={}, headers={"Authorization": header}).status_code == 401


def test_scheme_is_case_insensitive(client):
    assert client.post("/otel/v1/metrics", json={}, headers={"Authorization": f"bearer {TOKEN}"}).status_code == 200


@pytest.mark.parametrize("path", ["/otel/v1/metrics", "/otel/v1/traces"])
def test_metrics_and_traces_are_accepted_and_dropped(client, path):
    response = client.post(path, json={"resourceMetrics": []}, headers=AUTH)
    assert response.status_code == 200
    assert response.json() == {}

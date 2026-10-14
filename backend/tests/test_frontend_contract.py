from pathlib import Path


def test_dashboard_loads_the_backend_bootstrap_endpoint():
    index = Path(__file__).resolve().parents[2] / "index.html"
    source = index.read_text()
    assert "/dashboard/bootstrap" in source
    assert "Authorization" in source
    assert "backendStatus" in source
    assert "indicator.threat_type" in source
    assert "indicator.last_synced_at" in source
    assert "Expired indicators are hidden by the API" in source
    assert "ABUSECH_AUTH_KEY" not in source

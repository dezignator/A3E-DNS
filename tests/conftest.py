
---

### File 125 — `tests/conftest.py`

**Upload path on GitHub:** `tests/conftest.py`

```python
"""Shared pytest fixtures for the A3E-DNS test suite.

The fixtures here are deliberately small and deterministic. They are
used by the unit tests and by the integration tests; the integration
tests that need the full pipeline add their own fixtures locally.

Naming convention: fixtures that produce a dict configuration use the
``*_config`` suffix; fixtures that produce a callable or an object use
the plain name. Fixtures that touch the file system use ``tmp_path``
(the pytest built-in) so that every test gets its own directory.

Run the suite with:

    pytest tests/ -v --timeout=600
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pytest

# Make the package importable when running `pytest` without installing.
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from src import __version__  # noqa: E402
from src.utils.seed import DEFAULT_SEED, seed_everything  # noqa: E402


# ---------------------------------------------------------------- session
@pytest.fixture(scope="session")
def artifact_version() -> str:
    """The artifact version string, for reporting in test output."""
    return __version__


@pytest.fixture(scope="session")
def repo_root() -> Path:
    """Absolute path to the repository root."""
    return _REPO_ROOT


@pytest.fixture(scope="session")
def configs_dir(repo_root: Path) -> Path:
    """Absolute path to ``configs/``."""
    return repo_root / "configs"


# ---------------------------------------------------------------- seeding
@pytest.fixture
def seeded_rng() -> np.random.Generator:
    """Seed all RNGs and return a generator.

    Every test that uses randomness should use this fixture so that
    the test suite is fully deterministic. The master seed is
    ``DEFAULT_SEED``.
    """
    return seed_everything(DEFAULT_SEED)


@pytest.fixture
def fixed_seed() -> int:
    """The master seed used by the artifact (20261130)."""
    return DEFAULT_SEED


# ---------------------------------------------------------------- small data
@pytest.fixture
def small_feature_matrix() -> np.ndarray:
    """A ``(16, 128)`` feature matrix, deterministic given the seed."""
    rng = np.random.default_rng(DEFAULT_SEED)
    return rng.normal(0.0, 1.0, size=(16, 128))


@pytest.fixture
def small_labels() -> np.ndarray:
    """16 binary labels, 8 of each class, deterministic given the seed."""
    return np.array([0, 1] * 8, dtype=np.int64)


@pytest.fixture
def small_scores() -> np.ndarray:
    """16 anomaly scores in [0, 1], deterministic given the seed."""
    rng = np.random.default_rng(DEFAULT_SEED + 1)
    return rng.uniform(0.0, 1.0, size=16)


@pytest.fixture
def small_updates() -> np.ndarray:
    """A ``(10, 16)`` matrix of FL client updates, deterministic given the seed."""
    rng = np.random.default_rng(DEFAULT_SEED + 2)
    return rng.normal(0.0, 0.1, size=(10, 16))


# ---------------------------------------------------------------- metadata
@pytest.fixture
def minimal_metadata() -> dict:
    """Minimal metadata dict for the compliance checkers.

    Contains the minimum fields needed for the checkers to return a
    verdict. The checkers are exercised fully in
    ``tests/unit/test_compliance_checkers.py``; this fixture is the
    shared baseline.
    """
    return {
        "aee": {
            "se3_dim": 1,
            "key_bits": 256,
            "entropy_source": ["/dev/urandom"],
        },
        "qhe": {
            "scheme": "ring_lwe",
            "n": 256,
            "q": 4096,
        },
        "federated_learning": {
            "dp_sgd": {"enabled": True, "epsilon": 0.68},
            "aggregation": {"method": "geometric_median"},
            "performance": {"rounds": 100, "clients": 100},
        },
        "threat_intel": {
            "internal_logs": {"enabled": True},
            "cert_alerts": {"enabled": True},
        },
        "amps": {
            "control": {"model": "mdp", "solver": "hamilton_jacobi_bellman"},
            "divergence": {"metrics": ["kl", "renyi"]},
            "isolation": {"doh": {}, "dot": {}, "doq": {}},
            "resources": {"memory_gb": 2, "timeout_seconds": 30},
            "performance": {"p99_mitigation_ms": 1.5},
        },
        "failover": {},
    }


# ---------------------------------------------------------------- paths
@pytest.fixture
def sample_stix_bundle(repo_root: Path) -> Path:
    """Path to the committed sample STIX 2.1 bundle."""
    return repo_root / "data" / "threat_feeds" / "cert_alerts_sample.stix.json"


@pytest.fixture
def sample_honeypot_logs(repo_root: Path) -> Path:
    """Path to the committed sample honeypot logs."""
    return repo_root / "data" / "threat_feeds" / "honeypot_logs_sample.json"


@pytest.fixture
def sample_darknet_metadata(repo_root: Path) -> Path:
    """Path to the committed sample darknet PCAP metadata."""
    return repo_root / "data" / "threat_feeds" / "darknet_pcap_metadata.json"


@pytest.fixture
def sample_vendor_feed(repo_root: Path) -> Path:
    """Path to the committed sample vendor feed."""
    return repo_root / "data" / "threat_feeds" / "vendor_feeds_normalized.json"


# ---------------------------------------------------------------- tmp helpers
@pytest.fixture
def tmp_config(tmp_path: Path) -> Path:
    """A temp directory pre-populated with a copy of ``configs/``.

    Tests that need to write a config can use this fixture without
    touching the committed configuration.
    """
    import shutil
    src = _REPO_ROOT / "configs"
    dst = tmp_path / "configs"
    shutil.copytree(src, dst)
    return dst


@pytest.fixture
def tmp_output(tmp_path: Path) -> Path:
    """A temp directory for outputs; cleaned up by pytest."""
    d = tmp_path / "outputs"
    d.mkdir()
    return d

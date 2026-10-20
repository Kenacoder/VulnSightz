import pytest

from xss.config import XSSConfig
from xss.scope import ScopeController, ScopeError


def test_out_of_scope_url_rejected():
    cfg = XSSConfig(
        allowed_origins=["http://127.0.0.1:5001"],
        allow_loopback=True,
    )
    scope = ScopeController(cfg)
    with pytest.raises(ScopeError):
        scope.check_url("http://evil.example/path")


def test_loopback_blocked_without_flag():
    cfg = XSSConfig(allowed_origins=["http://127.0.0.1:5001"], allow_loopback=False)
    scope = ScopeController(cfg)
    with pytest.raises(ScopeError):
        scope.check_url("http://127.0.0.1:5001/reflect")


def test_in_scope_ok():
    cfg = XSSConfig(
        allowed_origins=["http://127.0.0.1:5001"],
        allow_loopback=True,
    )
    scope = ScopeController(cfg)
    assert scope.check_url("http://127.0.0.1:5001/reflect")


def test_out_of_scope_redirect_rejected():
    cfg = XSSConfig(
        allowed_origins=["http://127.0.0.1:5001"],
        allow_loopback=True,
    )
    scope = ScopeController(cfg)
    with pytest.raises(ScopeError):
        scope.check_redirect("http://example.com/")


def test_metadata_blocked():
    cfg = XSSConfig(
        allowed_origins=["http://169.254.169.254"],
        allow_private_networks=True,
        allow_loopback=True,
    )
    scope = ScopeController(cfg)
    with pytest.raises(ScopeError):
        scope.check_url("http://169.254.169.254/latest/meta-data/")


def test_path_prefix_enforced():
    cfg = XSSConfig(
        allowed_origins=["http://127.0.0.1:5001"],
        allowed_path_prefixes=["/api"],
        allow_loopback=True,
    )
    scope = ScopeController(cfg)
    with pytest.raises(ScopeError):
        scope.check_url("http://127.0.0.1:5001/reflect")

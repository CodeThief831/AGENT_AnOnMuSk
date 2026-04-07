"""Tests for core.scope module."""

import pytest
from core.scope import ScopeValidator


class TestScopeValidator:
    """Test scope validation logic."""

    def test_exact_domain_match(self):
        scope = ScopeValidator(include_patterns=["example.com"])
        assert scope.is_in_scope("example.com")
        assert not scope.is_in_scope("other.com")

    def test_wildcard_match(self):
        scope = ScopeValidator(include_patterns=["*.example.com"])
        assert scope.is_in_scope("api.example.com")
        assert scope.is_in_scope("test.api.example.com")
        assert not scope.is_in_scope("example.com")

    def test_url_extraction(self):
        scope = ScopeValidator(include_patterns=["example.com", "*.example.com"])
        assert scope.is_in_scope("https://example.com/api/v1")
        assert scope.is_in_scope("http://api.example.com/test")
        assert not scope.is_in_scope("https://evil.com")

    def test_exclusion_priority(self):
        scope = ScopeValidator(
            include_patterns=["*.example.com"],
            exclude_patterns=["internal.example.com"],
        )
        assert scope.is_in_scope("api.example.com")
        assert not scope.is_in_scope("internal.example.com")

    def test_empty_scope_fails_closed(self):
        scope = ScopeValidator(include_patterns=[])
        assert not scope.is_in_scope("anything.com")

    def test_validate_or_raise(self):
        scope = ScopeValidator(include_patterns=["example.com"])
        scope.validate_or_raise("example.com")  # Should not raise

        with pytest.raises(ValueError, match="OUT OF SCOPE"):
            scope.validate_or_raise("evil.com")

    def test_from_target(self):
        scope = ScopeValidator.from_target("example.com")
        assert scope.is_in_scope("example.com")
        assert scope.is_in_scope("sub.example.com")

    def test_cidr_scope(self):
        scope = ScopeValidator(include_patterns=["192.168.1.0/24"])
        assert scope.is_in_scope("192.168.1.42")
        assert not scope.is_in_scope("10.0.0.1")

    def test_case_insensitive(self):
        scope = ScopeValidator(include_patterns=["Example.COM"])
        assert scope.is_in_scope("example.com")
        assert scope.is_in_scope("EXAMPLE.COM")

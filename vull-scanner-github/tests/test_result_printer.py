"""Tests for result printer node."""

import pytest
from vull_scanner.nodes.result_printer import mask_password


class TestMaskPassword:
    """Tests for password masking function."""

    def test_show_full_password(self):
        """Test that show_full=True returns the full password."""
        assert mask_password("secretpass123", show_full=True) == "secretpass123"

    def test_mask_empty_password(self):
        """Test masking empty password."""
        assert mask_password("", show_full=False) == "****"

    def test_mask_short_password(self):
        """Test masking 1-2 character passwords."""
        assert mask_password("a", show_full=False) == "*"
        assert mask_password("ab", show_full=False) == "**"

    def test_mask_normal_password(self):
        """Test masking normal length passwords."""
        # "password" (8 chars) -> "p******d"
        result = mask_password("password", show_full=False)
        assert result[0] == "p"
        assert result[-1] == "d"
        assert len(result) == 8
        assert result[1:-1] == "******"

    def test_mask_long_password(self):
        """Test masking long passwords."""
        # "supersecretpassword123" -> "s********************3"
        result = mask_password("supersecretpassword123", show_full=False)
        assert result[0] == "s"
        assert result[-1] == "3"
        assert "*" in result

    def test_mask_three_char_password(self):
        """Test masking 3 character password (edge case)."""
        # "abc" -> "a*c"
        result = mask_password("abc", show_full=False)
        assert result == "a*c"

    def test_default_is_masked(self):
        """Test that default behavior is masked."""
        result = mask_password("mypassword")
        assert result != "mypassword"
        assert result[0] == "m"
        assert result[-1] == "d"

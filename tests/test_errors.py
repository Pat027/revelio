"""Tests for error classes."""

import pytest
from revelio.errors import ModelRefusalError


class TestModelRefusalError:
    def test_default_message(self):
        err = ModelRefusalError()
        assert "refused to simulate" in str(err)

    def test_entity_in_message(self):
        err = ModelRefusalError(entity="bias")
        assert "bias" in str(err)
        assert "refused" in str(err)

    def test_is_exception_subclass(self):
        assert issubclass(ModelRefusalError, Exception)

    def test_can_be_raised_and_caught(self):
        with pytest.raises(ModelRefusalError):
            raise ModelRefusalError(entity="test")

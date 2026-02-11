"""Tests for utility functions."""

import pytest
from revelio.utils import (
    validate_model_callback_signature,
    format_turns,
    create_progress,
    add_pbar,
    update_pbar,
)
from revelio.test_case.test_case import RTTurn


class TestValidateModelCallbackSignature:
    def test_sync_callback_sync_mode(self):
        def sync_fn(x):
            return x

        # Should not raise
        validate_model_callback_signature(sync_fn, async_mode=False)

    def test_async_callback_async_mode(self):
        async def async_fn(x):
            return x

        # Should not raise
        validate_model_callback_signature(async_fn, async_mode=True)

    def test_sync_callback_async_mode_raises(self):
        def sync_fn(x):
            return x

        with pytest.raises(ValueError, match="async"):
            validate_model_callback_signature(sync_fn, async_mode=True)

    def test_async_callback_sync_mode_raises(self):
        async def async_fn(x):
            return x

        with pytest.raises(ValueError, match="sync"):
            validate_model_callback_signature(async_fn, async_mode=False)


class TestFormatTurns:
    def test_single_turn(self):
        turns = [RTTurn(role="user", content="hello")]
        result = format_turns(turns)
        assert "Role: user" in result
        assert "Content: hello" in result
        assert "Full Conversation" in result
        assert "End of conversation" in result

    def test_multiple_turns(self):
        turns = [
            RTTurn(role="user", content="hi"),
            RTTurn(role="assistant", content="hello"),
        ]
        result = format_turns(turns)
        assert "Role: user" in result
        assert "Role: assistant" in result

    def test_empty_list_raises(self):
        with pytest.raises(ValueError, match="no 'turns'"):
            format_turns([])


class TestProgressHelpers:
    def test_create_progress_disabled(self):
        progress = create_progress(enabled=False)
        # Should be a context manager (the _null_progress generator)
        assert progress is not None

    def test_create_progress_enabled(self):
        progress = create_progress(enabled=True)
        assert progress is not None
        assert hasattr(progress, "add_task")

    def test_add_pbar_with_none_progress(self):
        result = add_pbar(None, "test", total=10)
        assert result is None

    def test_update_pbar_with_none_progress(self):
        # Should not raise
        update_pbar(None, None)

    def test_update_pbar_with_none_pbar_id(self):
        from rich.progress import Progress

        p = Progress()
        update_pbar(p, None)

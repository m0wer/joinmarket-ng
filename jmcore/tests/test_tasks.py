"""Tests for shared async task utilities."""

from __future__ import annotations

import asyncio

import pytest

from jmcore.tasks import parse_directory_address, run_periodic_task


class TestRunPeriodicTask:
    """Tests for run_periodic_task."""

    @pytest.mark.asyncio
    async def test_callback_is_called(self) -> None:
        """Callback should be invoked at least once."""
        call_count = 0

        async def callback() -> None:
            nonlocal call_count
            call_count += 1

        task = asyncio.create_task(
            run_periodic_task(
                name="test",
                callback=callback,
                interval=0.01,
            )
        )
        await asyncio.sleep(0.05)
        task.cancel()
        await task  # returns normally after catching CancelledError
        assert call_count >= 1

    @pytest.mark.asyncio
    async def test_initial_delay(self) -> None:
        """Callback should not fire before initial_delay elapses."""
        call_count = 0

        async def callback() -> None:
            nonlocal call_count
            call_count += 1

        task = asyncio.create_task(
            run_periodic_task(
                name="delay-test",
                callback=callback,
                interval=0.01,
                initial_delay=0.5,
            )
        )
        await asyncio.sleep(0.05)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert call_count == 0

    @pytest.mark.asyncio
    async def test_running_check_stops_task(self) -> None:
        """Task should stop when running_check returns False."""
        call_count = 0
        keep_running = True

        async def callback() -> None:
            nonlocal call_count, keep_running
            call_count += 1
            if call_count >= 3:
                keep_running = False

        await run_periodic_task(
            name="stop-test",
            callback=callback,
            interval=0.01,
            running_check=lambda: keep_running,
        )
        assert call_count >= 3

    @pytest.mark.asyncio
    async def test_exception_in_callback_does_not_crash(self) -> None:
        """Exceptions in callback should be caught; task keeps running."""
        call_count = 0

        async def callback() -> None:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise ValueError("test error")

        task = asyncio.create_task(
            run_periodic_task(
                name="error-test",
                callback=callback,
                interval=0.01,
            )
        )
        await asyncio.sleep(0.05)
        task.cancel()
        await task  # returns normally after catching CancelledError
        assert call_count >= 2

    @pytest.mark.asyncio
    async def test_cancellation_is_handled(self) -> None:
        """CancelledError should break the loop gracefully and return normally."""
        task = asyncio.create_task(
            run_periodic_task(
                name="cancel-test",
                callback=self._noop,
                interval=0.01,
            )
        )
        await asyncio.sleep(0.02)
        task.cancel()
        # Task catches CancelledError internally and returns normally
        await task
        assert task.done()
        assert not task.cancelled()

    @pytest.mark.asyncio
    async def test_no_running_check_runs_indefinitely(self) -> None:
        """Without running_check, task runs until cancelled."""
        call_count = 0

        async def callback() -> None:
            nonlocal call_count
            call_count += 1

        task = asyncio.create_task(
            run_periodic_task(
                name="indefinite-test",
                callback=callback,
                interval=0.01,
                running_check=None,
            )
        )
        await asyncio.sleep(0.08)
        task.cancel()
        await task  # returns normally after catching CancelledError
        assert call_count >= 3

    @staticmethod
    async def _noop() -> None:
        pass


class TestParseDirectoryAddress:
    """Tests for parse_directory_address."""

    def test_host_and_port(self) -> None:
        host, port = parse_directory_address("example.com:1234")
        assert host == "example.com"
        assert port == 1234

    def test_host_only_uses_default_port(self) -> None:
        host, port = parse_directory_address("example.com")
        assert host == "example.com"
        assert port == 5222

    def test_custom_default_port(self) -> None:
        host, port = parse_directory_address("example.com", default_port=9999)
        assert host == "example.com"
        assert port == 9999

    def test_onion_address_with_port(self) -> None:
        addr = "abcdef1234567890.onion:5222"
        host, port = parse_directory_address(addr)
        assert host == "abcdef1234567890.onion"
        assert port == 5222

    def test_onion_address_without_port(self) -> None:
        addr = "abcdef1234567890.onion"
        host, port = parse_directory_address(addr)
        assert host == "abcdef1234567890.onion"
        assert port == 5222

    def test_localhost(self) -> None:
        host, port = parse_directory_address("localhost:8080")
        assert host == "localhost"
        assert port == 8080

    def test_ip_address_with_port(self) -> None:
        host, port = parse_directory_address("192.168.1.1:3000")
        assert host == "192.168.1.1"
        assert port == 3000

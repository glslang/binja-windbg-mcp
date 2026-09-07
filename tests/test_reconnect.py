"""Exercise the pairing loop with controlled failures and a clock that skips delays."""

import asyncio

import pytest

from binja_windbg_mcp import pairing as module
from binja_windbg_mcp.pairing import Pairing


class Clock:
    def __init__(self):
        self.polls = []
        self.retries = []

    def __getattr__(self, name):
        return getattr(asyncio, name)

    async def wait_for(self, request, timeout):
        # These tests drive _run directly, where wait_for waits only for queued actions.
        request.close()
        self.polls.append(timeout)
        raise asyncio.TimeoutError

    async def sleep(self, delay):
        self.retries.append(delay)


@pytest.fixture
def loop_setup(monkeypatch):
    clock = Clock()
    connections = []

    class Client:
        async def __aenter__(self):
            connections.append(self)
            return self

        async def __aexit__(self, *args):
            return False

    monkeypatch.setattr(module, "Client", lambda *args, **kwargs: Client())
    monkeypatch.setattr(module, "asyncio", clock)

    class Workspace:
        def current_location(self, binary_id):
            return {"generation": ["binary", 0x1000, 0]}

    pair = Pairing(Workspace(), None)
    pair.state = {"binary_id": "binary", "session_id": "session"}
    pair.generation = ["binary", 0x1000, 0]

    async def validate(client):
        pass

    monkeypatch.setattr(pair, "_validate", validate)
    return pair, clock, connections


@pytest.mark.parametrize("interval", [0.2, 5])
@pytest.mark.parametrize("running", [False, True])
def test_poll_failures_back_off_until_a_healthy_sample(loop_setup, monkeypatch, interval, running):
    pair, clock, connections = loop_setup
    healthy = (
        {"status": "error", "error": {"category": "target_running"}}
        if running
        else {"status": "ok", "location_state": "unmapped", "coordinate": None}
    )
    responses = iter(
        [ConnectionError()] * 6
        + [healthy, ConnectionError(), ConnectionError()]
        + [{"status": "error", "error": {"category": "stale_session"}}]
    )

    async def sample(*args):
        response = next(responses)
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(pair, "_call", sample)

    async def check():
        ready = asyncio.get_running_loop().create_future()
        await pair._run("http://127.0.0.1/mcp", "test", pair.epoch, ready, interval)
        assert ready.result()
        assert pair.state["state"] == "stale_session"

    asyncio.run(check())
    assert clock.retries == [1, 2, 4, 8, 10, 10, 1, 2]
    assert len(connections) == 9
    expected_polls = [interval] * 10
    expected_polls[7] = max(interval, 1) if running else interval
    assert clock.polls == expected_polls


def test_connection_and_validation_failures_preserve_the_retry_streak(loop_setup, monkeypatch):
    pair, clock, connections = loop_setup
    attempts = iter(["poll", "connect", "validation", "poll", "connect", "validation", "stop"])

    class Client:
        async def __aenter__(self):
            self.failure = next(attempts)
            connections.append(self)
            if self.failure == "connect":
                raise ConnectionError()
            return self

        async def __aexit__(self, *args):
            return False

    async def validate(client):
        if client.failure == "validation":
            raise ConnectionError()

    async def sample(client, *args):
        if client.failure == "poll":
            raise ConnectionError()
        return {"status": "error", "error": {"category": "worker_lost"}}

    monkeypatch.setattr(module, "Client", lambda *args, **kwargs: Client())
    monkeypatch.setattr(pair, "_validate", validate)
    monkeypatch.setattr(pair, "_call", sample)

    async def check():
        ready = asyncio.get_running_loop().create_future()
        await pair._run("http://127.0.0.1/mcp", "test", pair.epoch, ready, 0.5)
        assert ready.result()
        assert pair.state["state"] == "worker_lost"

    asyncio.run(check())
    assert clock.retries == [1, 2, 4, 8, 10, 10]
    assert len(connections) == 7


def test_unpair_cancels_backoff_and_refuses_unsent_actions(loop_setup, monkeypatch):
    pair, clock, connections = loop_setup

    async def check():
        sleeping = asyncio.Event()

        async def sleep(delay):
            clock.retries.append(delay)
            sleeping.set()
            await asyncio.Event().wait()

        async def sample(*args):
            raise ConnectionError()

        monkeypatch.setattr(clock, "sleep", sleep)
        monkeypatch.setattr(pair, "_call", sample)
        ready = asyncio.get_running_loop().create_future()
        pair.task = asyncio.create_task(
            pair._run("http://127.0.0.1/mcp", "test", pair.epoch, ready, 0.5)
        )
        actions = []
        try:
            await asyncio.wait_for(sleeping.wait(), 1)
            actions.append(asyncio.create_task(pair.action("set_breakpoint_here")))
            await asyncio.sleep(0)
            assert pair.queue.qsize() == 1
            await asyncio.wait_for(pair.unpair(), 1)
            with pytest.raises(ValueError, match="before action was sent"):
                await actions[0]
            assert pair.state == {"paired": False}
            assert pair.queue.empty()
            assert clock.retries == [1]
            assert len(connections) == 1
        finally:
            await pair.unpair()
            for action in actions:
                action.cancel()
            await asyncio.gather(*actions, return_exceptions=True)

    asyncio.run(check())

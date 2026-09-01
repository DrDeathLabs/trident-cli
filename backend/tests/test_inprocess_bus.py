"""In-process event bus — desktop mode's Redis-pub/sub replacement. Proves
publish/subscribe works, multiple subscribers each get their own copy, and a
publish from a worker thread (the real usage pattern — scans run via
asyncio.to_thread) safely reaches a queue owned by the event-loop thread."""

from __future__ import annotations

import asyncio
import threading

import pytest

from trident.events import inprocess_bus as bus


@pytest.fixture(autouse=True)
def _reset_bus_state():
    bus._subscribers.clear()
    bus._main_loop = None
    yield
    bus._subscribers.clear()
    bus._main_loop = None


@pytest.mark.asyncio
async def test_publish_reaches_subscriber():
    bus.set_main_loop(asyncio.get_running_loop())
    q = bus.subscribe("job1")
    bus.publish("job1", {"type": "tool.complete"})
    msg = await asyncio.wait_for(q.get(), timeout=1)
    assert msg == {"type": "tool.complete"}


@pytest.mark.asyncio
async def test_publish_with_no_subscribers_does_not_raise():
    bus.set_main_loop(asyncio.get_running_loop())
    bus.publish("no-such-job", {"type": "x"})  # must be a no-op, not an error


@pytest.mark.asyncio
async def test_multiple_subscribers_each_get_a_copy():
    bus.set_main_loop(asyncio.get_running_loop())
    q1, q2 = bus.subscribe("job1"), bus.subscribe("job1")
    bus.publish("job1", {"type": "x"})
    m1 = await asyncio.wait_for(q1.get(), timeout=1)
    m2 = await asyncio.wait_for(q2.get(), timeout=1)
    assert m1 == m2 == {"type": "x"}


@pytest.mark.asyncio
async def test_unsubscribe_stops_delivery():
    bus.set_main_loop(asyncio.get_running_loop())
    q = bus.subscribe("job1")
    bus.unsubscribe("job1", q)
    bus.publish("job1", {"type": "x"})
    assert q.empty()
    assert "job1" not in bus._subscribers


@pytest.mark.asyncio
async def test_publish_from_worker_thread_reaches_loop_owned_queue():
    """The real usage pattern: scan bodies run in a worker thread
    (asyncio.to_thread), not the event-loop thread that owns the queue."""
    bus.set_main_loop(asyncio.get_running_loop())
    q = bus.subscribe("job1")

    def _publish_from_thread():
        bus.publish("job1", {"type": "from-thread"})

    t = threading.Thread(target=_publish_from_thread)
    t.start()
    t.join()

    msg = await asyncio.wait_for(q.get(), timeout=1)
    assert msg == {"type": "from-thread"}

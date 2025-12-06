"""
Simple Nostr Client using websockets.
"""

import asyncio
import json

import websockets
from loguru import logger

from jmcore.nostr import NostrEvent


class NostrClient:
    def __init__(self, relays: list[str]):
        self.relays = relays

    async def publish(self, event: NostrEvent) -> None:
        """
        Publish an event to all configured relays.
        """
        event_dict = event.model_dump()
        message = json.dumps(["EVENT", event_dict])

        for relay in self.relays:
            try:
                async with websockets.connect(relay) as websocket:
                    await websocket.send(message)
                    response = await websocket.recv()
                    logger.info(f"Relay {relay} response: {response}")
            except Exception as e:
                logger.error(f"Failed to publish to {relay}: {e}")

    async def query(self, filters: list[dict]) -> list[NostrEvent]:
        """
        Query relays for events matching filters.
        Returns unique events.
        """
        sub_id = f"jm-query-{int(asyncio.get_running_loop().time())}"
        req_message = json.dumps(["REQ", sub_id] + filters)

        events = {}

        for relay in self.relays:
            try:
                async with websockets.connect(relay) as websocket:
                    await websocket.send(req_message)

                    while True:
                        try:
                            response = await asyncio.wait_for(websocket.recv(), timeout=5.0)
                            msg = json.loads(response)

                            if msg[0] == "EOSE":
                                break

                            if msg[0] == "EVENT":
                                event_data = msg[2]
                                try:
                                    event = NostrEvent(**event_data)
                                    if event.verify():
                                        events[event.id] = event
                                    else:
                                        logger.warning(f"Event verification failed for {event.id}")
                                except Exception as e:
                                    logger.warning(f"Invalid event received: {e}")

                            if msg[0] == "CLOSED":
                                logger.warning(f"Subscription closed by relay: {msg}")
                                break

                        except TimeoutError:
                            logger.warning(f"Timeout waiting for events from {relay}")
                            break

                    # Close subscription
                    await websocket.send(json.dumps(["CLOSE", sub_id]))

            except Exception as e:
                logger.error(f"Failed to query {relay}: {e}")

        return list(events.values())

    async def subscribe(self, filters: list[dict], callback) -> None:
        """
        Subscribe to relays and call callback on new events.
        Runs until cancelled.
        """
        tasks = []
        for relay in self.relays:
            tasks.append(asyncio.create_task(self._subscribe_single(relay, filters, callback)))

        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _subscribe_single(self, relay: str, filters: list[dict], callback) -> None:
        logger.info(f"Subscribing to {relay}...")
        while True:
            try:
                async with websockets.connect(relay) as websocket:
                    sub_id = f"jm-sub-{int(asyncio.get_running_loop().time())}"
                    req_message = json.dumps(["REQ", sub_id] + filters)
                    await websocket.send(req_message)
                    logger.info(f"Connected and subscribed to {relay}")

                    while True:
                        response = await websocket.recv()
                        msg = json.loads(response)

                        if msg[0] == "EVENT":
                            event_data = msg[2]
                            try:
                                event = NostrEvent(**event_data)
                                if event.verify():
                                    if asyncio.iscoroutinefunction(callback):
                                        await callback(event)
                                    else:
                                        callback(event)
                                else:
                                    logger.warning(f"Event verification failed for {event.id}")
                            except Exception as e:
                                logger.warning(f"Invalid event received: {e}")

                        elif msg[0] == "EOSE":
                            logger.debug(f"EOSE received from {relay}")

                        elif msg[0] == "CLOSED":
                            logger.warning(f"Subscription closed by relay {relay}: {msg}")
                            break

            except asyncio.CancelledError:
                logger.info(f"Subscription to {relay} cancelled")
                return
            except Exception as e:
                logger.error(f"Connection to {relay} lost: {e}. Retrying in 5s...")
                await asyncio.sleep(5)

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from jmcore.nostr import NostrEvent
from jmcore.nostr_client import NostrClient

TEST_PRIV_KEY = "5c85b63076f752676735261313398c775604100657579899386d9a04a3f4e242"


@pytest.fixture
def sample_event():
    return NostrEvent.create(
        kind=1,
        content="test",
        tags=[],
        private_key_hex=TEST_PRIV_KEY,
    )


async def test_publish_success(sample_event):
    relays = ["ws://relay1.com", "ws://relay2.com"]
    client = NostrClient(relays)

    with patch("websockets.connect", new_callable=MagicMock) as mock_connect:
        mock_ws = AsyncMock()
        mock_ws.recv.return_value = json.dumps(["OK", sample_event.id, True, ""])

        mock_connect.return_value.__aenter__.return_value = mock_ws
        mock_connect.return_value.__aexit__.return_value = None

        await client.publish(sample_event)

        assert mock_connect.call_count == 2
        assert mock_ws.send.call_count == 2

        expected_msg = json.dumps(["EVENT", sample_event.model_dump()])
        mock_ws.send.assert_called_with(expected_msg)


async def test_query_success(sample_event):
    relays = ["ws://relay1.com"]
    client = NostrClient(relays)

    filters = [{"ids": [sample_event.id]}]

    with patch("websockets.connect", new_callable=MagicMock) as mock_connect:
        mock_ws = AsyncMock()

        event_msg = json.dumps(["EVENT", "subid", sample_event.model_dump()])
        eose_msg = json.dumps(["EOSE", "subid"])

        mock_ws.recv.side_effect = [event_msg, eose_msg]

        mock_connect.return_value.__aenter__.return_value = mock_ws

        events = await client.query(filters)

        assert len(events) == 1
        assert events[0].id == sample_event.id

        args, _ = mock_ws.send.call_args
        assert "CLOSE" in args[0]

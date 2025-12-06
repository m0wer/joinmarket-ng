from jmcore.models import Offer, OfferType
from jmcore.nostr import NostrEvent, OfferEventFactory

# A fixed private key for deterministic testing
# Priv: 5c85b63076f752676735261313398c775604100657579899386d9a04a3f4e242
# Pub (x-only): a131016773278c253457193d9e51921359c19315b81a2575f28c24734da2149b
TEST_PRIV_KEY = "5c85b63076f752676735261313398c775604100657579899386d9a04a3f4e242"
TEST_PUB_KEY = "e65e6c3e5c349e9ac31e03a8a6178ac4e772a0fa5d14c248516c27efc7f82de0"


def test_nostr_event_creation_and_verification():
    content = "Hello Nostr"
    tags = [["t", "test"]]
    kind = 1

    event = NostrEvent.create(kind=kind, content=content, tags=tags, private_key_hex=TEST_PRIV_KEY)

    assert event.pubkey == TEST_PUB_KEY
    assert event.content == content
    assert event.kind == kind
    assert event.tags == tags
    assert event.verify() is True


def test_nostr_event_invalid_signature():
    event = NostrEvent.create(kind=1, content="test", tags=[], private_key_hex=TEST_PRIV_KEY)

    # Tamper with content
    event.content = "modified content"
    assert event.verify() is False


def test_offer_event_factory():
    offer = Offer(
        counterparty="test_counterparty",
        oid=123,
        ordertype=OfferType.SW0_ABSOLUTE,
        minsize=1000,
        maxsize=10000,
        txfee=100,
        cjfee=500,
        fidelity_bond_value=1000000,
    )

    event = OfferEventFactory.create_offer_event(offer, TEST_PRIV_KEY)

    assert event.kind == OfferEventFactory.KIND_JM_OFFER
    assert event.pubkey == TEST_PUB_KEY
    assert event.verify() is True

    # Check if offer can be reconstructed
    parsed_offer = Offer.model_validate_json(event.content)
    assert parsed_offer == offer

    # Check tags
    tag_map = {t[0]: t[1] for t in event.tags}
    assert tag_map["d"] == f"offer-{offer.oid}"
    assert tag_map["t"] == "joinmarket-offer"
    assert tag_map["v"] == str(offer.fidelity_bond_value)

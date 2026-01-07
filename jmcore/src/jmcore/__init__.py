"""
jmcore - Core library for JoinMarket components

Provides shared functionality for protocol, crypto, and networking.
"""

__version__ = "2.2.0"

# Bitcoin utilities - consolidated from multiple modules
from jmcore.bitcoin import (
    ParsedTransaction,
    TxInput,
    TxOutput,
    address_to_scriptpubkey,
    create_p2wpkh_script_code,
    decode_varint,
    encode_varint,
    get_hrp,
    get_txid,
    hash160,
    hash256,
    parse_transaction,
    pubkey_to_p2wpkh_address,
    pubkey_to_p2wpkh_script,
    script_to_p2wsh_address,
    script_to_p2wsh_scriptpubkey,
    scriptpubkey_to_address,
    serialize_outpoint,
    serialize_transaction,
    sha256,
)
from jmcore.commitment_blacklist import (
    CommitmentBlacklist,
    add_commitment,
    check_and_add_commitment,
    check_commitment,
    get_blacklist,
    set_blacklist_path,
)
from jmcore.config import (
    BackendConfig,
    DirectoryServerConfig,
    TorConfig,
    TorControlConfig,
    WalletConfig,
)
from jmcore.constants import (
    BITCOIN_DUST_THRESHOLD,
    DEFAULT_DUST_THRESHOLD,
    DUST_THRESHOLD,
    STANDARD_DUST_LIMIT,
)
from jmcore.deduplication import (
    DeduplicationStats,
    MessageDeduplicator,
    ResponseDeduplicator,
)
from jmcore.directory_client import DirectoryClient, DirectoryClientError
from jmcore.encryption import CryptoSession, NaclError
from jmcore.models import (
    DIRECTORY_NODES_MAINNET,
    DIRECTORY_NODES_SIGNET,
    DIRECTORY_NODES_TESTNET,
    MessageEnvelope,
    PeerInfo,
    get_default_directory_nodes,
)
from jmcore.paths import get_commitment_blacklist_path, get_default_data_dir
from jmcore.podle import (
    PoDLECommitment,
    PoDLEError,
    deserialize_revelation,
    generate_podle,
    parse_podle_revelation,
    serialize_revelation,
    verify_podle,
)
from jmcore.protocol import (
    FEATURE_NEUTRINO_COMPAT,
    FEATURE_PUSH_ENCRYPTED,
    JM_VERSION,
    JM_VERSION_MIN,
    FeatureSet,
    MessageType,
    ProtocolMessage,
    RequiredFeatures,
    UTXOMetadata,
    format_utxo_list,
    get_nick_version,
    parse_utxo_list,
    peer_supports_neutrino_compat,
)
from jmcore.rate_limiter import RateLimiter, TokenBucket
from jmcore.timenumber import (
    TIMELOCK_EPOCH,
    TIMELOCK_EPOCH_TIMESTAMP,
    TIMELOCK_EPOCH_YEAR,
    TIMELOCK_ERA_YEARS,
    TIMENUMBER_COUNT,
    format_locktime_date,
    get_all_locktimes,
    get_all_timenumbers,
    get_future_locktimes,
    get_nearest_valid_locktime,
    is_valid_locktime,
    parse_locktime_date,
    timenumber_to_timestamp,
    timestamp_to_timenumber,
    validate_locktime,
)
from jmcore.tor_control import (
    EphemeralHiddenService,
    TorAuthenticationError,
    TorControlClient,
    TorControlError,
    TorHiddenServiceError,
)

__all__ = [
    # Constants
    "BITCOIN_DUST_THRESHOLD",
    "DEFAULT_DUST_THRESHOLD",
    "DUST_THRESHOLD",
    "STANDARD_DUST_LIMIT",
    # Deduplication
    "DeduplicationStats",
    "MessageDeduplicator",
    "ResponseDeduplicator",
    # Config
    "BackendConfig",
    "DirectoryServerConfig",
    "TorConfig",
    "TorControlConfig",
    "WalletConfig",
    # Commitment blacklist
    "CommitmentBlacklist",
    "add_commitment",
    "check_and_add_commitment",
    "check_commitment",
    "get_blacklist",
    "set_blacklist_path",
    # Encryption
    "CryptoSession",
    "NaclError",
    # Directory
    "DIRECTORY_NODES_MAINNET",
    "DIRECTORY_NODES_SIGNET",
    "DIRECTORY_NODES_TESTNET",
    "DirectoryClient",
    "DirectoryClientError",
    "get_default_directory_nodes",
    # Models
    "MessageEnvelope",
    "PeerInfo",
    # Paths
    "get_commitment_blacklist_path",
    "get_default_data_dir",
    # PoDLE
    "PoDLECommitment",
    "PoDLEError",
    "deserialize_revelation",
    "generate_podle",
    "parse_podle_revelation",
    "serialize_revelation",
    "verify_podle",
    # Protocol
    "FEATURE_NEUTRINO_COMPAT",
    "FEATURE_PUSH_ENCRYPTED",
    "FeatureSet",
    "JM_VERSION",
    "JM_VERSION_MIN",
    "MessageType",
    "ProtocolMessage",
    "RequiredFeatures",
    "UTXOMetadata",
    "format_utxo_list",
    "get_nick_version",
    "parse_utxo_list",
    "peer_supports_neutrino_compat",
    # Rate limiting
    "RateLimiter",
    "TokenBucket",
    # Tor
    "EphemeralHiddenService",
    "TorAuthenticationError",
    "TorControlClient",
    "TorControlError",
    "TorHiddenServiceError",
    # Timenumber (fidelity bonds)
    "TIMENUMBER_COUNT",
    "TIMELOCK_EPOCH",
    "TIMELOCK_EPOCH_TIMESTAMP",
    "TIMELOCK_EPOCH_YEAR",
    "TIMELOCK_ERA_YEARS",
    "format_locktime_date",
    "get_all_locktimes",
    "get_all_timenumbers",
    "get_future_locktimes",
    "get_nearest_valid_locktime",
    "is_valid_locktime",
    "parse_locktime_date",
    "timenumber_to_timestamp",
    "timestamp_to_timenumber",
    "validate_locktime",
    # Bitcoin utilities (consolidated)
    "ParsedTransaction",
    "TxInput",
    "TxOutput",
    "address_to_scriptpubkey",
    "create_p2wpkh_script_code",
    "decode_varint",
    "encode_varint",
    "get_hrp",
    "get_txid",
    "hash160",
    "hash256",
    "parse_transaction",
    "pubkey_to_p2wpkh_address",
    "pubkey_to_p2wpkh_script",
    "script_to_p2wsh_address",
    "script_to_p2wsh_scriptpubkey",
    "scriptpubkey_to_address",
    "serialize_outpoint",
    "serialize_transaction",
    "sha256",
]

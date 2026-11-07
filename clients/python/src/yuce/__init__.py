"""A thin Python client of the YuCe audit server (`sbgk audit-serve`). Standard library only."""
from .client import FORBIDDEN, UNAUTHORIZED, Client, ConnectionClosed, RpcError, YuceError, claim, observe

__version__ = "0.1.7"
__all__ = ["Client", "ConnectionClosed", "FORBIDDEN", "RpcError", "UNAUTHORIZED", "YuceError", "claim", "observe"]

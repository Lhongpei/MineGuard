"""Independent enterprise reporting assistant.

This package deliberately has no import-time or runtime dependency on the
regulatory platform.  Its only integration boundary is a versioned JSON/HTTP
contract.
"""

from .models import DRAFT_SCHEMA_VERSION, SUBMISSION_SCHEMA_VERSION

__all__ = ["DRAFT_SCHEMA_VERSION", "SUBMISSION_SCHEMA_VERSION"]
__version__ = "0.1.0"

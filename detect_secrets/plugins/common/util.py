try:
    from functools import lru_cache
except ImportError:  # pragma: no cover
    from functools32 import lru_cache

# These plugins need to be imported here so that globals()
# can find them.
from ..artifactory import ArtifactoryDetector               # noqa: F401
from ..aws import AWSKeyDetector                            # noqa: F401
from ..base import BasePlugin
from ..basic_auth import BasicAuthDetector                  # noqa: F401
from ..high_entropy_strings import Base64HighEntropyString  # noqa: F401
from ..high_entropy_strings import HexHighEntropyString     # noqa: F401
from ..keyword import KeywordDetector                       # noqa: F401
from ..private_key import PrivateKeyDetector                # noqa: F401
from ..slack import SlackDetector                           # noqa: F401
from ..stripe import StripeDetector                         # noqa: F401


@lru_cache(maxsize=1)
def get_mapping_from_secret_type_to_class_name():
    """Returns secret_type => plugin classname"""
    mapping = {}
    for key, value in globals().items():
        try:
            if issubclass(value, BasePlugin) and value != BasePlugin:
                mapping[value.secret_type] = key
        except TypeError:
            pass

    return mapping

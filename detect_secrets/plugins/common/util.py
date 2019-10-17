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
from ..box import BoxDetector                               # noqa: F401
from ..cloudant import CloudantDetector                     # noqa: F401
from ..db2 import DB2Detector                               # noqa: F401
from ..high_entropy_strings import Base64HighEntropyString  # noqa: F401
from ..high_entropy_strings import HexHighEntropyString     # noqa: F401
from ..ibm_cloud_iam import IBMCloudIAMDetector             # noqa: F401
from ..ibm_cos_hmac import IBMCosHmacDetector               # noqa: F401
from ..keyword import KeywordDetector                       # noqa: F401
from ..private_key import PrivateKeyDetector                # noqa: F401
from ..slack import SlackDetector                           # noqa: F401
from ..stripe import StripeDetector                         # noqa: F401


@lru_cache(maxsize=1)
def get_mapping_from_secret_type_to_class_name():
    """Returns secret_type => plugin classname"""
    return {
        plugin.secret_type: name
        for name, plugin in import_plugins().items()
    }


@lru_cache(maxsize=1)
def import_plugins():
    """
    :rtype: Dict[str, Type[TypeVar('Plugin', bound=BasePlugin)]]
    """
    modules = []
    for root, _, files in os.walk(
        os.path.join(get_root_directory(), 'detect_secrets/plugins'),
    ):
        for filename in files:
            if not filename.startswith('_'):
                modules.append(os.path.splitext(filename)[0])

        # Only want to import top level files
        break

    plugins = {}
    for module_name in modules:
        module = import_module('detect_secrets.plugins.{}'.format(module_name))
        for name in filter(lambda x: not x.startswith('_'), dir(module)):
            plugin = getattr(module, name)
            try:
                if not issubclass(plugin, BasePlugin):
                    continue
            except TypeError:
                # Occurs when plugin is not a class type.
                continue

            # Use this as a heuristic to determine abstract classes
            if isinstance(plugin.secret_type, abstractproperty):
                continue

            plugins[name] = plugin

    return plugins

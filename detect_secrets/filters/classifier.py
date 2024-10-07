import logging
import string
from argparse import Namespace
from functools import lru_cache
from typing import Any
from typing import Dict
from typing import Optional
from typing import Union

from ..core.plugins import Plugin
from ..plugins.private_key import PrivateKeyDetector
from ..settings import get_settings

Pipeline = Any


logger = logging.getLogger(__name__)


def is_feature_enabled() -> bool:
    try:
        import torch
        import transformers

        print(transformers.__version__)
        print(torch.__version__)

        return True
    except Exception:
        return False


def is_feature_ready(args: Namespace) -> bool:
    try:
        temp = vars(args)
        answer = True

        entries = ['huggingface_model', 'threshold', 'huggingface_token']
        for entry in entries:
            answer = answer and temp[entry] is not None

        return answer
    except Exception:
        return False


def initialize(
        huggingface_model: str = None,
        threshold: float = 0.8,
        huggingface_token: Optional[str] = None,
) -> None:
    """
    :param limit: this limit was obtained through trial and error. Check out
        the original pull request for rationale.

    :raises: ValueError
    """
    path = huggingface_model

    get_model(huggingface_model, huggingface_token)

    config: Dict[str, Union[float, str, Optional[str]]] = {
        'threshold': threshold,
    }
    if huggingface_model:
        config['model'] = huggingface_model
        config['huggingface_token'] = huggingface_token

    path = f'{__name__}.should_exclude_secret'
    get_settings().filters[path] = config


def should_exclude_secret(secret: str, plugin: Optional[Plugin] = None) -> bool:
    """
    :param plugin: optional, for easier testing. The dependency injection system
        will populate its proper value on complete runs.
    """
    # Private keys are actual words, so they will be a false negative.
    if isinstance(plugin, PrivateKeyDetector):
        return False

    if not (set(secret) - set(string.hexdigits + '-')):
        return False

    model_name = get_settings().filters[f'{__name__}.should_exclude_secret']['model']
    token = get_settings().filters[f'{__name__}.should_exclude_secret']['huggingface_token']
    threshold = get_settings().filters[f'{__name__}.should_exclude_secret']['threshold']

    if not get_model(model_name, token):
        raise AssertionError('Attempting to use uninitialized HuggingFace model.')

    pipeline = get_model(model_name, token)
    result: Dict[str, Union[str, float]] = pipeline(secret)[0]

    return result['label'] == 'LABEL_1' and result['score'] >= threshold


@lru_cache(maxsize=1)
def get_model(model_name: str, huggingface_token: str) -> 'Pipeline':
    import torch
    from transformers import pipeline, AutoModelForSequenceClassification, AutoTokenizer

    model = AutoModelForSequenceClassification.from_pretrained(model_name, token=huggingface_token)
    model = model.share_memory()

    tokenizer = AutoTokenizer.from_pretrained(model_name, token=huggingface_token)

    if torch.cuda.is_available():
        logger.info('CUDA is available. Using GPU for Bert model.')
        return pipeline(
            'text-classification',
            model=model,
            tokenizer=tokenizer,
            device=torch.cuda.current_device(),
        )
    else:
        logger.info('CUDA is not available. Using CPU for Bert model.')
        return pipeline(
            'text-classification',
            model=model_name,
            use_auth_token=huggingface_token,
        )

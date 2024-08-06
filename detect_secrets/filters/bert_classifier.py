import logging
import string
from typing import Dict
from typing import Union
from typing import Optional

from functools import lru_cache

from transformers import Pipeline

from ..core.plugins import Plugin
from ..plugins.private_key import PrivateKeyDetector
from ..settings import get_settings

from argparse import Namespace

logger = logging.getLogger(__name__)

def is_feature_enabled() -> bool:
    try:
        import torch
        import transformers

        return True
    except Exception:
        return False
    
def is_feature_ready(args: Namespace) -> bool:
    return args.bert_model and args.bert_threshold and args.huggingface_token
    
def initialize(model_path: str = None, limit: float = 0.8, huggingface_token: Optional[str] = None) -> None:
    """
    :param limit: this limit was obtained through trial and error. Check out
        the original pull request for rationale.

    :raises: ValueError
    """
    path = model_path

    model = get_model(model_path, huggingface_token)

    config: Dict[str, Union[float, str]] = {
        'limit': limit,
    }
    if model_path:
        config['model'] = model_path
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

    if not get_model(get_settings().filters[f'{__name__}.should_exclude_secret']['model'], get_settings().filters[f'{__name__}.should_exclude_secret']['huggingface_token']):
        raise AssertionError('Attempting to use uninitialized HuggingFace model.')

    pipeline = get_model(get_settings().filters[f'{__name__}.should_exclude_secret']['model'], get_settings().filters[f'{__name__}.should_exclude_secret']['huggingface_token'])
    result = pipeline(secret)[0]

    return result['label'] == 'LABEL_1' and result['score'] >= get_settings().filters[f'{__name__}.should_exclude_secret']['limit']

@lru_cache(maxsize=1)
def get_model(model_name: str, huggingface_token: str) -> 'Pipeline':
    import torch
    from transformers import pipeline, BertForSequenceClassification, BertTokenizer

    model = BertForSequenceClassification.from_pretrained(model_name, token=huggingface_token)
    model = model.share_memory()

    tokenizer = BertTokenizer.from_pretrained(model_name, token=huggingface_token)

    if torch.cuda.is_available():
        logger.info("CUDA is available. Using GPU for Bert model.")
        return pipeline(
            'text-classification',
            model=model,
            tokenizer=tokenizer,
            device=torch.cuda.current_device(),
        )
    else:
        logger.info("CUDA is not available. Using CPU for Bert model.")
        return pipeline(
            'text-classification',
            model=model_name,
            use_auth_token=huggingface_token,
        )
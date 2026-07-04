import logging

from detect_secrets.core.log import get_logger


class TestGetLogger:
    def test_preserves_existing_named_logger_handlers(self):
        logger = logging.getLogger('detect-secrets-test-preserve-handlers')
        original_handlers = logger.handlers[:]
        original_level = logger.level
        original_propagate = logger.propagate

        handler = logging.NullHandler()
        try:
            logger.handlers = [handler]
            logger.setLevel(logging.INFO)
            logger.propagate = True

            get_logger(logger.name)

            assert logger.handlers == [handler]
            assert logger.level == logging.INFO
            assert logger.propagate is False
        finally:
            logger.handlers = original_handlers
            logger.setLevel(original_level)
            logger.propagate = original_propagate

    def test_preserves_existing_root_handlers(self):
        logger = logging.getLogger()
        original_handlers = logger.handlers[:]
        original_level = logger.level

        handler = logging.NullHandler()
        try:
            logger.handlers = [handler]
            logger.setLevel(logging.INFO)

            get_logger()

            assert logger.handlers == [handler]
            assert logger.level == logging.INFO
        finally:
            logger.handlers = original_handlers
            logger.setLevel(original_level)

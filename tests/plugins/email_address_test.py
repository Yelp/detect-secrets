import pytest
from detect_secrets.plugins.email_address import EmailAddressDetector


class TestEmailAddressDetector:
    """
    Testing strategy

    Cover the cartesian product of these partitions:

      1. Partition on email address format:
        a. Valid email addresses
        b. Invalid email addresses

      2. Partition on line content:
        a. email address is the only content
        b. email address is part of a larger string

    And cover these cases:

      1. Partition on whitelist email addresses:
        a. email address is in the whitelist
        b. email address is not in the whitelist
    """

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            # Valid email addresses, only content
            ('user@example.com', True),
            ('user.name@example.com', True),
            ('user_name@example.com', True),
            ('user-name@example.com', True),
            ('user+name@example.com', True),
            ('user@ex_ample.com', True),
            ('user@-example.com', True),
            ('user@example-.com', True),
            ('user.name+category@example.com', True),
            # Valid email addresses, part of larger string
            ('This is an email address: user@example.com', True),
            ('user@example.com is a valid email address', True),
            # Invalid email addresses
            ('user@com', False),
            ('@example.com', False),
            ('user@.com', False),
            ('user@ex..com', False),
            # Whitelist email addresses
            ('noreply@github.com', False),
            ('git@github.com', False),
            # Non-whitelist email addresses
            ('user@gmail.com', True),
            ('user@yahoo.com', True),
            ('user@hotmail.com', True),
        ],
    )
    def test_analyze_line(self, payload, should_flag):
        logic = EmailAddressDetector()

        output = logic.analyze_line(filename='mock_filename', line=payload)
        assert len(output) == int(should_flag)

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

            # Additional test cases

            # Valid email addresses with different domain extensions
            ('user@domain.co.uk', True),
            ('user@domain.io', True),
            ('user@domain.org', True),
            ('user@sub.domain.com', True),

            # Valid email addresses with numbers
            ('user123@example.com', True),
            ('123user@example.com', True),
            ('user123@123example.com', True),

            # Valid email addresses, part of larger text with special characters
            ('Contact us at: user@example.com!', True),
            ('Email: user@example.com for more info.', True),

            # Invalid email addresses with missing components
            ('user@example', False),
            ('user@.example.com', False),
            ('@example.com', False),
            ('user@', False),

            # Invalid email addresses with special characters
            ('user@exa*mple.com', False),
            ('user@examp!e.com', False),
            ('user@exampl$.com', False),
            ('user@exam^ple.com', False),

            # Unusual formats, mark as false
            ('"user"@example.com', False),  # Quoted local part
            ('user@[123.123.123.123]', False),  # IP address domain

            # Invalid email addresses, incorrect use of special characters
            ('user@exa,mple.com', False),
            ('user@examp<le.com', False),
            ('user@exampl>com', False),
            ('user@exampl;e.com', False),

            # Edge cases - rare but valid email formats
            ('user+mailbox/department=shipping@example.com', True),
            ('customer/department=shipping@example.com', True),
            ('!def!xyz%abc@example.com', True),
            ('_Yosemite.Sam@example.com', True),

            # Edge cases - position of . (dot)
            ('user@example..com', False),  # Double dot in domain
            ('.user@example.com', True),  # Leading dot in local part
            ('user@.example.com', False),  # Leading dot in domain
            ('user@example.com.', True),  # Trailing dot in domain
        ],
    )
    def test_analyze_line(self, payload, should_flag):
        logic = EmailAddressDetector()

        output = logic.analyze_line(filename='mock_filename', line=payload)
        assert len(output) == int(should_flag)

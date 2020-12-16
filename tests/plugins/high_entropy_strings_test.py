import pytest

from detect_secrets.plugins.high_entropy_strings import Base64HighEntropyString
from detect_secrets.plugins.high_entropy_strings import HexHighEntropyString
from detect_secrets.plugins.high_entropy_strings import HighEntropyStringsPlugin


@pytest.mark.parametrize(
    'plugin, non_secret, secret',
    (
        (HexHighEntropyString, 'aaaaaa', '2b00042f7481c7b056c4b410d28f33cf'),
        (
            Base64HighEntropyString,
            'c3VwZXIgc2VjcmV0IHZhbHVl',     # too short
            'c3VwZXIgbG9uZyBzdHJpbmcgc2hvdWxkIGNhdXNlIGVub3VnaCBlbnRyb3B5',
        ),

        # url-safe
        (
            Base64HighEntropyString,
            'Zrm-ySTAq7D2sHk=',     # too short
            'I6FwzQZFL9l-44nviI1F04OTmorMaVQf9GS4Oe07qxL_vNkW6CRas4Lo42vqJMT0M6riJfma_f-pTAuoX2U=',
        ),
    ),
)
class TestHighEntropyString:
    @staticmethod
    @pytest.mark.parametrize(
        'format, should_be_caught',
        (
            ("'{non_secret}'", False),
            ('"{non_secret}"', False),
            ('"{secret}"', True),
            ("'{secret}'", True),

            # Non-quoted string
            ('{secret}', False),
        ),
    )
    def test_basic(plugin, non_secret, secret, format, should_be_caught):
        # NOTE: We need to use analyze_line (rather than analyze_string) since the entropy
        # limit check lives in this function.
        results = list(
            plugin().analyze_line(
                filename='does not matter',
                line=format.format(non_secret=non_secret, secret=secret),
                line_number=0,
            ),
        )
        assert bool(results) == should_be_caught

    @staticmethod
    @pytest.mark.parametrize(
        'format, num_results',
        (
            (
                'String #1: "{non_secret}"; String #2: "{secret}"',
                1,
            ),
            (
                # We add an 'a' to make the second secret different.
                # This currently fits both hex and base64 char set.
                'String #1: "{secret}"; String #2: "{secret}a"',
                2,
            ),
        ),
    )
    def test_multiple_strings_same_line(plugin, non_secret, secret, format, num_results):
        results = list(
            plugin().analyze_line(
                filename='does not matter',
                line=format.format(non_secret=non_secret, secret=secret),
                line_number=0,
            ),
        )
        assert len(results) == num_results

    @staticmethod
    @pytest.mark.parametrize(
        'limit',
        (-1, 15),
    )
    def test_entropy_limit(plugin, non_secret, secret, limit):
        with pytest.raises(ValueError):
            plugin(limit)


class TestHexEntropyCalculation:
    @staticmethod
    @pytest.fixture
    def original_hex_detector():
        class OriginalHexHighEntropyString(HexHighEntropyString):
            def calculate_shannon_entropy(self, data):
                return HighEntropyStringsPlugin.calculate_shannon_entropy(self, data)

        return OriginalHexHighEntropyString

    @staticmethod
    def test_basic(original_hex_detector):
        value = '0123456789'
        assert (
            HexHighEntropyString().calculate_shannon_entropy(value)
            < original_hex_detector().calculate_shannon_entropy(value)
        )

        # This is the goal.
        assert HexHighEntropyString().calculate_shannon_entropy(value) < 3

    @staticmethod
    def test_length_dependency(original_hex_detector):
        assert (
            HexHighEntropyString().calculate_shannon_entropy('0123456789')
            < HexHighEntropyString().calculate_shannon_entropy('01234567890123456789')
        )

    @staticmethod
    def test_only_with_numbers(original_hex_detector):
        value = '12345a'
        assert (
            HexHighEntropyString().calculate_shannon_entropy(value)
            == original_hex_detector().calculate_shannon_entropy(value)
        )

    @staticmethod
    def test_single_case(original_hex_detector):
        value = '0'
        assert (
            HexHighEntropyString().calculate_shannon_entropy(value)
            == original_hex_detector().calculate_shannon_entropy(value)
        )

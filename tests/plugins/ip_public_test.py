import pytest

from detect_secrets.plugins.ip_public import IPPublicDetector


class TestIPPublicDetector:

    class TestIPv4:
        """
        Testing strategy

        Cover the cartesian product of these partitions:

          1. Partition on ip address format:
              a. Valid ipv4 address

          2. Partition on ip address type:
              a. Public
              b. Non-public

        And cover this case:
          1. Partition on ip address format:
              a. Invalid ipv4 address
        """

        @pytest.mark.parametrize(
            'payload, should_flag',
            [
                # Valid IPv4 addresses, Public
                ('133.133.133.133', True),
                ('This line has an IP address 133.133.133.133@something else', True),
                ('133.133.133.133:8080', True),
                ('This line has an IP address: 133.133.133.133:8080@something else', True),
                ('1.1.1.1', True),
                # Valid IPv4 addresses, Non-public
                ('127.0.0.1', False),
                ('10.0.0.1', False),
                ('172.16.0.1', False),
                ('192.168.0.1', False),
                # Invalid IPv4 addresses
                ('256.256.256.256', False),
                ('1.2.3', False),
                ('1.2.3.4.5.6', False),
                ('1.2.3.4.5.6.7.8', False),
                ('1.2.3.04', False),
                ('noreply@github.com', False),
                ('github.com', False),
            ],
        )
        def test_analyze_line(self, payload, should_flag):
            logic = IPPublicDetector()

            output = logic.analyze_line(filename='mock_filename', line=payload)
            assert len(output) == int(should_flag)

import re

from .base import RegexBasedDetector


class DB2Detector(RegexBasedDetector):

    secret_type = 'DB2 Credentials'

    begin = r'(?:(?<=\W)|(?<=^))'
    opt_quote = r'(?:"|\'|)'
    opt_db = r'(?:db2|dashdb|db|)'
    opt_dash_undrscr = r'(?:_|-|)'
    password_keyword = r'(?:password|pwd|pass|passwd)'
    opt_space = r'(?: *)'
    assignment = r'(?:=|:|:=|=>|::)'
    password = r'[a-zA-Z0-9\W]+'
    denylist = (
        re.compile(
            r'{begin}{opt_quote}{opt_db}{opt_dash_undrscr}{password_keyword}{opt_quote}{opt_space}'
            '{assignment}{opt_space}{opt_quote}{password}{opt_quote}'.format(
                begin=begin,
                opt_quote=opt_quote,
                opt_db=opt_db,
                opt_dash_undrscr=opt_dash_undrscr,
                password_keyword=password_keyword,
                opt_space=opt_space,
                assignment=assignment,
                password=password,
            ), flags=re.IGNORECASE,
        ),
    )

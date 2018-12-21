import re

WHITELIST_REGEXES = [
    re.compile(r)
    for r in [
        r'[ \t]+{} ?pragma: ?whitelist[ -]secret{}[ \t]*$'.format(start, end)
        for start, end in (
            ('#', ''),              # e.g. python
            ('//', ''),             # e.g. golang
            (r'/\*', r' ?\*/'),     # e.g. c
            ('\'', ''),             # e.g. visual basic .net
            ('--', ''),             # e.g. sql
            # many other inline comment syntaxes are not included,
            # because we want to be performant for the common case
        )
    ]
]

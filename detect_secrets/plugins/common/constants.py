import re


WHITELIST_REGEXES = [
    re.compile(r)
    for r in [
        r'[ \t]+{} *pragma: ?whitelist[ -]secret.*?{}[ \t]*$'.format(start, end)
        for start, end in (
            ('#', ''),                    # e.g. python or yaml
            ('//', ''),                   # e.g. golang
            (r'/\*', r' *\*/'),           # e.g. c
            ('\'', ''),                   # e.g. visual basic .net
            ('--', ''),                   # e.g. sql
            (r'<!--[# \t]*?', ' *?-->'),  # e.g. xml
            # many other inline comment syntaxes are not included,
            # because we want to be performant for
            # any(regex.search(line) for regex in WHITELIST_REGEXES)
            # calls. of course, this won't be a concern if detect-secrets
            # switches over to implementing file plugins for each supported
            # filetype.
        )
    ]
]

# add to this mapping (and WHITELIST_REGEXES if applicable) lazily,
# as more language specific file parsers are implemented.
# discussion: https://github.com/Yelp/detect-secrets/pull/105
WHITELIST_REGEX = {
    'yaml': WHITELIST_REGEXES[0],
}

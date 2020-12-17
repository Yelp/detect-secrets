import re

from detect_secrets.core import private_corporation as corp


ALLOWLIST_REGEXES = [
    re.compile(r)
    for r in [
        # Note: Always use allowlist, whitelist will be deprecated in the future
        r'[ \t]+{} *pragma: ?(allow|white)list[ -]secret.*?{}[ \t]*$'.format(start, end)
        for start, end in (
            ('#', ''),                    # e.g. python or yaml
            ('//', ''),                   # e.g. golang
            (r'/\*', r' *\*/'),           # e.g. c
            ('\'', ''),                   # e.g. visual basic .net
            ('--', ''),                   # e.g. sql
            (r'<!--[# \t]*?', ' *?-->'),  # e.g. xml
            # many other inline comment syntaxes are not included,
            # because we want to be performant for
            # any(regex.search(line) for regex in ALLOWLIST_REGEXES)
            # calls. of course, this won't be a concern if detect-secrets
            # switches over to implementing file plugins for each supported
            # filetype.
        )
    ]
]
ALLOWLIST_REGEXES.extend(corp.ALLOWLIST_REGEXES)

# Add to this mapping (and ALLOWLIST_REGEXES if applicable) lazily,
# as more language specific file parsers are implemented.
# Discussion: https://github.com/Yelp/detect-secrets/pull/105
ALLOWLIST_REGEX = {
    'yaml': ALLOWLIST_REGEXES[0],
}

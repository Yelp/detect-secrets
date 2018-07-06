import re

# TODO: Update for not just python comments?
WHITELIST_REGEX = re.compile(r'# ?pragma: ?whitelist[ -]secret')

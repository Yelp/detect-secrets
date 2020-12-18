from detect_secrets.core.constants import COMMON_PASSWORDS

def hide_secret(plaintext):
    hidden = '*' * len(plaintext)
    if len(plaintext) >= 8 and not is_common_secret(plaintext.lower()):
        hidden = plaintext[:3] + ('*' * len(plaintext[3:]))
    return hidden


def hide_line(hidden_secret, line, index):
    prefix = line[:index]
    suffix = line[index + len(hidden_secret):]
    return prefix + hidden_secret + suffix


def is_common_secret(plaintext):
    for common in COMMON_PASSWORDS:
        if plaintext in common:
            return True
    return False
from detect_secrets import SecretsCollection
from detect_secrets.settings import default_settings

secrets = SecretsCollection()
with default_settings():
    secrets.scan_line('XMY_KEY="AKIAY5XAIXXR7ALTOOHH"MY_SECRET="3L091LfFvV/dcoDCy5YO7sWz56bitLQjlVVY2WxmY"')


import json
print(json.dumps(secrets.json(), indent=2))
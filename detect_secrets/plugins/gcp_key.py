import re
from re import IGNORECASE
from .base import RegexBasedDetector


class GcpkeyDetector(RegexBasedDetector):

    secret_type = 'google cloud API Token'

    denylist = [
        ## API Key  reference = https://developers.google.com/workspace/guides/create-credentials?hl=pt-br#oauth-client-id
        re.compile(r'AIza[0-9a-zA-Z0-9_-]{35}'),   

        #Oauth key  
        re.compile(r'[0-9]+-[0-9A-Za-z_]{32}.apps.googleusercontent.com')
        
        ]

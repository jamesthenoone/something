import json
import requests
from bs4 import BeautifulSoup
import urllib
import re
import base64
        
post_data_str = base64.b64decode("YnRuU2lnbj1TaWduK0d1ZXN0Ym9vayZtdHhNZXNzYWdlPTEmdHh0TmFtZT1hZG1pbiZ1c2VyX3Rva2VuPTdjYzQxZjJlOTUxYjYyNTk1YWU4M2ZjZGMwZGY3ZjJh").decode('utf-8')
print(post_data_str)
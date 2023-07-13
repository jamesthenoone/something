import requests
from bs4 import BeautifulSoup
import urllib.parse
import json
import base64
import io
import sys

def extract_post_requests_b64(html):
    soup = BeautifulSoup(html, 'html.parser')
    forms = soup.find_all('form')
    post_requests = []

    for form in forms:
        action = form.get('action')
        method = form.get('method', '').upper()

        if method == 'POST':
            post_data = {}
            for input_tag in form.find_all('input'):
                input_name = input_tag.get('name')
                input_value = input_tag.get('value', '')
                if input_name:
                    post_data[input_name] = input_value

            post_data_str = urllib.parse.urlencode(post_data)
            b64_body = base64.b64encode(post_data_str.encode('utf-8')).decode('utf-8')
            
            request_info = {
                "Method": "POST",
                "URL": action,
                "b64_body": b64_body
            }
            post_requests.append(request_info)

    return post_requests

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf8')

cookies = {
'ADMINCONSOLESESSION': 'zgdCesVKymWvqvFnbCata2anMG-9iwT7SjqqwQdqVk478oFAYTjA!-936241992'
}

with open('output.txt', 'r') as f:
    urls = f.read().splitlines()

all_post_requests = set()

for url in urls:
    response = requests.get(url,cookies=cookies)
    post_requests = extract_post_requests_b64(response.text)
    for post_request in post_requests:
        post_request_json = json.dumps(post_request)
        if post_request_json not in all_post_requests:
            all_post_requests.add(post_request_json)
            with open('output_post_requests.json', 'a') as f:
                f.write(post_request_json + ',\n')

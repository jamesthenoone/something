import json
import requests
from bs4 import BeautifulSoup
import urllib
import re
import base64
import io
import sys
# Cookie: PHPSESSID=8kon5e4ov65v3kkoo75lsfcff4; security=low
sys.stdout = io.TextIOWrapper(sys.stdout.buffer,encoding='utf-8')

def load_urls(file_path):
    with open(file_path, 'r') as file:
        data = json.load(file)

    urls = []
    for entry in data:
        method = entry.get('Method')
        url = entry.get('URL')
        # 如果存在'b64_body'属性则取出，否则设为None
        b64_body = entry.get('b64_body', None)  

        urls.append({
            'method': method,
            'url': url,
            'b64_body': b64_body  # 添加'b64_body'到url数据中
        })
    return urls

def load_payloads(file_path):
    with open(file_path, 'r') as file:
        payloads = file.read().splitlines()
    return payloads

def is_xss_present(url_data, payload):
    cookies = {
    'ADMINCONSOLESESSION': 'zgdCesVKymWvqvFnbCata2anMG-9iwT7SjqqwQdqVk478oFAYTjA!-936241992'
    }

    proxies={'http':'http://127.0.0.1:8080','https':'https://127.0.0.1:8080'}

    if url_data['method'].upper() == 'GET':
        

        url_parts = list(urllib.parse.urlparse(url_data['url']))
        query = dict(urllib.parse.parse_qsl(url_parts[4]))
        # URL中没有参数的话，那肯定没有xss
        if not query:
            return False
        for key in query.keys():
            original_value = query[key]
            query[key] = payload
            url_parts[4] = urllib.parse.urlencode(query)
            url_with_payload = urllib.parse.urlunparse(url_parts)
            query[key] = original_value  # restore original value for next iteration

            response = requests.get(url_with_payload,cookies=cookies)
            soup = BeautifulSoup(response.text, 'html.parser')
            # print(soup)
            if payload in soup.prettify():
                return True
    elif url_data['method'].upper() == 'POST':
        # Similar logic can be implemented for POST requests, 
        # but it depends on how parameters are included in the POST data
        # Decode base64 body
        post_data_str = base64.b64decode(url_data['b64_body']).decode('utf-8')
        post_data = dict(urllib.parse.parse_qsl(post_data_str))

        # If there are no parameters in the body, it's unlikely that a POST-based XSS vulnerability exists.
        if not post_data:
            return False

        # Check each parameter
        for key in post_data.keys():
            original_value = post_data[key]
            post_data[key] = payload
            # Encode the post data
            post_data_encoded = urllib.parse.urlencode(post_data).encode('utf-8')
            # Send POST request with the payload
            response = requests.post(url_data['url'], data=post_data_encoded,cookies=cookies)
            # Create a BeautifulSoup object and check if the payload is in the response
            soup = BeautifulSoup(response.text, 'html.parser')
            # print(soup)


            if payload in soup.prettify().replace("\n", "").replace(" ", ""):
                return True
            # restore original value for next iteration
            post_data[key] = original_value  

    return False



# sys.stdout = io.TextIOWrapper(sys.stdout.buffer,encoding='utf8')
urls = load_urls('output.json')
# for url_info in urls:
#     print(url_info)
payloads = load_payloads('payload.txt')
# for payload in payloads:
#     print(payload)

for url_data in urls:
    print(url_data)
    for payload in payloads:
        # print(url_data)
        # print(payload)
        sign=is_xss_present(url_data, payload)
        print(url_data['url'],sign)


# url_data=urls[3]
# payload=payloads[0]
# print(payload)
# sign=is_xss_present(url_data, payload)
# print(url_data['url'],sign)



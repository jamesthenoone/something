import json
import requests
from bs4 import BeautifulSoup
import urllib
import re
import base64
import io
import sys
# Cookie: PHPSESSID=8kon5e4ov65v3kkoo75lsfcff4; security=low
    # PHPSESSID=kph0f3rp6r0mpelfrd7qtniqa1; security=low

def load_urls(file_path):
    with open(file_path, 'r') as file:
        data = json.load(file)

    urls = []
    for entry in data:
        method = entry.get('Method')
        url = entry.get('URL')
        headers = entry.get('Header')
        # 如果存在'b64_body'属性则取出，否则设为None
        b64_body = entry.get('b64_body', None)  

        urls.append({
            'method': method,
            'url': url,
            'headers': headers,
            'b64_body': b64_body  # 添加'b64_body'到url数据中
        })
    return urls

def load_payloads(file_path):
    with open(file_path, 'r') as file:
        payloads = file.read().splitlines()
    return payloads

def is_xss_present(url_data, payload):
    cookies = {
    'PHPSESSID': 'kph0f3rp6r0mpelfrd7qtniqa1',
    'security': 'low'
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

            # s = requests.Session()
            # s.cookies.set('PHPSESSID', '8kon5e4ov65v3kkoo75lsfcff4')  # 设置cookie
            # s.cookies.set('security', 'low')
            # response = s.get(url_with_payload, headers=url_data['headers'])
            # soup = BeautifulSoup(response.text, 'html.parser')


            response = requests.get(url_with_payload, headers=url_data['headers'],cookies=cookies)
            soup = BeautifulSoup(response.text, 'html.parser')
            # print(soup)
            if payload in soup.prettify():
                return True
    elif url_data['method'].upper() == 'POST':
        # 跟GET逻辑基本一样
        # 不过POST类型由于爬虫对body进行编码了,所以要先解码
        # 解密post body部分 base64 body
        post_data_str = base64.b64decode(url_data['b64_body']).decode('utf-8')
        post_data = dict(urllib.parse.parse_qsl(post_data_str))

        # 如果body中数据为空,那么直接返回False
        if not post_data:
            return False

        # Check each parameter
        for key in post_data.keys():
            original_value = post_data[key]
            post_data[key] = payload
            # 编码post data
            post_data_encoded = urllib.parse.urlencode(post_data).encode('utf-8')
            # 发出post请求
            response = requests.post(url_data['url'], data=post_data_encoded, headers=url_data['headers'],cookies=cookies)
            # 创建一个BeautifulSoup 对象， 检查payload是不是存在于response里面
            soup = BeautifulSoup(response.text, 'html.parser')

            if payload in soup.prettify().replace("\n", "").replace(" ", ""):
                return True
            # 把被替换的值还原
            post_data[key] = original_value  

    return False



# sys.stdout = io.TextIOWrapper(sys.stdout.buffer,encoding='utf8')
urls = load_urls('test.json')
# for url_info in urls:
#     print(url_info)
payloads = load_payloads('payload.txt')
# for payload in payloads:
#     print(payload)

for url_data in urls:
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



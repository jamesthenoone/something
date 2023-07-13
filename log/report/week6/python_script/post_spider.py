# coding:utf-8
import requests
from bs4 import BeautifulSoup
import sys
import io
import urllib.parse
import base64

def extract_post_requests(html):
    soup = BeautifulSoup(html, 'html.parser')
    forms = soup.find_all('form')
    post_requests = []

    for form in forms:
        action = form.get('action')
        method = form.get('method', '').upper()

        if method == 'POST':
            inputs = []
            for input_tag in form.find_all('input'):
                input_name = input_tag.get('name')
                # input_type = input_tag.get('type')
                input_value = input_tag.get('value')
                inputs.append((input_name, input_value))

            post_requests.append((action, inputs))

    return post_requests

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

from bs4 import BeautifulSoup
import urllib.parse

def extract_get_requests(html):
    soup = BeautifulSoup(html, 'html.parser')
    links = soup.find_all('a')
    get_requests = []

    for link in links:
        url = link.get('href')
        if url:
            url_parsed = urllib.parse.urlparse(url)
            if url_parsed.scheme and url_parsed.netloc:
                # this is a full URL
                request_info = {
                    "Method": "GET",
                    "URL": url,
                }
                get_requests.append(request_info)

    return get_requests




sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf8')

cookies = {
'ADMINCONSOLESESSION': '5QU_w4NxRos8JZy_CHbw8Rd6-6N_8K1VAAQYJWwjAtwGEtSHNNOh!995606110'
}

with open('output.txt', 'r') as f:
    urls = f.read().splitlines()

for url in urls:
    response = requests.get(url,cookies=cookies)

    print(extract_post_requests_b64(response.text))


# url = "http://127.0.0.1:7001/console/console.portal?_nfpb=true&_pageLabel=DomainBatchJobsPage&DomainBatchJobsTablePortletsortby=applicationName"
# response = requests.get(url,cookies=cookies)

# print(extract_post_requests_b64(response.text))









# print(extract_get_requests(response.text))



# soup = BeautifulSoup(response.text, 'html.parser')

# # 提取GET请求
# links = soup.find_all('a')
# get_requests = [link.get('href') for link in links]

# # 打印所有GET请求
# for request in get_requests:
#     print(request)

import json
import base64

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

        body=base64.b64decode(b64_body).decode("utf-8")
        print(body)

        # urls.append({
        #     'method': method,
        #     'url': url,
        #     'headers': headers,
        #     'b64_body': b64_body  # 添加'b64_body'到url数据中
        # })
    return urls

load_urls("output_post_requests.json")
import json
import base64
from urllib.parse import parse_qs

def decode_body(b64_body):
    decoded_body = base64.b64decode(b64_body).decode('utf-8')
    return decoded_body

def main():
    with open('output_post_requests.json', 'r') as f:
        data = json.load(f)
    post_bodies = []
    seen_parameters = set()

    for item in data:
        if item.get('Method') == 'POST':
            decoded_body = decode_body(item['b64_body'])
            param_dict = parse_qs(decoded_body)

            # 这里我们将参数名称转化为一个字符串，然后使用这个字符串来判断参数类型是否已经存在
            param_keys_str = str(sorted(list(param_dict.keys())))
            if param_keys_str not in seen_parameters:
                seen_parameters.add(param_keys_str)
                post_bodies.append({
                    'URL': item['URL'],
                    'Body': decoded_body
                })

    for post_body in post_bodies:
        print(f"URL: {post_body['URL']}")
        print(f"Body: {post_body['Body']}")
        print("----------------------")


main()
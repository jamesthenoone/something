import json

def parse_swagger(swagger_file):
    with open(swagger_file, 'r') as file:
        swagger_data = json.load(file)
    paths = swagger_data.get('paths', {})
    api_data = []

    for path, path_data in paths.items():
        for method, method_data in path_data.items():
            if method in ['get', 'post', 'put', 'delete', 'options', 'head', 'patch', 'trace']:
                api_item = {
                    'method': method,
                    'url': path,
                    'parameters': method_data.get('parameters', [])
                }
                api_data.append(api_item)

    return api_data

def write_json(api_data, json_file):
    with open(json_file, 'w') as file:
        json.dump(api_data, file, indent=4)

def main():
    swagger_file = 'swagger.json' # 替换为你的swagger文件路径
    json_file = 'api_data.json' # 替换为你想要保存的json文件路径

    api_data = parse_swagger(swagger_file)
    write_json(api_data, json_file)

main()
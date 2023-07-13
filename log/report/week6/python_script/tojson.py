import json

# 首先，我们从文件中读取所有的URL
with open('output.txt', 'r') as f:
    urls = f.read().splitlines()

# 然后，我们将每个URL转换为一个字典
data = [{'Method': 'GET', 'URL': url} for url in urls]

# 最后，我们将这些字典写入新的JSON文件
with open('output.json', 'w') as f:
    json.dump(data, f, indent=4)

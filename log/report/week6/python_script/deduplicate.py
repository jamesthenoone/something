import json

def deduplicate_requests(requests):
    request_set = set()
    for request in requests:
        request_str = json.dumps(request, sort_keys=True)
        request_set.add(request_str)
    deduplicated_requests = [json.loads(request_str) for request_str in request_set]
    return deduplicated_requests

# Assume requests is the list of requests you extracted
deduplicated_requests = deduplicate_requests(requests)

# Save the result to a JSON file
with open('requests.json', 'w') as f:
    json.dump(deduplicated_requests, f, indent=4)
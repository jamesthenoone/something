import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

cookies = {
    'ADMINCONSOLESESSION': 'zgdCesVKymWvqvFnbCata2anMG-9iwT7SjqqwQdqVk478oFAYTjA!-936241992'
}

def crawl(url):
    response = requests.get(url,cookies=cookies)
    soup = BeautifulSoup(response.text, 'lxml')
    urls = [a.get('href') for a in soup.find_all('a', href=True)]
    urls = [urljoin(url, u) for u in urls if not u.startswith('#')]
    return urls

def recursive_crawl(url, visited=None):
    if visited is None:
        visited = set()

    if url not in visited and url.startswith("http://127.0.0.1:7001/console/console.portal"):
        visited.add(url)
        with open('output.txt', 'a') as f:
            f.write(url + '\n')

        urls = crawl(url)
        for u in urls:
            recursive_crawl(u, visited)

host = "http://127.0.0.1:7001/console/console.portal?_nfpb=true&_pageLabel=DiagnosticsSummaryPage"

recursive_crawl(host)

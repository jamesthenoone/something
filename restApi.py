import time
import requests
from urllib import parse
from scrapy import Selector
# from  selenium import webdriver
# https://developer.vmware.com/apis/vsphere-automation/latest/vapi/operation-index/
url = "https://developer.vmware.com"
# domain_url = "https://developer.vmware.com/apis/vsphere-automation/latest/vapi/operation-index/"
domain_url = "https://developer.vmware.com/apis/vsphere-automation/latest/vcenter/operation-index/"
header={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.80 Safari/537.36'}
# # 这里网站会有一个反爬的情况
# # onePage_text = requests.get(domain_url).text
#
# browser = webdriver.Chrome(executable_path="D:\Chrome\Driver\chromedriver.exe")
# browser.get(domain_url)
# #time.sleep(5)
# cookies = browser.get_cookies()
# cookie_dict = {}
# for item in cookies:
#     cookie_dict[item["name"]] = item["value"]

onePage_text = requests.get(domain_url, headers=header).text
# use xpath
onePage_text_sel = Selector(text=onePage_text)

# div-api_models //*[@id="doc-content-container"]/div/div[2]
api_models = onePage_text_sel.xpath('//*[@id="doc-content-container"]/div/div[@class="clr-row"]')
print(api_models)
i = 0
for api_model in api_models:
    rest_api_url = []
    ways = []
    api_parts = api_model.xpath('./div[@class="clr-col-12"]')
    for api_part in api_parts:
        # print(i, api_part)
        api_raws = api_part.xpath('./div/div[2]/div/table/tbody/tr')
        # print(i, api_raws)
        for api_raw in api_raws:
            # api_item = api_raw.xpath('./td[1]/span/text()').extract()[0]
            api_url_test = api_raw.xpath('./td[2]/a/@href').extract()[0]
            i = i + 1
            # 获取api段地址，进行拼接
            api_url = parse.urljoin(url, api_url_test)
            print(i, api_url)
            get_api_page_text = requests.get(api_url, headers=header).text
            get_api_page_text_sel = Selector(text=get_api_page_text)
            api_path = get_api_page_text_sel.xpath('//*[@id="operation-api-path"]/text()').extract()[0]
            print(i+100, api_path)
            # "//*[@id="operation-api-path"]/text()"
            # print(i, api_item)
        # api_methods
    # "//*[@id="doc-content-container"]/div/div[30]/div[32]/div/div[2]/div/table/tbody/tr[1]/td[1]/span"
    # "//*[@id="doc-content-container"]/div/div[30]/div[32]/div/div[2]/div/table/tbody/tr[2]/td[1]/span"
    # "//*[@id="doc-content-container"]/div/div[30]/div[32]/div/div[2]/div/table/tbody/tr[3]/td[1]/span"
    # "//*[@id="doc-content-container"]/div/div[30]/div[32]/div/div[2]/div/table/tbody/tr[4]/td[1]/span"
    #
    # "//*[@id="doc-content-container"]/div/div[31]/div[3]/div/div[2]/div/table/tbody/tr[1]/td[1]/span" - ways
    # "//*[@id="doc-content-container"]/div/div[31]/div[3]/div/div[2]/div/table/tbody/tr[1]/td[2]/a"    - url
    # "//*[@id="doc-content-container"]/div/div[31]/div[3]/div/div[2]/div/table/tbody/tr[2]/td[1]/span"
    # "//*[@id="doc-content-container"]/div/div[31]/div[3]/div/div[2]/div/table/tbody/tr[3]/td[1]/span"
    # "//*[@id="doc-content-container"]/div/div[2]/div[6]/div/div[2]/div/table/tbody/tr[1]/td[2]/a"
    # "//*[@id="doc-content-container"]/div/div[24]/div[1]/div/div[2]/div/table/tbody/tr[1]/td[1]/span"

# text2 = api_models.xpath("./div[9]/div/div[2]/div/table/tbody/tr/td[1]/span/text()").extract()[0]

# text = onePage_text_sel.xpath('//*[@id="doc-content-container"]/div/div[27]/div[9]/div/div[2]/div/table/tbody/tr/td[1]/span/text()').extract()[0]
# //*[@id="doc-content-container"]/div/div[4]/div[2]/div/div[2]/div/table/tbody/tr[2]/td[1]/span/text()
# text1 = onePage_text_sel.xpath('//*[@id="doc-content-container"]/div/div[27]/div[9]/div/div[2]/div/table/tbody/tr/td[2]/a/@href').extract()[0]

# print(onePage_text_sel)
# print(text2)
# print(api_models)
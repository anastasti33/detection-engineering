import requests
import tomllib
import sys
import os


url = "https://b6bcd8441d444584a3b4f74fa2a281e6.us-central1.gcp.cloud.es.io:9243/api/detection_engine/rules"
api_key = os.environ['ELASTIC_KEY']
changed_files = os.environ["CHANGED_FILES"]
headers = {
    'Content-Type' : 'application/json;charset=UTF-8',
    'kbn-xsrf': 'true',
    'Authorization' : 'ApiKey ' + api_key
}


data = ""

for root, dirs, files in os.walk(r"detections"):
    for file in files:
        if file in changed_files:

            data = "{\n"
            if file.endswith(".toml"):
                full_path = os.path.join(root, file)
                with open(full_path,"rb") as toml:
                    alert = tomllib.load(toml)

                    if alert['rule']['type'] == "query":
                        required_fields = ['author','description','query','type','severity','risk_score','name','threat','index','rule_id']
                    elif alert['rule']['type'] == "eql": #event correlation
                        required_fields = ['author','description','query','type','severity','risk_score','name','language','threat','index','rule_id']
                    elif alert['rule']['type'] == "threshold":
                        required_fields = ['author','description','query','type','severity','risk_score','name','threshold','threat','index','rule_id']
                    else:
                        print("Unsupported rule type found in: " + full_path)
                        break


                    for field in alert['rule']:
                        if field in required_fields:
                        
                            if type(alert['rule'][field]) == list:
                                data += "  " + "\"" + field + "\": " + str(alert['rule'][field]).replace("'","\"") + "," + "\n"
                            elif type(alert['rule'][field]) == str:
                                if field == 'description':
                                    data += "  " + "\"" + field + "\": " + "\"" + str(alert['rule'][field]).replace("\n"," ").replace("\"","\\\"").replace("\\","\\\\") + "\"" + "," + "\n"
                                else:
                                    data += "  " + "\"" + field + "\": " + "\"" + str(alert['rule'][field]).replace("\n"," ").replace("\"","\\\"") + "\"" + "," + "\n"
                            elif type(alert['rule'][field]) == int:
                                data += "  " + "\"" + field + "\": " + str(alert['rule'][field]) + "," + "\n"
                            elif type(alert['rule'][field]) == dict:
                                data += "  " + "\"" + field + "\": " + str(alert['rule'][field]).replace("'","\"") + "," + "\n"
                    data += "  \"enabled\": true\n}"


            rule_id = alert['rule']['rule_id']
            updated_url = url + "?rule_id=" + rule_id
       
            elastic_data = requests.put(updated_url, headers=headers, data=data).json()

            for key in elastic_data:
                if key == "status_code":
                    if 404 == elastic_data["status_code"]:
                        elastic_data = requests.post(url, headers=headers, data=data).json()
                        
        
import tomllib
import sys
import os

for root, dirs, files in os.walk(r"detections"):
    for file in files:
        if file.endswith(".toml"):
            full_path = os.path.join(root, file)
            with open(full_path,"rb") as toml:
                alert = tomllib.load(toml)
                #print(alert)



#file = "alert_example.toml"

                present_fields = []
                missing_fields = []

                if alert['rule']['type'] == "query":
                    required_fields = ['description','query','type','severity','risk_score','name','rule_id']
                elif alert['rule']['type'] == "eql": #event correlation
                    required_fields = ['description','query','type','severity','risk_score','name','language','rule_id']
                elif alert['rule']['type'] == "threshold":
                    required_fields = ['description','query','type','severity','risk_score','name','threshold','rule_id']
                else:
                    print("Unsupported rule type found in: " + full_path)
                    break

                for table in alert:
                    for field in alert[table]:
                        present_fields.append(field)

                for field in required_fields:
                    if field not in present_fields:
                        missing_fields.append(field)


                if missing_fields:
                    print("The following fields are missing in " + file + ": " + str(missing_fields))
                else:
                    print("Validation Passed for: "+ file)
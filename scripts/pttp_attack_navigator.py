import copy
import json 
import csv



class pttp_attack_navigator():
    """
    The Class PTTP_attack_navigator is meant to 
    """
    def __init__(self, name, attack_version, navigator_version):
        self.name = name
        self.json = copy.deepcopy(self.navigator_json_blob())
        self.attack_version = attack_version
        self.json["name"] = self.name
        self.json["versions"]["attack"] = attack_version
        self.navigator_version = navigator_version
        self.json["versions"]["navigator"] = navigator_version

    def add_ttp(self, tcode, score, comments):
        if self.check_for_ttp(tcode):
            for ttp in self.json["techniques"]:
                if tcode == ttp["techniqueID"]:
                    ttp["score"] = int(ttp["score"]) + int(score)
                    if ttp["comment"]:
                        ttp["comment"] = ttp["comment"] + "\n" + comments
        else:
            ttp={ 'color': '',  'enabled': True, 'metadata': [], 'links': [], 'showSubtechniques': True}
            ttp["techniqueID"] = tcode.upper()
            ttp["score"] = int(score)
            ttp["comment"] = comments
            self.json["techniques"].append(ttp)

    def check_for_ttp(self, tcode): 
        for ttp in self.json["techniques"]:
            if tcode == ttp["techniqueID"]:
                return True
        return False

    def edit_ttp(self, tcode, field, value,):
        """
        Allows changing of an arbitrary field to inputed value
        """

        for ttp in self.json["techniques"]:
            if ttp["techniqueID"] == tcode:
                ttp[field] = value

    def write_to_file(self, path):
        with open(path, "w") as file:
            file.write(json.dumps(self.json))

    def add_scores_from_layer(self, input_layer):
        """adds the scores from an input json to the object's json"""
        processed_ttps=[] # uses a list to avoid adding duplicates 
        # first loop through increases score of already existing ttps 
        for input_ttp in input_layer["techniques"]:
            for ttp in self.json["techniques"]:
                if ttp["techniqueID"] == input_ttp["techniqueID"]:
                    ttp["score"] = int(ttp["score"]) + int(input_ttp["score"])
                    ttp["comment"] = ttp["comment"] + input_ttp["comment"]
                    processed_ttps.append(ttp["techniqueID"]) 
        for input_ttp in input_layer["techniques"]: # adds the ttps that were 
            if input_ttp["techniqueID"] not in processed_ttps:
                self.json["techniques"].append(input_ttp)
        
    def print_json(self):
        return self.json

    def navigator_json_blob(self):
        JSON_BLOB = {

        "name": "",
        "versions": {
        "attack": "",
        "navigator": "",
        "layer": "4.5"
        },
        "domain": "enterprise-attack",
        "description": "",
        "filters": {
        "platforms": [
        "Windows",
        "Linux",
        "macOS",
        "Network",
        "PRE",
        "Containers",
        "Office 365",
        "SaaS",
        "Google Workspace",
        "IaaS",
        "Azure AD"
        ]
        },
        "sorting": 3,
        "layout": {
        "layout": "flat",
        "aggregateFunction": "average",
        "showID": True,
        "showName": True,
        "showAggregateScores": True,
        "countUnscored": False,
        "expandedSubtechniques": "none"
        },
        "hideDisabled": False,
        "techniques": [

        ],
        "gradient": {
        "colors": [
        '#ffffff00',
        '#f20707'
        ],
        "minValue": 0,
        "maxValue": 70
        },
        "legendItems": [],
        "metadata": [],
        "links": [],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False
        }
    # seperating this into another function so I can collapse it in IDE easier
        return JSON_BLOB


    def load_from_csv(self, input_csv):
        field_names=["tcode", "score", "comments"]
        return_list=[]
        with open(input_csv, "r") as csvfile:
            reader = csv.DictReader(csvfile, fieldnames=field_names)
            for row in reader:
                if row["tcode"] != "tcode":
                    return_list.append(row)
        return return_list

    def write_navigator_to_file(self, input_file_path):
        with open(input_file_path, "w") as file:
            file.write(json.dumps(self.json))


    def make_navigator_from_csv(self, input_csv, name="", attack_version="", navigator_version=""):
        if name:
            self.name = name 
            self.json["name"] = self.name
        if attack_version:
            self.attack_version = attack_version
            self.json["versions"]["attack"] = attack_version
        if navigator_version:
            self.navigator_version = navigator_version
            self.json["versions"]["navigator"] = navigator_version
        ttp_list = self.load_from_csv(input_csv)
        for row in ttp_list:
            self.add_ttp(row["tcode"].upper(), row["score"], row["comments"])

    def print(self):
        print(self.json)


# test_class=pttp_attack_navigator("test", 1, 1)
# test_class2=pttp_attack_navigator("test", 1, 1)
# test_class.add_ttp("T1", 1, "")
# test_class.add_ttp("T2", 2, "")
# test_class.add_ttp("T1", 1, "")
# test_class2.add_ttp("T1", 1, "")
# test_class2.add_ttp("T2", 2, "")
# test_class2.add_ttp("T4", 1, "")
# test_class.add_scores_from_layer(test_class2.print_json())
# test_class.print()
# test_csv_read=pttp_attack_navigator("test", 1, 1)

# test_csv_read.make_navigator_from_csv("./inputs/stellar_example.csv")
# test_csv_read.print()
import json 
from pttp_attack_navigator import pttp_attack_navigator
# yello #eeda08
# green #40ff03
# red #fb2005

def read_json(json_file):
    with open(json_file, "r") as file:
        file_contents = file.read()
    return json.loads(file_contents)

detections_json = read_json("/home/kswagler/Programs/gitlab/ti/tooling/pttp_tools/PriorityTTP_generator/outputs/stellars_detections.json")
ta_ttp_json = read_json("/home/kswagler/Programs/gitlab/ti/tooling/pttp_tools/PriorityTTP_generator/manual_outputs/pta_ttps.json")
new_navigator=pttp_attack_navigator("Detection Priorities", "16", "5")


already_done_det=[]
already_done_ta=[]
already_done_join=[]

for detect_ttp in detections_json["techniques"]:
    if detect_ttp not in already_done_det:
        already_done_det.append(detect_ttp["techniqueID"])
        new_navigator.add_ttp(detect_ttp["techniqueID"], 0, "")
        new_navigator.edit_ttp(detect_ttp["techniqueID"], "color", "#40ff03")

for ta_ttp in ta_ttp_json["techniques"]:
    if ta_ttp not in already_done_ta:
        already_done_ta.append(ta_ttp["techniqueID"])
        new_navigator.add_ttp(ta_ttp["techniqueID"], 0, "")
        new_navigator.edit_ttp(ta_ttp["techniqueID"], "color", "#fb2005")

for detect_ttp in detections_json["techniques"]:
    for ta_ttp in ta_ttp_json["techniques"]:
        if detect_ttp["techniqueID"] not in already_done_det and ta_ttp not in already_done_ta and detect_ttp["techniqueID"] == ta_ttp["techniqueID"]  :
            already_done_join.append(ta_ttp["techniqueID"])
            new_navigator.add_ttp(ta_ttp["techniqueID"], 0, "")
            new_navigator.edit_ttp(ta_ttp["techniqueID"], "color", "#0743f2")

new_navigator.write_to_file("./outputs/detection_diff.json")
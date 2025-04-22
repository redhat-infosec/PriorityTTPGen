import requests
import json
from pathlib import Path 
from helper import get_os_type
from helper import get_project_base_path
from pttp_attack_navigator import pttp_attack_navigator
from pttp_markdown_report import pttp_markdown_report



# retrives the location where the script is running the retrieve 
base_path = get_project_base_path()
detections_csv=base_path+"/inputs/stellars_detections.csv"
output_path=base_path+"/outputs/stellars_detections.json"
markdown_header_file=base_path+"/inputs/markdown_report_template.md"
stellar_pttps=base_path+"/inputs/stellar's_priority_ttps.json"
threat_actor_pir_map=base_path+"/inputs/threatactor_pir_map.csv"
markdown_report=base_path+"/products/stellar_pttp_report.md"
detection_layer=pttp_attack_navigator("Stellar's Detections", "16", "5.1.0")
detection_layer.make_navigator_from_csv(detections_csv)
detection_layer.write_navigator_to_file(output_path)
stellar_markdown_report=pttp_markdown_report(markdown_header_file, 25, stellar_pttps, threat_actor_pir_map, markdown_report, "Stellar Electric", base_path+"/outputs/stellar_Logo_copped.png")

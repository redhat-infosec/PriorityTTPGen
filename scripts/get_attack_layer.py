import requests
import json
from pathlib import Path 
import os
from helper import get_os_type
from helper import get_project_base_path



def check_and_download_attack_data(base_path, attack_url):
    """
    Checks if the required ATT&CK data exists and if not downloads it
    """
    attack_path=base_path+"/resources/attack_data.json"
    if os.path.exists(attack_path):
        check_attack_data_is_latest(attack_path, attack_url)
    else:
        download_and_write_attack_data(base_path, attack_url)

        

def download_and_write_attack_data(base_path, attack_url):
    # downloads and writes the data from attack_url var to base_path var
    with open(attack_path, "w") as file:
        file.write(download_attack_data(attack_url))


def check_attack_data_is_latest(local_path, attack_url):
    """
    Checks that the attack data on disk is latest and if there is a difference pulls the 
    remote version which is assumed to be latest 
    """
    local_copy = parse_attack(local_path)
    local_version = local_copy["id"]
    remote_version = json.loads(download_attack_data(attack_url))["id"]
    if local_version == remote_version:
        return True
    else:
        os.remove(local_path)
        download_and_write_attack_data(local_path, attack_url)

def download_attack_data(attack_url):
    response = requests.get(attack_url)
    return str(response.text)


def parse_attack(local_path):
    with open(local_path, "r") as file:
        file_contents = file.read()
    return json.loads(file_contents)


def main():
    project_base_path = get_project_base_path()
    attack_json_url="https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    check_and_download_attack_data(project_base_path, attack_json_url)
    



main()
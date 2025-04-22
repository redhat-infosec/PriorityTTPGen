from mitreattack.stix20 import MitreAttackData
import requests
import json
import copy
import csv
from bs4 import BeautifulSoup
import time
import re
import get_attack_layer
from helper import get_project_base_path

class pttp_markdown_report():
    """
    The Class PTTP Markdown Report is meant to easily generate a Priority TTP report from an input ATT&CK Navigator layer

    """
    def __init__(self, header_file, ttp_limit, input_layer, input_pir_ta_map, output_file, org_name="", logo_photo_path=""):
        self = self 
        get_attack_layer.main()
        mitre_attack_data_path=get_project_base_path()+"/resources/attack_data.json"
        mitre_attack_data=MitreAttackData(mitre_attack_data_path)
        self.header = self.get_header_template(header_file)
        if org_name:
            self.org_name = org_name
        else: 
            self.org_name = "our"
        self.ta_list = self.get_priority_ta(input_pir_ta_map)
        self.pttp_list = self.make_ttp_ranking(input_layer, ttp_limit)
        write_string=""
        for ttp in self.pttp_list:
            ttp["reference_list"] = []
            ttp["description"], ttp["name"], ttp["ttp_url"] = self.get_ttp_detail(mitre_attack_data, ttp["tcode"])
            potential_ref_list = self.get_reference_from_technique_html(ttp["tcode"])
            for ref in potential_ref_list:
                if ref["group_alias"] in self.ta_list:
                    ttp["reference_list"].append(ref)
            ref_count=1
            for group_ref in ttp["reference_list"]:
                for ref in group_ref["ref_list"]:
                    group_ref["description"] = group_ref["description"].replace(ref["text"], "[" + str(ref_count) + "]" )
                    ref["text"] = "[" + str(ref_count) + "]"
                    ref_count=ref_count+1
            # aadds the TTP to the write_string variable which is later passed to the writing function
            write_string=write_string+self.make_ttp_markdown(ttp, mitre_attack_data)
        write_string=write_string+"\n[TLP](https://www.first.org/tlp/): Amber+Strict"
        self.markdown_body = self.update_logo_and_name(write_string, logo_photo_path)
        self.write_markdown(output_file, logo_photo_path)
        
    def write_markdown(self, file_path, logo_path):
        # Picture file does have to be in same directory as the markdown! 
        write_string = self.update_logo_and_name(self.header + self.markdown_body, logo_path)
        with open(file_path, "w") as writefile:
            writefile.write(write_string)
        
    def update_logo_and_name(self, input_markdown, logo_path):

        return_string = input_markdown.replace('{ Path to photo logo }', logo_path)
        return_string = return_string.replace('{ Place holder organization name }', self.org_name)
        return return_string

    def get_header_template(self, header_template_file): #, exclusion_dict):
        with open(header_template_file, "r") as headerfile:
            return_string=headerfile.read()
        return return_string

    def add_logo(self, logo_path):
        self.header.replace('{{ path to photo logo }}', logo_path)


    def get_priority_ta(self, ta_pir_map):
        """
        Takes in The Threat Actor PIR map file and deduplicates and extracts the TA for getting MITRE descriptions
        """
        field_names=["pir", "ta"]
        return_list=[]
        with open(ta_pir_map, "r") as csvfile:
            reader = csv.DictReader(csvfile, fieldnames=field_names)
            for row in reader:
                if row["ta"] not in return_list:
                    return_list.append(row["ta"])
        return return_list



    def get_ttp_for_ta(self, stix_id, ta_alias, mitre_object):
        return_list=[]
        priority_ta_ttp = mitre_object.get_techniques_used_by_group(stix_id)
        for i in priority_ta_ttp:
            tcode=""
            #print(i.keys())
            #print(i)
            for ii in i["object"]["external_references"]: # ["external_id"]:
                #print(ii)
                if ii["source_name"] == "mitre-attack":
                    tcode = ii["external_id"]
                    return_list.append(tcode)
        return return_list

    def get_group_page(self, group_id):
        """
        Gets the Threat Actor groups MITRE ATT&CK web page to extract TTPs and references
        It contains code for both downloading everytime and saving a file locally, due to really long request times to the MITRE page
        """
        headers= {"Accept": "*/*" } # "User-Agent": 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/111.0.0.0 Safari/537.36', }
        req_url = "https://attack.mitre.org/groups/" + group_id + "/"
        #print("Getting the mitre page for " + req_url)
        response = requests.get(req_url, headers=headers, allow_redirects=True)
        #print(response.status_code)
        # page = response.text
        # this stuff is to do a first run download because getting it every time is very slow
        file_name=group_id + ".html"
        with open(file_name, "w") as file:
            file.write(response.text)
        #
        page = load_html_file(group_id)
        soup = BeautifulSoup(page, 'html.parser')

        # print("request took " + str(request_time_end - request_time_start))
        # print("parse took " + str(parse_time_end - parse_time_start))
        return soup


    def get_description(self, input_soup):
        return_string=""
        description = input_soup.find_all("div", {"class": "description-body"})
        for i in description:
            return_string = return_string + i.text
        return return_string

    def get_citations(self, input_soup):
        return_list=[]
        citations = input_soup.find_all("span", {"class": "scite-citation"})
        for i in citations:
            return_dict={}
            return_dict["number"] =  i["id"].split("-")[1]
            return_dict["display_name"] = i.text.strip()
            return_dict["link"] = i.find("a")["href"]
        return return_dict

    def get_ttps_from_html(self, input_soup, group_name):
        ttp_table_parent = input_soup.find_all("table", {"class": "table techniques-used background table-bordered"})
        ttp_table = ttp_table_parent[0].find_all("tr")[1:]
        technique=""
        for row in ttp_table:
            ttp_ref_dict={}
            cols = row.find_all('td')
            length = len(cols)
            if cols[1].text.strip() != "":
                technique = cols[1].text.strip()
            regex_results = re.search(r"^\.\d{3}$", cols[2].text.strip())
            if regex_results:
                subtechnique = cols[2].text.strip()
                ttp_ref_dict["tcode"] = technique + subtechnique
            else:
                ttp_ref_dict["tcode"] = technique
            ttp_ref_dict["ref_text"] = cols[length-1].text.strip()
            for links in cols[length-1].find_all("a"):
                regex_results = re.search(r"\[\d+\]", links.text)
                if regex_results:
                    ttp_ref_dict["ref_url"] = links["href"]
                    #ref_id = links.text.replace("[", "").replace("]", "")
                    ttp_ref_dict["citation_number"] = links.text.replace("[", "").replace("]", "")
            return ttp_ref_dict

    def find_highest_score(self, ttp_json, ttp_list, limit): #:, exclusion_list):
        """
        This function finds the lowest score of the ttp_list list passed in. It excludes TTPs already scored.
        """
        max=0
        already_done_list=[]
        # for excluded_ttp in exclusion_list:
        #     already_done_list.append(excluded_ttp) # We want to exclude some TTPs in the rankings for a variety of reasons
        # mostly due to a lack of relevance, for example several Windows specific TTPs make the ranking
        inter_dict={}

        while len(ttp_list) < limit:
            max=0
            for technique in ttp_json["techniques"]:
            # Gets the highest score of the techniques that are not already in already_done_list
                if technique["score"] > max and technique["techniqueID"] not in already_done_list:
                    max = technique["score"]
                # print("not adding {} as a max score ".format(technique["techniqueID"]))
            for technique in ttp_json["techniques"]:
                if technique["score"] == max and technique["techniqueID"] not in already_done_list:
                    inter_dict={}
                # print("adding {} to already done list ".format(technique["techniqueID"]))
                    inter_dict["tcode"] = technique["techniqueID"]
                    inter_dict["position"] = len(ttp_list) + 1
                    inter_dict["score"] = technique["score"]
                    ttp_list.append(inter_dict)
                    already_done_list.append(inter_dict["tcode"])
                # print(already_done_list)
        return ttp_list

    def make_ttp_ranking(self, file_path, limit): # , exclusion_list):
        """
        This is the meat of the file, it takes in the ATTACK Navigator layer to be prioritized, passed as the file_path variable and ranks the TTPs
        from highest score to the lowest within the limit passed. If there is a tie, all TTPs with the score will be included, possibly
        leading to a much higher number than the limit.
        """
        with open(file_path, "r") as layerfile:
            layer_file_json = layerfile.read()
        layer_json = json.loads(layer_file_json)
        #### pickup here, loop through techniques and find the top limit specifieced
        priority_dict={}
        priority_ttp_list=[]
        #while len(priority_ttp_list) < limit:
        priority_ttp_list = (self.find_highest_score(layer_json, priority_ttp_list, limit )) # , exclusion_list))
        #print("Done! We have {} TTPs prioritizated".format(len(priority_ttp_list)))
        return priority_ttp_list



    def add_scores_from_layer(self, input_layer):
        """adds the scores from an input json to the object's json"""
        processed_ttps=[] # uses a list to avoid adding duplicates 
        # first loop through increases score of already existing ttps 
        for input_ttp in input_layer["techniques"]:
            for ttp in self.json["techniques"]:
                if ttp["techniqueID"] == input_ttp["techniqueID"]:
                    ttp["score"] = ttp["score"] + input_ttp["score"]
                    ttp["comment"] = ttp["comment"] + input_ttp["comment"]
                    processed_ttps.append(ttp["techniqueID"]) 
        for input_ttp in input_layer["techniques"]: # adds the ttps that were 
            if input_ttp["techniqueID"] not in processed_ttps:
                self.json["techniques"].append(input_ttp)
        

    def get_ttp_detail(self, mitre_attack_data, tcode):
        # for some reason it appears that there isn't any way to get a single technique
        # so looping through all is the best way to get the description
        all_ttps = mitre_attack_data.get_techniques()
        return_dict={}
        # apparently sub techniques don't have the parent technique names so we end up with results like
        # "Domains"
        # this checks for the telling period of a sub technique and then
        if "." in tcode:
            # I finally get recursion !
            parent_technique_name = self.get_ttp_detail(mitre_attack_data, tcode.split(".")[0])[1]
        for ttp in all_ttps:
            if ttp["external_references"][0]["source_name"] == "mitre-attack" and ttp["external_references"][0]["external_id"] == tcode:
                #print(ttp)
                if "." in tcode:
                    return ttp["description"], parent_technique_name + ": " + ttp["name"], ttp["external_references"][0]["url"]
                else:
                    return ttp["description"], ttp["name"], ttp["external_references"][0]["url"]


    def get_reference_from_technique_html(self, tcode):
        """
        Gets all the Procedure Examples text and and links from the TCode that is passed in as a variable and returns in a list
        """
        return_list=[]
        if "." in tcode:
            url="https://attack.mitre.org/techniques/{}/{}/".format(tcode.split(".")[0], tcode.split(".")[1])
        else:
            url="https://attack.mitre.org/techniques/{}/".format(tcode)
        response = requests.get(url)

        # Check if request was successful
        if response.status_code != 200:
            print(f"Failed to retrieve page with status code {response.status_code}")
            return None
        # Parse the webpage content using BeautifulSoup
        #soup = BeautifulSoup(response.content, 'html.parser')
        soup = BeautifulSoup(response.text, 'html.parser')
        # Find the table containing Procedure Examples
        procedure_element = soup.find('h2', {'id': 'examples'})
        # gets the next element, which should be the procedure table
        procedure_table = procedure_element.find_next("table")
        # loops through the rows in the procedure table, skipping the header
        for row in procedure_table.find_all('tr')[1:]:
            count=0
            row_dict={}
            # loops through the columns of each row and assigns values to a dict
            for col in row:
                if count == 1:
                    row_dict["mitre_groupid"] = col.text.strip()
                elif count == 3:
                    row_dict["group_alias"] = col.text.strip()
                elif count == 5:
                    row_dict["description"] = col.text.strip()
                    row_dict["ref_list"] = []
                    for link in col.find_all('a'):
                        ref_dict = {}
                        # Gets only the external references
                        if "http" in link.get('href'):
                            ref_dict["link"] = link.get('href')
                            ref_dict["text"] = link.get_text()
                            row_dict["ref_list"].append(ref_dict)
                count=count+1
            return_list.append(row_dict)
        return return_list

    def get_detection_and_data_sources(self, tcode, mitre_attack_data):
        return_text=""
        all_ttps = mitre_attack_data.get_techniques()
        for ttp in all_ttps:
            if ttp["external_references"][0]["source_name"] == "mitre-attack" and ttp["external_references"][0]["external_id"] == tcode:
                if ttp["x_mitre_data_sources"]:
                    return_text=return_text+"### Data Sources:" +"\n"
                    for data_source in ttp["x_mitre_data_sources"]:
                            return_text = return_text + "- " + data_source + "\n"
                if  ttp["x_mitre_detection"]:
                    return_text=return_text+"### Detection Suggestions:" +"\n"
                    return_text = return_text + ttp["x_mitre_detection"] + "\n"

        return(return_text)

    def get_ta_stix_id(self, threat_actor_alias, mitre_object):
        func_ta = mitre_object.get_groups_by_alias(threat_actor_alias)
        #for i in func_ta:
        #    print(i)
        for i in func_ta[0]["external_references"]:
            if i["source_name"] == "mitre-attack":
                group_mitre_name = i["external_id"]
                group_mitre_url = i["url"]
        #for i in return_json["object"]["external_references"]:
        #    print(i)
        return func_ta[0]["id"], group_mitre_name, group_mitre_url


    def make_ttp_markdown(self, ttp_dict, mitre_attack_data):
        # the ttp name and tcode with link
        ttp_markdown="### [" + ttp_dict["name"] + " (" + ttp_dict["tcode"] + ")](" + ttp_dict["ttp_url"] + ")\n"
        ttp_markdown=ttp_markdown + "#### Score: " + str(ttp_dict["score"]) +"\n"
        ttp_markdown=ttp_markdown + "#### Description:" +"\n"
        ttp_markdown=ttp_markdown + ttp_dict["description"] + "\n"
        ttp_markdown=ttp_markdown + "#### " + self.org_name + " Analysis: " + "\n"
        ttp_markdown=ttp_markdown + self.get_detection_and_data_sources(ttp_dict["tcode"], mitre_attack_data)
        ttp_markdown=ttp_markdown + "#### Examples: " + "\n"
        #get_detection_and_data_sources(ttp_dict["tcode"], mitre_attack_data_func)
        for group_ref in ttp_dict["reference_list"]:

            ref_string = "- " + group_ref["description"] + "\n"
            for ref in group_ref["ref_list"]:
                ref_text_with_link= "[" + ref["text"] + "](" + ref["link"] + ")"
                ref_string = ref_string.replace(ref["text"], ref_text_with_link)
            ttp_markdown=ttp_markdown + ref_string
        return ttp_markdown

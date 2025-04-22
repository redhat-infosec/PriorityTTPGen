import os 
import copy 



def get_os_type():
    if os.name == "posix":
        return "posix"
    elif os.name == "Windows":
        return "Windows"

def get_project_base_path():
    file_path = os.getcwd()
    os_type = get_os_type()
    if os_type == "posix":
        file_list=file_path.split("/")
        if file_list[-1] == "scripts":
            new_path=""
            for directory in file_list[:-1]:
                if directory != "":
                    new_path=new_path + "/" + directory 
        else:
            return file_path
    elif os_type == "Windows":
        file_list=file_path.split("\\")
        if file_list[-1] == "scripts":
            new_path="C:"
            for directory in file_list[:-1]:
                if directory != "":
                    new_path=new_path + "\\" + directory 
        else:
            return file_path
    return new_path


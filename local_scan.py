# Local repository scan : SAST

import os
import yaml
import pathlib
import re
import pprint

keys_table=[]
blacklisted_extensions=[]
blacklisted_paths=[]
result=[]

def walk_path(target_path):    
    for root, dirs, files in os.walk(target_path):
        path = root.split(os.sep)
        for file in files:
            if root[:-1].endswith('\\') or root[:-1].endswith('/'):
                complete_path = root + file
            else: 
                complete_path = root + "/" + file
            extension = pathlib.Path(file).suffix
            if extension in blacklisted_extensions:
                continue
            if path in blacklisted_paths:
                continue
            scan(complete_path,file,extension)

# Will scan path, filename, and extension
def scan(path,filename,extension):
    problem_checked=""
    for value in keys_table:
        case=value["part"]
        if case == "extension":
            problem_checked=extension
        elif case == "filename":
            problem_checked=filename
        elif case == "path":
            problem_checked=path
        elif case == "contents":
            internal_scan(path,value)
            continue
        else:
            print("Unknown part tested " + value["part"])
            print("Check yaml key file")
            continue
        check_if_match(path, problem_checked, value)

def check_if_match(path,problem_checked,value):
    if 'match' in value:
        if problem_checked == value["match"]:
            result.append({'path': path, 'problem_type': value["part"], 'problem_checked': value['match'], 'problem_found': value['name']})
    elif 'regex' in value:
        pattern = re.compile(value['regex'])
        if pattern.search(problem_checked) != None:
            result.append({'path': path, 'problem_type': value["part"], 'problem_checked': value['regex'], 'problem_found': value['name']})
    else:
        print("Unknown value found : " + str(value))

def internal_scan(path,value):
    with open(path, 'r') as file:
        for line in file:
            if 'regex' in value:
                pattern = re.compile(value['regex'])
                if pattern.search(line) != None:
                    result.append({'path': path, 'problem_type': value["part"], 'problem_checked': value['regex'], 'problem_found': value['name'], 'line_vulnerable' : line})
            else:
                print("Unknown value found : " + str(value))
            continue

#Display : Group vulns by files - Number By Problem-Found
def parse_results():
    print("Total number of vulnerabilities found : " + str(len(result)))
    for vuln in result:
        if vuln["problem_type"] != "contents":
            print(vuln["problem_found"] + " found in file " + vuln["path"] + " (" + vuln["problem_type"] + " problem).\n")
        else :
            print(vuln["problem_found"] + " found in file " + vuln["path"] + " at line " + vuln["line_vulnerable"] + " (" + vuln["problem_type"] + " problem).\n")

def local_scan(path):
    with open("part.yaml", 'r') as stream:
        try:
            yaml_file = yaml.safe_load(stream)
            for key, value in yaml_file.items():
                if str(key) == "signatures":
                    for v in value:
                        keys_table.append(v)
                if str(key) == "blacklisted_extensions":
                    for v in value:
                        blacklisted_extensions.append(v)
                if str(key) == "blacklisted_paths":
                    for v in value:
                        blacklisted_paths.append(v)
        except yaml.YAMLError as exc:
            print(exc)
    walk_path(path)
    parse_results()
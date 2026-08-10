import os
import yaml

index_dict = {
    "linux":"linux_os",
    "windows":"windows_os",
    "monitoring": "monitoring",
    "zeek":"monitoring"
    }

source_type_dict = {
    "auditd":"linux_audit",
    "sudo":"sudo",
    "sshd":"sshd",
    "yara":"yara",
    "suricata":"suricata",
    "conn":"zeek_conn",
    "process_creation":"WinEventLog:Microsoft-Windows-Sysmon/Operational",
    "security":"WinEventLog:Security"
}

platform_dict = {
    "linux":"Linux",
    "windows":"Windows",
    "monitoring": "Network",
    "zeek":"Network"
}

datasource_dict = {
    "auditd":"Audit",
    "sudo":"Sudo",
    "sshd":"Sshd",
    "yara":"YARA",
    "suricata":"Suricata",
    "conn":"Zeek",
    "process_creation":"Sysmon",
    "security":"Security"
}


def read_sigma_rule(filename):
    with open(filename, "r", encoding="utf-8") as sigma_file:
        data = yaml.safe_load(sigma_file)
    return data


def build_eval(file):
    eval_alert_name = f'alert_name=\"{file["title"]}\"'
    eval_rule_id = f'rule_id=\"{file["x_rule_id"]}\"'
    eval_mitre_technique = f'mitre_technique=\"{file["tags"][1].removeprefix("attack.").upper()}\"'
    eval_severity = f'severity=\"{file["level"]}\"'
    eval_sigma_id = f'sigma_id=\"{file["id"]}\"'
    eval_platform = f'platform=\"{platform_dict[file["logsource"]["product"]]}\"'
    eval_datasource = f'datasource=\"{datasource_dict[file["logsource"]["service"]]}\"'
    eval_formatted_time = f'formatted_time=strftime(_time,\"%Y-%m-%d %H:%M:%S\")'
    eval_time = f'time=_time'
    
    eval_request = "| eval " + ",\n    ".join([eval_alert_name, eval_rule_id, eval_mitre_technique, eval_severity, eval_sigma_id, eval_platform, eval_datasource, eval_formatted_time, eval_time])
    return eval_request


def list_selection(field, current_content, list_type):
    if list_type == "contains":
        field_name = field.removesuffix("|contains")
        ending = "*\""
    else:
        field_name = field.removesuffix("|endswith")
        ending = "\""
    if isinstance(current_content, list):
        list_selection = [field_name + "=\"*" + f + ending for f in current_content]
        contains_request = "(\n    "    
        contains_request += "\n    OR ".join(list_selection)
        contains_request += "\n)"
    else:
        list_selection = field_name + "=\"*" + str(current_content) + ending
        contains_request = list_selection
    return contains_request


def count_selection(condition, timeframe):
    count_by = condition.split()[2]
    threshold_operation = condition.split()[3]
    threshold = condition.split()[4]
    build_selection = "| bin _time span=" + timeframe + "\n"
    build_selection += "| stats count by "+ count_by+" _time\n"
    build_selection += "| where count " + threshold_operation + " " + threshold + "\n"
    return build_selection


def build_detection(file):
    build_selection_list = {"and": "AND",
                            "or": "OR"}
    for select in file["detection"]:
        multiple_fields = False
        if "selection" in select:          
            build_selection = ""
            for field in file["detection"][select]:
                if len(build_selection) > 1:
                    build_selection += " AND "
                    multiple_fields = True
                current_content = file["detection"][select][field]
                # case |contains
                if "|contains" in field:
                    build_selection += list_selection(field, current_content, "contains")
                # case |endswith    
                elif "|endswith" in field:
                    build_selection += list_selection(field, current_content, "endswith")
                elif "|gte" in field:
                    field_name = field.removesuffix("|gte")
                    build_selection += field_name +">=" + str(current_content)
                
                # case single field
                else:
                    build_selection += field +"=\""+ str(current_content)  + "\""
                    
            if multiple_fields:
                build_selection = "("+ build_selection + ")"
            build_selection_list[select] = build_selection

        elif "timeframe" == select:
            timeframe = file["detection"][select]

        elif "condition" == select:
            return_build_selection = ""
            conditions = file["detection"]["condition"].split("|")
            for condition in conditions:
                if "count" in condition:
                    return_build_selection += count_selection(condition, timeframe)
                else:
                    for cond in condition.split():
                        return_build_selection += build_selection_list[cond]
                        return_build_selection += "\n"
                
    return return_build_selection



def build_splunk(file):
    splunk_request = ""

    #index and logsource filter
    filter_index = f'index=\"{index_dict[file["logsource"]["product"]]}\"'
    filter_sourcetype =   f' sourcetype=\"{source_type_dict[file["logsource"]["service"]]}\"\n'
    splunk_request += filter_index
    splunk_request += filter_sourcetype
    
    # add auditd build command line
    if (file["logsource"]["service"] == "auditd"):
        filter_command_line = " type=EXECVE\n   | `auditd_command_line`\n   | search \n"
        splunk_request += filter_command_line
        
    # add detection
    splunk_request += build_detection(file)

    # add eval alert_name, rule_id, mitre_technique, severity, sigma_id
    splunk_request += build_eval(file)
    
    return splunk_request


def main():
    folder = "02-detection-engineering/03-sigma-rules/linux"
    for filename in os.listdir(folder):
        if filename.endswith((".yaml")):
            path = os.path.join(folder, filename)
            file = read_sigma_rule(path)
            try:
                splunk_request = build_splunk(file)
                print("Splunk rule for ", filename,"\n")
                print(splunk_request, 2*"\n")
            except Exception as e:
                print("The following error occured while parsing the Sigma rule")
                print("Error: ", e)
            print(40*"-")

main()







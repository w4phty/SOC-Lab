import os
import yaml
from custom_sigma2splunk import build_splunk, read_sigma_rule

def build_report(folder):
    splunk_requests = []
    for filename in os.listdir(folder):
        if filename.endswith((".yaml")):
            path = os.path.join(folder, filename)
            file = read_sigma_rule(path)
            try:
                splunk_request = build_splunk(file)
                splunk_requests.append(splunk_request)
            except Exception as e:
                print("The following error occured while parsing the Sigma rule")
                print("Error: ", e)
    
    all_requests = [splunk_requests[0]] + ["[\n    search " + request + "]" for request in splunk_requests[1:]]
    report = "\n| append\n".join(all_requests)
    
    # add eval
    eval_string = "\n| foreach alert_name rule_id severity mitre_technique platform datasource sigma_id formatted_time time hostname user event_code src_ip dest_ip dest_port executable process_name parent_executable command_line file_path hash alert_signature sourcetype [" +"\neval _raw=_raw . \"<<FIELD>>=\\\"\" . '<<FIELD>>' . \"\\\" \""+ "\n]"
    report += eval_string
    
    # add collect index
    collect_index = "\n| collect index=siem_alerts"
    report += collect_index

    
    return report
    
    


def main():
    folder_linux = "02-detection-engineering/03-sigma-rules/linux"
    #folder_windows = "02-detection-engineering/03-sigma-rules/windows"
    #folder_network = "02-detection-engineering/03-sigma-rules/network"
    for report in [folder_linux]:#[folder_linux, folder_windows, folder_network]
        print("\nreport for ", report)
        print(build_report(report))

main()

import argparse
import json
import datetime

from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC

from veracode_api_py import VeracodeAPI as vapi
from veracode_api_py.dynamic import DynUtils

def processBlockList(dast_name, url_list, scan_id, dry_run, audit):

    
    
    if(scan_id is None):
        print("Looking up App ID...")
        app_id = lookup_analysis_id(dast_name)
        if (app_id is None):
            print ("Sorry, can't find that application in your Veracode account.")
            return None

        print("Looking up Scan ID...")
        scan = lookup_scan(app_id)
        if (scan is None):
            print ("Sorry, can't find that Scan in your Veracode account.")
            return None
        if (scan == -1):
            return None
        scan_id = scan.get("scan_id")

    script_date_time = (datetime.datetime.now()).isoformat("_", "seconds").replace(":", "_")
    output_file_prefix = "audits_" + scan_id + "_" + script_date_time
    
    print("Pulling DAST Scan config...")
    scan_config = pull_dast_config(scan_id)
    if (scan_config is None):
        return None
    if (dry_run or audit):
        write_json_file(scan_config, output_file_prefix+"_original.json")
    print("Parsing input blocklist file...")
    blocklist = parse_txt_blocklist(url_list)
    if(blocklist is None or len(blocklist) == 0 ):
        print("No blocklist or blocklist empty")
        return None
    
    print("Adding blocklist urls...")
    blocklist = process_blocklist_urls(scan_config, blocklist)
    
    print("Patching local scan configuration...")
    updated_scan = patch_local_scan_config(scan_config, blocklist)
    if (dry_run or audit):
        write_json_file(updated_scan, output_file_prefix+"_patch.json")
    
    if not dry_run:
        print("Pushing scan configuration changes to API...")
        try:
            results = vapi().update_dyn_scan(scan_id, updated_scan)
            print(results)
        except Exception as e:
            print("Error trying to pull the DAST scan")
            print(e)
    
    if audit:
        print("Pulling DAST Scan config...")
        scan_config_final = pull_dast_config(scan_id)
        write_json_file(scan_config_final, output_file_prefix+"_updated.json")
    
    print("Done!")



def lookup_analysis_id(dast_name):

    data = vapi().get_analyses_by_name(dast_name)

    for app in data:
        if (app.get("name") == dast_name):
           analysis_id = app.get("analysis_id")
           print("Analysis ID is: " + analysis_id)
           return analysis_id

    return None

def lookup_scan(analysis_id):

    scans = vapi().get_analysis_scans(analysis_id)

    if len(scans) == 1:
        return scans[0]
    if len(scans) > 1:
        # Set column widths
        wcol1 = 50
        wcol2 = 50
        wcol3 = 100
        
        print("Multiple scans found, please review the list, choose the correct scan_id and run the script again using the '--scan_id' parameter")
        
        print("==================".ljust(wcol1) + "==================".ljust(wcol2) + "==================".ljust(wcol3))
        print("Scan ID".ljust(wcol1) + "Scan Name".ljust(wcol2) + "Target URL".ljust(wcol3) )
        print("==================".ljust(wcol1) + "==================".ljust(wcol2) + "==================".ljust(wcol3))
        for scan in scans:
            print(scan.get("scan_id").ljust(wcol1) +  scan.get("scan_config_name").ljust(wcol2) +  scan.get("target_url").ljust(wcol3))
        return -1

    return None
       
def pull_dast_config(scan_id):

    try:
        dast_config = vapi().get_dyn_scan_config(scan_id)
        return dast_config

    except Exception as e:
       print("Error trying to pull the DAST scan")
       return None

def parse_txt_blocklist(filename):
    blocklist = []
    f = open(filename, "r")
    for x in f:
        url = x.strip()
        if(url.startswith("http")):
            blocklist.append(url)
        else:
            print("Not url format: " + url)
    f.close()
    return blocklist
    
# TODO: Parse a Veracode CSV coverage report. 
# def parse_csv_blocklist(filename):
    
def process_blocklist_urls(scan_config, blocklist):
    #Check for existing blacklist
    blocklist_updated = scan_config["scan_setting"]["blacklist_configuration"].get("blackList")
    #prepare urls
    if(blocklist_updated is None):
        blocklist_updated = []    
    
    for url in blocklist:
        # check if url already exists in blocklist, remove http:// and https:// for better matching
        blocklist_updated_string = str(blocklist_updated).replace("https://","").replace("http://", "")
        # strip out http:// and https:// and add single quotes for exact url matches
        url_stripped = "'"+url.replace("https://","").replace("http://", "")+"'"
        if url_stripped not in blocklist_updated_string:
            blocklist_updated.append(vapi().dyn_setup_url(url))
    
    return vapi().dyn_setup_blocklist(blocklist_updated)
    
def patch_local_scan_config(scan_config, blocklist):
    # check for existing hosts
    custom_hosts = scan_config["scan_setting"].get("custom_hosts")
    if(custom_hosts is None):
        custom_hosts = []
    # check for custom user agent
    user_agent = scan_config["scan_setting"].get("user_agent")
    # update scan settings
    scan_settings_updated = vapi().dyn_setup_scan_setting(blocklist, custom_hosts, user_agent)
    
    # create new scan request
    url = scan_config.get("target_url")
    allowed_hosts = scan_config.get("allowed_hosts", [])
    auth_config = None
    authentications = None
    authentications_config = scan_config.get("auth_configuration", None)
    if(authentications_config is not None):
        authentications = authentications_config.get("authentications", None)
        auth_config = DynUtils().setup_auth_config(authentications)
    crawl_config = DynUtils().setup_crawl_configuration(scan_config["crawl_configuration"].get("scripts"), scan_config["crawl_configuration"].get("disabled"))
    
    scan_config_request = vapi().dyn_setup_scan_config_request(url, allowed_hosts, auth_config, crawl_config, scan_settings_updated)
    
    # create final payload for scan request
    scan_payload = vapi().dyn_setup_scan(scan_config_request)
    # print(scan_payload)
    return scan_payload

    
def write_json_file(json_data, filename):
    print("Writing to json file: " + filename)
    with open(filename, "w") as outfile:
        json.dump(json_data, outfile)
    outfile.close()
    
def main():

    parser = argparse.ArgumentParser(description="This script takes DAST Scan name as input and adds a list of urls to the blocklist.")
    parser.add_argument("-n", "--name", required=True, help="DAST scan name within the Veracode platform.")
    parser.add_argument("-u", "--url_list", required=True, help="Path to text list of urls to add to blocklist.")
    parser.add_argument("-s", "--scan_id", required=False, help="Unique Scan_ID")
    parser.add_argument("-d", "--dry_run", help="Will not make call to Veracode API to update DAST Scan, instead will generate original json of scan and patch json as files.", action="store_true")
    parser.add_argument("-a", "--audit", help="Generate audit files of original json of scan, updated patch json and final scan config after patch as files.", action="store_true")
    
    args = parser.parse_args()

    dast_name = args.name.strip()
    url_list = args.url_list.strip()
    dry_run = args.dry_run
    audit = args.audit
    
    scan_id = None
    if(args.scan_id != None):
        scan_id = args.scan_id.strip()
    processBlockList(dast_name, url_list, scan_id, dry_run, audit)


if __name__ == '__main__':
    main()

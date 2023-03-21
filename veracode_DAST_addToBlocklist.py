import sys
import argparse
import datetime

from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC

from veracode_api_py import VeracodeAPI as vapi

def processList(app_name):

    print("Looking up Scan ID...")
    app_id = lookup_analysis_id(app_name)
    if (app_id is None):
        print ("Sorry, can't find that application in your Veracode account.")
        return None

    print("Looking up Analysis ID...")
    scan = lookup_scan(app_id)
    if (scan is None):
        print ("Sorry, can't find that Scan in your Veracode account.")
        return None

    print("Pulling DAST Scan config...")
    scan_id = scan.get("scan_id")
    scan_config = pull_dast_config(scan_id)
    if (scan_config is None):
        return None

    print("Parsing input blocklist file...")
    blocklist = parse_txt_blocklist("blocklist.txt")
    if(blocklist is None or len(blocklist) == 0 ):
        print("No blocklist or blocklist empty")
        return None
    
    print("Adding blocklist urls...")
    blocklist = process_blocklist_urls(scan_config, blocklist)
    
    print("Patching local scan configuration...")
    patch_local_scan_config(scan_config, blocklist, scan_id)
    
    print("Pushing scan configuration changes to API...")
    
    
    print("Done!")

    # print("Building notice file...")
    # filename = build_notice_file(sbom_dict)
    # if (filename is None):
    #     return None

    # return filename


def lookup_analysis_id(app_name):

    data = vapi().get_analyses_by_name(app_name)

    for app in data:
        if (app.get("name") == app_name):
           analysis_id = app.get("analysis_id")
           print("Analysis ID is: " + analysis_id)
           return analysis_id

    return None

def lookup_scan(analysis_id):

    scans = vapi().get_analysis_scans(analysis_id)

    if len(scans) == 1:
        return scans[0]
    # TODO: Implement handling of multiple scans
    # for scan in data:
    #     if (scan.get("name") == app_name):
    #        analysis_id = scan.get("analysis_id")
    #        print("Analysis ID is: " + analysis_id)
    #        return analysis_id

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
        blocklist_updated.append(vapi().dyn_setup_url(url))
    
    return vapi().dyn_setup_blocklist(blocklist_updated)
    
def patch_local_scan_config(scan_config, blocklist, scan_id):
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
    allowed_hosts = scan_config.get("allowed_hosts")
    if(allowed_hosts is None):
        allowed_hosts = []
    auth_config = scan_config.get("auth_configuration")
    crawl_config = scan_config.get("crawl_configuration")
    scan_config_request = vapi().dyn_setup_scan_config_request(url, allowed_hosts, auth_config, crawl_config, scan_settings_updated)
    scan = vapi().get_dyn_scan(scan_id)
    # 
    scan_payload = vapi().dyn_setup_scan(scan_config_request)
    print("scan grabbed")
    
    
    
# def build_notice_file(sbom):

#     # Expected input to this function is a CycloneDX SBOM in JSON format

#     # Grab the application name from the SBOM
#     metadata = sbom["metadata"]
#     app_name = metadata["component"].get("name") 
#     if app_name is None or len(app_name)==0:
#         app_name = "APPLICATION"

#     # Truncate app name to 50 and remove chars that might cause filename issues
#     app_name_trunc = app_name[:50]
#     specials = "\"\\/:*?<>|"
#     cleaned_name = "".join(c for c in app_name_trunc if c not in specials)
#     filename = cleaned_name + "_notice.txt"

#     with open(filename, 'w') as f:

#         # Write header section
#         print("==============================================================================", file=f)
#         print("==                       OPEN SOURCE LICENSE NOTICE                         ==", file=f)
#         print("==                                                                          ==", file=f)          
#         print("==   This application uses open source software (OSS). The OSS components   ==", file=f)
#         print("==   are used in accordance wtih the terms and conditions of the license    ==", file=f)
#         print("==   under which the component is distributed. A list of components and     ==", file=f)
#         print("==   their corresponding license(s) is provided below.                      ==", file=f)
#         print("==                                                                          ==", file=f)            
#         print("==============================================================================", file=f)
#         print("", file=f)
#         print("APPLICATION NAME: " + app_name, file=f)
#         print("DATA SOURCE:      Veracode Software Composition Analysis (SCA) / SBOM API", file=f)
#         print("GENERATED:        " + (datetime.datetime.now()).strftime("%c"), file=f)
#         print("", file=f)

#         # Set column widths
#         wcol1 = 50
#         wcol2 = 25
#         wcol3 = 30
#         wcol4 = 80

#         # Write the column headers
#         print("OSS COMPONENT NAME".ljust(wcol1) + "VERSION".ljust(wcol2) + "LICENSE".ljust(wcol3) + "LICENSE REFERENCE".ljust(wcol4), file=f)
#         print("==================".ljust(wcol1) + "=======".ljust(wcol2) + "=======".ljust(wcol3) + "=================".ljust(wcol4), file=f)

#         # If SBOM has no components, write relevant message and return
#         components = sbom["components"]
        
#         if (components is None or len(components)==0):
#             print("No open source components", file=f)
#             f.close()
#             return filename

#         # Sort components by name (case insensitive)
#         components.sort(key=lambda x:x['name'].lower())

#         # Loop on all components in the SBOM
#         for c in components:
#             comp_type = c.get("type")
#             # Skip this component if not a library
#             if (comp_type != "library"):
#                 continue
#             # Get the library name and version. Truncate to column width minus 1 to keep things aligned.
#             lib_name = c.get("name") if c.get("name") else " "
#             lib_name = lib_name[:(wcol1-1)]
#             lib_ver = c.get("version") if c.get("version") else " "
#             lib_ver = lib_ver[:(wcol2-1)]
#             # Write component info
#             print(lib_name.ljust(wcol1) + lib_ver.ljust(wcol2), end="", file=f)
#             # Skip ahead if licenses element is not present
#             if "licenses" not in c.keys():
#                 print("", file=f)
#                 continue
#             licenses = c["licenses"]
#             # Skip ahead if licenses element is empty              
#             if len(licenses) == 0:
#                 print("", file=f)
#                 continue
#             # Write license info
#             count = 0
#             for l in licenses:
#                 count += 1
#                 # Note that license name in the SBOM may be under "id" or "name". Need to account for this.
#                 lic_id = l["license"].get("id")
#                 lic_name = l["license"].get("name")
#                 license_name = lic_id if lic_id is not None else lic_name
#                 license_name = license_name if license_name is not None else ""
#                 # Truncate to column width minus 1 to keep things aligned
#                 license_name = license_name[:(wcol3-1)]
#                 lic_url = l["license"].get("url")
#                 license_url = lic_url if lic_url is not None else ""
#                 # If 2 or more licenses for this component, first two columns need spaces to keep things aligned
#                 if count >= 2:
#                     print(" ".ljust(wcol1) + " ".ljust(wcol2), end="", file=f)
#                 print(license_name.ljust(wcol3) + license_url.ljust(wcol4), file=f)

#         f.close()

#     return filename

def main():

    # parser = argparse.ArgumentParser(description="This script takes DAST Scan name as input and adds a list of urls to the blocklist.")
    # parser.add_argument("-a", "--app_name", required=True, help="DAST scan name within the Veracode platform.")

    # args = parser.parse_args()

    # app_name = args.app_name.strip()
    # filename = processList(app_name)
    filename = processList("Verademo")

    if filename is not None:
        print("Success! Created file \"" + filename + "\"")


if __name__ == '__main__':
    main()

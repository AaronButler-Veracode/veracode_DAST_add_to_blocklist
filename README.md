# veracode_DAST_add_to_blocklist
Python scripts that leverage the Veracode API to automate tasks or extend capabilities of Veracode Dynamica Application Security Testing (DAST). These scripts are not officially supported by Veracode.

**Dependencies**

The following Python packages need to be installed:

* Veracode API Authentication library: [veracode-api-signing](https://pypi.org/project/veracode-api-signing/)
* Veracode API Helper library:  [veracode-api-py](https://pypi.org/project/veracode-api-py/)

**Authentication**

Option 1 - Save your Veracode API credentials in `~/.veracode/credentials` file as follows:

    [default]
    veracode_api_key_id = <YOUR_API_KEY_ID>
    veracode_api_key_secret = <YOUR_API_KEY_SECRET>

Option 2 - Save your Veracode API credentials in environment variables as follows:

    VERACODE_API_KEY_ID=<YOUR_API_KEY_ID>
    VERACODE_API_KEY_SECRET=<YOUR_API_KEY_SECRET>    

## DAST_addToBlocklist.py ##
Updates an existing DAST scan blocklist from a provided text file.

**Usage**

`DAST_addToBlocklist.py [-h] <arguments>`

Arguments:
* `-a` or `--app_name` `<APPLICATION>` - name of the DAST configuration within Veracode (required).
* `-u` or `--url_list` `<Path to Text file>` - Path to the text file containgin the list of urls to add to blocklist (required).
* `-s` or `--scan_id` `<GUID>` - scan_id can be provided to reduce number of calls to api or if app_name returns multiple scan_id's (optional)


**Example**
```
> python DAST_addToBlocklist.py --app_name "Verademo" --url_list "blocklist.txt"
```
# These scripts are examples and unsupported
#Make sure requests is installed
#Turn on EDB Tamper v1.0
import requests
import csv
import configparser
import json
# Import datetime modules
from datetime import date
from datetime import datetime
#Import OS to allow to check which OS the script is being run on
import os
today = date.today()
now = datetime.now()
timestamp = str(now.strftime("%d%m%Y_%H-%M-%S"))
# This list will hold all the sub estates
sub_estate_list = []
# This list will hold all the computers
computer_list = []

# Get Access Token - JWT in the documentation
def get_bearer_token(client, secret, url):
    d = {
                'grant_type': 'client_credentials',
                'client_id': client,
                'client_secret': secret,
                'scope': 'token'
            }
    request_token = requests.post(url, auth=(client, secret), data=d)
    json_token = request_token.json()
    #headers is used to get data from Central
    #headers = {'Authorization': str('Bearer ' + json_token['access_token'])}
    headers = {'Authorization': f"Bearer {json_token['access_token']}"}
    # post headers is used to post to Central
    post_headers = {'Authorization': f"Bearer {json_token['access_token']}",
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                    }
    return headers, post_headers

def get_whoami():
    # We now have our JWT Access Token. We now need to find out if we are a Partner or Organization
    # Partner = MSP
    # Organization = Sophos Central Enterprise Dashboard
    # The whoami URL
    whoami_url = 'https://api.central.sophos.com/whoami/v1'
    request_whoami = requests.get(whoami_url, headers=headers)
    whoami = request_whoami.json()
    # MSP or Sophos Central Enterprise Dashboard
    # We don't use this variable in this script. It returns the organization type
    check_organization_type = whoami["idType"]
    if whoami["idType"] == "partner":
        organization_Header= "X-Partner-ID"
    else:
        organization_Header = "X-Organization-ID"
    organizationID = whoami["id"]
    return organizationID, organization_Header, check_organization_type

def get_all_sub_estates(organization):
    #Add X-Organization-ID to the headers dictionary
    headers[organizationHeader] = organization
    #URL to get the list of tennants
    sub_estate_url = 'https://api.central.sophos.com/' + organizationType + '/v1/tenants?pageTotal=true'
    #Request all tenants
    request_sub_estates = requests.get(sub_estate_url, headers=headers)
    #Convert to JSON
    sub_estate_json = request_sub_estates.json()
    #Set the keys you want in the list
    #Find the number of pages we will need to search to get all the sub estates
    total_pages = sub_estate_json["pages"]["total"]
    #Paged URL https://api.central.sophos.com/organization/v1/tenants?page=2 add total pages in a loop
    sub_estate_keys = ('id', 'name', 'dataRegion')
    #Add the tenants to the sub estate list
    for all_sub_estates in sub_estate_json["items"]:
        #Make a temporary Dictionary to be added to the sub estate list
        sub_estate_dictionary = {key:value for key, value in all_sub_estates.items() if key in sub_estate_keys}
        sub_estate_list.append(sub_estate_dictionary)
    #Remove X-Organization-ID from headers dictionary. We don't need this anymore
    del headers[organizationHeader]

def get_all_computers(sub_estate_token, url, name):
    #Get all Computers from sub estates
    computers_url = url
    #Loop while the page_count is not equal to 0. We have more computers to query
    page_count = 1
    while page_count != 0:
        #Sub estate to be searched
        sub_estate_id = sub_estate_token
        #Add X-Tenant-ID to the headers dictionary
        headers['X-Tenant-ID'] = sub_estate_id
        #Add X-Tenant-ID to the post_headers dictionary
        post_headers['X-Tenant-ID'] = sub_estate_id
        #Request all Computers
        request_computers = requests.get(computers_url, headers=headers)
        if request_computers.status_code != 200:
            return
        #Convert to JSON
        computers_json = request_computers.json()
        #Set the keys you want in the list
        computer_keys = ('id', 'hostname', 'lastSeenAt', 'tamperProtectionEnabled', 'Sub Estate', 'type')        #Add the computers to the computers list
        for all_computers in computers_json["items"]:
            # Make a temporary Dictionary to be added to the sub estate list
            computer_dictionary = {key: value for key, value in all_computers.items() if key in computer_keys}
            # Sends the last seen date to get_days_since_last_seen and converts this to days
            computer_dictionary['Last_Seen'] = get_days_since_last_seen(computer_dictionary['lastSeenAt'])
            # Checks if Health have been returned
            if 'tamperProtectionEnabled' in computer_dictionary.keys():
                # Checks if Tamper is enabled
                if computer_dictionary['tamperProtectionEnabled'] == False:
                    computer_dictionary['Machine_URL'] = 'N/A'
                    computer_dictionary['Sub Estate'] = name
                    computer_list.append(computer_dictionary)
                    #Turn on Tamper and return status code. 201 successful
                    result_code = turn_on_tamper(computer_dictionary['id'], url, post_headers)
                    if result_code.status_code == 201:
                        computer_dictionary['tamperProtectionEnabled'] = 'Successful'
                    else:
                        computer_dictionary['tamperProtectionEnabled'] = 'Failed'
            #This line allows you to debug on a certain computer. Add computer name
            if 'mc-nuc-splunk' == computer_dictionary['hostname']:
                print('Add breakpoint here', computer_dictionary['hostname'])
        #Check to see if you have more than 50 machines by checking if nextKey exists
        #We need to check if we need to page through lots of computers
        if 'nextKey' in computers_json['pages']:
            next_page = computers_json['pages']['nextKey']
            # Change URL to get the next page of computers
            # Example https://api-us01.central.sophos.com/endpoint/v1/endpoints?pageFromKey=<next-key>
            computers_url = url + '?pageFromKey=' + next_page
        else:
            # If we don't get another nextKey set page_count to 0 to stop looping
            page_count = 0

def turn_on_tamper(machineID,endpoint_url,post_header):
    #print(machineID, endpoint_url)
    full_endpoint_url = f"{endpoint_url}{'/'}{machineID}{'/'}{'tamper-protection'}"
    tamper_status = {'enabled': 'true'}
    result = requests.post(full_endpoint_url,data=json.dumps(tamper_status), headers=post_header)
    return result

def get_days_since_last_seen(report_date):
    # https://www.programiz.com/python-programming/datetime/strptime
    # Converts report_date from a string into a DataTime
    convert_last_seen_to_a_date = datetime.strptime(report_date, "%Y-%m-%dT%H:%M:%S.%f%z")
    # Remove the time from convert_last_seen_to_a_date
    convert_last_seen_to_a_date = datetime.date(convert_last_seen_to_a_date)
    # Converts date to days
    days = (today - convert_last_seen_to_a_date).days
    return days

def get_threats(endpoint_url, endpoint_id):
    full_enpoint_url = endpoint_url + '/' + endpoint_id
    # https://api-{dataRegion}.central.sophos.com/endpoint/v1/endpoints/id
    request_threat = requests.get(endpoint_url, headers=headers)
    # Convert to JSON
    threat_json = request_threat.json()
    print('')

def make_valid_client_id(os, machine_id):
    # Characters to be removed
    # https://central.sophos.com/manage/server/devices/servers/b10cc611-7805-7419-e9f0-46947a4ab60e/summary
    # https://central.sophos.com/manage/endpoint/devices/computers/60b19085-7bbf-44ff-3a67-e58a3c4e14b1/summary
    Server_URL = 'https://central.sophos.com/manage/server/devices/servers/'
    Endpoint_URL = 'https://central.sophos.com/manage/endpoint/devices/computers/'
    # Remove the - from the id
    remove_characters_from_id = ['-']
    for remove_each_character in remove_characters_from_id:
        machine_id = machine_id.replace(remove_each_character, '')
    new_machine_id = list(machine_id)
    # Rotates the characters
    new_machine_id[::2], new_machine_id[1::2] = new_machine_id[1::2], new_machine_id[::2]
    for i in range(8, 28, 5):
        new_machine_id.insert(i, '-')
    new_machine_id = ''.join(new_machine_id)
    if os == 'computer':
        machine_url = Endpoint_URL + new_machine_id
    else:
        machine_url = Server_URL + new_machine_id
    return (machine_url)

def read_config():
    config = configparser.ConfigParser()
    config.read('edb_tamper_config.config')
    config.sections()
    ClientID = config['DEFAULT']['ClientID']
    ClientSecret = config['DEFAULT']['ClientSecret']
    ReportName = config['REPORT']['ReportName']
    ReportFilePath = config['REPORT']['ReportFilePath']
    #Checks if the last character of the file path contains a \ or / if not add one
    if ReportFilePath[-1].isalpha():
        if os.name != "posix":
            ReportFilePath = ReportFilePath + "\\"
        else:
            ReportFilePath = ReportFilePath + "/"
    return(ClientID,ClientSecret,ReportName,ReportFilePath)

def print_report():
    #Customise the column headers
    fieldnames = ['Machine URL', 'Sub Estate', 'Hostname', 'Type', 'Last Seen Date', 'Days Since Last Seen', 'Tamper Enabled', 'ID']
    with open(full_report_path, 'w') as f:
        writer = csv.writer(f)
        writer.writerow(fieldnames)
    #Sets the column order
    order = ['Machine_URL', 'Sub Estate', 'hostname', 'type', 'lastSeenAt', 'Last_Seen', 'tamperProtectionEnabled','id']
    with open(full_report_path, 'a+', encoding='utf-8', newline='') as output_file:
        dict_writer = csv.DictWriter(output_file, order)
        dict_writer.writerows(computer_list)

clientID, clientSecret, report_name, report_file_path = read_config()
full_report_path = f"{report_file_path}{report_name}{timestamp}{'.csv'}"

token_url = 'https://id.sophos.com/api/v2/oauth2/token'
headers, post_headers = get_bearer_token(clientID, clientSecret, token_url)
organizationID, organizationHeader, organizationType = get_whoami()
get_all_sub_estates(organizationID)
for sub_etates_in_list in range(len(sub_estate_list)):
    sub_estate = sub_estate_list[sub_etates_in_list]
    sub_estateID = sub_estate['id']
    sub_estate_name = sub_estate['name']
    sub_estate_region = sub_estate['dataRegion']
    sub_estate_region_url = f"https://api-{sub_estate_region}.central.sophos.com/endpoint/v1/endpoints"
    print (f'Checking machines in sub estate {sub_estate_name}')
    get_all_computers(sub_estateID, sub_estate_region_url, sub_estate_name)

print_report()
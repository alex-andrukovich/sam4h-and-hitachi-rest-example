#!/usr/bin/env python3
# Usage: -s 10.0.0.16 -u root -p Root1234
import requests
import urllib.parse
import argparse
from http.cookiejar import CookieJar
import logging
import functools
import urllib3
import json
import random
import string
import base64
import datetime
import time

# Suppress only the single InsecureRequestWarning from urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Create a logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
# Create handlers
file_handler = logging.FileHandler('sam4h_rest.log')  # Log to a file
stdout_handler = logging.StreamHandler()  # Log to stdout
# Create a formatter and add it to the handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
stdout_handler.setFormatter(formatter)
# Add the handlers to the logger
logger.addHandler(file_handler)
logger.addHandler(stdout_handler)
def log_decorator(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        logger.info(f'Function {fn.__name__} called with args: {args} and kwargs: {kwargs}')
        return fn(*args, **kwargs)
    return wrapper

@log_decorator
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "-sam4hserver",    dest="sam4hserver",       help="Enter sam4h server IP address")
    parser.add_argument("-u", "--sam4huser",     dest="sam4huser",         help="Enter sam4h user user name")
    parser.add_argument("-p", "--sam4hpassword", dest="sam4hpassword",     help="Enter sam4h password")
    arguments = parser.parse_args()
    if not arguments.sam4hserver:
        parser.exit("[-] Enter missing info.")
    elif not arguments.sam4huser:
        parser.exit("[-] Enter missing info.")
    elif not arguments.sam4hpassword:
        parser.exit("[-] Enter missing info.")
    return arguments


def decode_jwt_parts_return_jwt_exp_unix_time(jwt):
    jwt_exp_unix_time = None
    parts = jwt.split('.')
    if len(parts) != 3:
        raise ValueError("Invalid JWT structure")

    # Header
    header_encoded = parts[0]
    header_encoded += '=' * (4 - len(header_encoded) % 4)  # Add padding if needed
    header_decoded = base64.b64decode(header_encoded).decode('utf-8')
    header = json.loads(header_decoded)
    logger.info("Decoded Header:")
    logger.info(json.dumps(header, indent=4))

    # Payload
    payload_encoded = parts[1]
    payload_encoded += '=' * (4 - len(payload_encoded) % 4)  # Add padding if needed
    payload_decoded = base64.b64decode(payload_encoded).decode('utf-8')
    payload = json.loads(payload_decoded)
    logger.info("Decoded Payload:")
    for key, value in payload.items():
        # If 'exp' is present, decode it to human-readable time
        if key == "exp":
            jwt_exp_unix_time = value
            expiration_time = datetime.datetime.fromtimestamp(value, tz=datetime.timezone.utc)
            logger.info(f'{key}: {value} (Expiration Time: {expiration_time})')
        else:
            logger.info(f'{key}: {value}')

    # Signature
    logger.info(f'Signature (raw):, {parts[2]}')
    return jwt_exp_unix_time


@log_decorator
def get_login_token(base_url, user, password):
    login_suffix = "auth/login"
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
    }
    login_url = base_url + login_suffix
    logger.info("Using the following login URL:" + login_url)
    data = {
        'login': user,
        'password': password
    }
    encoded_data = urllib.parse.urlencode(data)
    # logger.info(encoded_data)
    login_response = requests.post(login_url, verify=False, data=encoded_data, headers=headers)
    if login_response.status_code == 200:
        # logger.info(login_response.json())
        login_data = login_response.json()
        token = login_data.get('auth_token')
        return token
    elif login_response.status_code == 401:
        login_data = login_response.json()
        status = login_data.get('status')
        message = login_data.get('message')
        # logger.info(status + ": " + message)
    else:
        raise Exception(f'Request failed with status code {login_response.status_code}')

def save_token_to_file(token, file_path):
    try:
        with open(file_path, "w") as file:
            file.write(token)
        print(f"Token successfully saved to {file_path}")
    except Exception as e:
        print(f"An error occurred while saving the token: {e}")

def load_token_from_file(file_path):
    try:
        with open(file_path, "r") as file:
            token = file.read().strip()
        return token
    except FileNotFoundError:
        logger.info(f'Token file {file_path} not found.')
        return None
    except Exception as e:
        logger.info(f'An error occurred while reading the token: {e}')
        return None

def is_token_about_to_expire(unix_time_of_token_exp, threshold_seconds):
    current_time = time.time()
    time_to_expiry = unix_time_of_token_exp - current_time
    logger.info(f'Current Unix Time: {int(current_time)}')
    logger.info(f'Token Expiry Unix Time: {unix_time_of_token_exp}')
    logger.info(f'Time to Expiry (seconds): {time_to_expiry}')
    # Check if the token is about to expire within the threshold
    return time_to_expiry < threshold_seconds





def list_arrays(base_url, login_token):
    arrays_suffix = "storage_arrays"
    arrays_url = base_url + arrays_suffix
    logger.info("Using the following arrays URL:" + arrays_url)
    headers = {
        "Accept": "application/vnd.sam4h.v1+json",
        "Authorization": login_token
    }
    params = {
        "page": 1, # Specify the page. Default pagination size is 100 entries (see parameter limit)
        "limit": 1 # Page size for pagination (default=100)
    }
    all_data = []
    while True:
        arrays_response = requests.get(arrays_url, verify=False, headers=headers, params=params)
        if arrays_response.status_code == 200:
            data = arrays_response.json()
            if data['status'] == "success":
                # Append the data from the current page to all_data
                all_data.extend(data['data'])
                # Update the current page
                params['page'] += 1
                # Check if there are more pages
                if params['page'] > data['pagination']['pages']:
                    break
            else:
                raise Exception(f'Status is {data['status']}')
        else:
            raise Exception(f'Request failed with status code {arrays_response.status_code}')
    return all_data

@log_decorator
def find_storage_array_id_by_serial_number(api_storage_arrays_list, serial_number):
    for storage in api_storage_arrays_list:
        if storage['serial_number'] == serial_number:
            return storage['id']
    return None


def listing_dp_vols(base_url, login_token, storage_cluster_id):
    list_dp_vols_suffix = "dp_vols"
    list_dp_vols_url = base_url + list_dp_vols_suffix
    logger.info("Using the following URL:" + list_dp_vols_url)
    headers = {
        "Accept": "application/vnd.sam4h.v1+json",
        "Authorization": login_token,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    params = {
        "page": 1,
        "limit": 400,
        "sort_by": "created_at",
        "direction": "desc",
        # "storage_array_id": storage_array_id,
        "storage_cluster_id": storage_cluster_id,
        "show_mapped_host_groups": "false"
    }
    list_dp_vols_response = requests.get(list_dp_vols_url, verify=False, headers=headers, params=params)
    if list_dp_vols_response.status_code == 200:
        return list_dp_vols_response.json()


def get_storage_clusters(base_url, login_token):
    get_storage_clusters_suffix = "storage_clusters"
    get_storage_clusters_suffix_url = base_url + get_storage_clusters_suffix
    logger.info("Using the following storage clusters URL:" + get_storage_clusters_suffix_url)
    headers = {
        "Accept": "application/vnd.sam4h.v1+json",
        "Authorization": login_token
    }
    get_storage_clusters_response = requests.get(get_storage_clusters_suffix_url,
                                                                   verify=False, headers=headers)
    if get_storage_clusters_response.status_code == 200:
        return get_storage_clusters_response.json()
    else:
        raise Exception(f'Request failed with status code {get_storage_clusters_response.status_code}')


def find_storage_cluster_id_by_name(api_storage_clusters, stg_clu_name):
    for storage_cluster in api_storage_clusters['data']:
        if storage_cluster['name'] == stg_clu_name:
            return storage_cluster['id']
    return None


def find_ldev_id_in_api_dp_vols(api_dp_vols_json, hex_dev_num, storage_array_id):
    dec_dev_num = int(hex_dev_num)
    for volume in api_dp_vols_json['data']:
        attributes = volume.get("attributes", {})
        if attributes.get("dev_num") == dec_dev_num and attributes.get("storage_array_id") == storage_array_id:
            return volume.get("id")
    return None


def find_cluster_id_by_name(api_clusters, cluster_name):
    for cluster in api_clusters:
        if cluster['name'] == cluster_name:
            return cluster['id']
    return None


def create_new_snapshot(base_url, login_token, dp_vol_ids, snap_group_name):
    snapshots_suffix = "snapshots"
    snapshots_url = base_url + snapshots_suffix
    logger.info("Using the following URL:" + snapshots_url)
    headers = {
        "Accept": "application/vnd.sam4h.v1+json",
        "Authorization": login_token,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    params = {
        "dp_vol_ids": dp_vol_ids, #	Comma-separated string of integers (IDs of the DpVol)
        "snap_group_name": snap_group_name, # Name of the Snapshot Group
    }
    a_list_of_snapshots_before_adding_new = list_snapshots(base_url, login_token)
    a_list_of_snapshots_before_adding_new_just_ids = []
    for snapshot_id in a_list_of_snapshots_before_adding_new:
        a_list_of_snapshots_before_adding_new_just_ids.append(snapshot_id['id'])

    create_new_snapshot_response = requests.post(snapshots_url, verify=False, headers=headers, params=params)
    if create_new_snapshot_response.status_code == 200:
        a_list_of_snapshots_after_adding_new = list_snapshots(base_url, login_token)
        a_list_of_snapshots_after_adding_new_just_ids = []
        for snapshot_id in a_list_of_snapshots_after_adding_new:
            a_list_of_snapshots_after_adding_new_just_ids.append(snapshot_id['id'])
        new_snapshots_created = [item for item in a_list_of_snapshots_after_adding_new_just_ids if item not in a_list_of_snapshots_before_adding_new_just_ids]
        new_snapshots_created_str = ','.join(map(str, new_snapshots_created))
        return new_snapshots_created_str


def join_strings(*args):
    return ','.join(args)


def list_snapshots(base_url, login_token):
    snapshots_suffix = "snapshots"
    arrays_url = base_url + snapshots_suffix
    logger.info("Using the following URL:" + arrays_url)
    headers = {
        "Accept": "application/vnd.sam4h.v1+json",
        "Authorization": login_token
    }
    params = {
        "page": 1, # Specify the page. Default pagination size is 100 entries (see parameter limit)
        "limit": 1, # Page size for pagination (default=100) ## must check not unique IDs when using 1
        "sort_by": "id"
    }
    all_data = []
    while True:
        snaphots_response = requests.get(arrays_url, verify=False, headers=headers, params=params)
        # print(f'current page: {params['page']}')
        if snaphots_response.status_code == 200:
            data = snaphots_response.json()
            if data['status'] == "success":
                # Append the data from the current page to all_data
                all_data.extend(data['data'])
                # print(data)
                # Update the current page
                params['page'] += 1
                # Check if there are more pages
                if params['page'] > data['pagination']['pages']:
                    break
            else:
                raise Exception(f'Status is {data['status']}')
        else:
            raise Exception(f'Request failed with status code {snaphots_response.status_code}')
    return all_data



def list_clusters(base_url, login_token):
    clusters_suffix = "clusters"
    clusters_url = base_url + clusters_suffix
    logger.info("Using the following clusters URL:" + clusters_url)
    headers = {
        "Accept": "application/vnd.sam4h.v1+json",
        "Authorization": login_token
    }
    params = {
        "page": 1, # Specify the page. Default pagination size is 100 entries (see parameter limit)
        "limit": 2 # Page size for pagination (default=100)
    }
    all_data = []
    while True:
        clusters_response = requests.get(clusters_url, verify=False, headers=headers, params=params)
        if clusters_response.status_code == 200:
            data = clusters_response.json()
            if data['status'] == "success":
                # Append the data from the current page to all_data
                all_data.extend(data['data'])
                # Update the current page
                params['page'] += 1
                # Check if there are more pages
                if params['page'] > data['pagination']['pages']:
                    break
            else:
                raise Exception(f'Status is {data['status']}')
        else:
            raise Exception(f'Request failed with status code {clusters_response.status_code}')
    return all_data




def mount_snapshot(base_url, login_token, api_cluster_id, snapshot_ids):
    snapshots_suffix = "snapshots/mount"
    snapshots_url = base_url + snapshots_suffix
    logger.info("Using the following URL:" + snapshots_url)
    headers = {
        "Accept": "application/vnd.sam4h.v1+json",
        "Authorization": login_token,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    params = {
        "cluster_id": api_cluster_id, #		ID of Snapshot?? Maybe of a cluster
        "snapshot_ids": snapshot_ids, # Comma-separated string of integers (IDs of Snapshot)
    }
    create_new_snapshot_response = requests.post(snapshots_url, verify=False, headers=headers, params=params)
    if create_new_snapshot_response.status_code == 200:
        return create_new_snapshot_response.json()


def unmount_snapshot(base_url, login_token, api_cluster_id, snapshot_ids):
    snapshots_suffix = "snapshots/unmount"
    snapshots_url = base_url + snapshots_suffix
    logger.info("Using the following URL:" + snapshots_url)
    headers = {
        "Accept": "application/vnd.sam4h.v1+json",
        "Authorization": login_token,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    params = {
        "snapshot_ids": snapshot_ids, # Comma-separated string of integers (IDs of Snapshot)
    }
    create_new_snapshot_response = requests.post(snapshots_url, verify=False, headers=headers, params=params)
    if create_new_snapshot_response.status_code == 200:
        return create_new_snapshot_response.json()


def list_luns(base_url, login_token):
    luns_suffix = "luns"
    luns_url = base_url + luns_suffix
    logger.info("Using the following clusters URL:" + luns_url)
    headers = {
        "Accept": "application/vnd.sam4h.v1+json",
        "Authorization": login_token
    }
    params = {
        "page": 1, # Specify the page. Default pagination size is 100 entries (see parameter limit)
        "limit": 2 # Page size for pagination (default=100)
    }
    all_data = []
    while True:
        clusters_response = requests.get(luns_url, verify=False, headers=headers, params=params)
        if clusters_response.status_code == 200:
            data = clusters_response.json()
            if data['status'] == "success":
                # Append the data from the current page to all_data
                all_data.extend(data['data'])
                # Update the current page
                params['page'] += 1
                # Check if there are more pages
                if params['page'] > data['pagination']['pages']:
                    break
            else:
                raise Exception(f'Status is {data['status']}')
        else:
            raise Exception(f'Request failed with status code {clusters_response.status_code}')
    return all_data



def delete_snapshot(base_url, login_token, snapshot_ids):
    snapshots_suffix = "snapshots"
    snapshots_url = base_url + snapshots_suffix
    logger.info("Using the following URL:" + snapshots_url)
    headers = {
        "Accept": "application/vnd.sam4h.v1+json",
        "Authorization": login_token,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    params = {
        "snapshot_ids": snapshot_ids #		Comma-separated string of integers (IDs of Snapshot)
    }
    delete_snapshots = requests.delete(snapshots_url, verify=False, headers=headers, params=params)
    if delete_snapshots.status_code == 200:
        return delete_snapshots.json()



user_input = get_arguments()
sam4hserver = user_input.sam4hserver
sam4huser = user_input.sam4huser
sam4hpassword = user_input.sam4hpassword

logger.info("sam4hserver = " + sam4hserver)
logger.info("sam4huser = " + sam4huser)
logger.info("sam4hpassword = " + sam4hpassword)

base_url = "https://" + sam4hserver + ":" + "443" + "/api/"
logger.info("base_url = " + base_url)

# Get and print the login token

login_token = load_token_from_file("jwt.json")


logger.info(f'login_token: {login_token}')
jwt_exp_unix_time = decode_jwt_parts_return_jwt_exp_unix_time(login_token)
logger.info(f'jwt_exp_unix_time = {jwt_exp_unix_time}')
if is_token_about_to_expire(jwt_exp_unix_time, 3600):
    login_token = get_login_token(base_url, sam4huser, sam4hpassword)
    save_token_to_file(login_token, "jwt.json")


# List storage arrays
storage_arrays = list_arrays(base_url, login_token)
# logger.info(json.dumps(storage_arrays, indent=4))

# for internal API ID of a storage serial
sn1_id = find_storage_array_id_by_serial_number(storage_arrays, 800001)
logger.info(f'800001: {sn1_id}')




# list storage clusters
storage_clusters_list = get_storage_clusters(base_url, login_token)
# logger.info(json.dumps(storage_clusters_list, indent=4))


# Get storage cluster internal API ID
storage_cluster_name = "vsp-one-800001"
storage_cluster_id = find_storage_cluster_id_by_name(storage_clusters_list, storage_cluster_name)
logger.info(f'Internal APi ID of {storage_cluster_name}: {storage_cluster_id}')

#List volumes
a_list_of_ldevs = listing_dp_vols(base_url, login_token, storage_cluster_id)
# logger.info(json.dumps(a_list_of_ldevs, indent=4))

# Find LDEV in API DP VOLs
hex_ldevs_list = [0x9a, 0x9c, 0x9d, 0x9e]
api_ldevs_list = []
for hex_ldev in hex_ldevs_list:
    api_dp_vol_id_of_an_ldev1 = find_ldev_id_in_api_dp_vols(a_list_of_ldevs, hex_ldev, sn1_id)
    logger.info(f'Internal API id of {hex(hex_ldev)} is {api_dp_vol_id_of_an_ldev1}')
    api_ldevs_list.append(api_dp_vol_id_of_an_ldev1)
ldevs_to_snap = ""
for ldev in api_ldevs_list:
    ldevs_to_snap =join_strings(ldevs_to_snap, ldev)
ldevs_to_snap = ldevs_to_snap[1:]
logger.info(f'Going to snap these: {ldevs_to_snap}')


# # Create snapshots
# for i in range(5):
#     length = 10
#     random_string = ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
#     snap_group_name = "my_fucking_snapshot_" + random_string
#     snapshots_created = create_new_snapshot(base_url, login_token, ldevs_to_snap, snap_group_name)
#     logger.info(f'Snapshots created: {snapshots_created}')

# Get and print the list of clusters
clusters = list_clusters(base_url, login_token)
# logger.info(json.dumps(clusters, indent=4))


#Find cluster API id by name
cluster_name_to_find = "cluster_1"
cluster_id = find_cluster_id_by_name(clusters, cluster_name_to_find)
logger.info(f'Cluster id of {cluster_name_to_find}: {cluster_id}')



# List all snapshots
a_list_of_snapshots = list_snapshots(base_url, login_token)
for s in a_list_of_snapshots:
    logger.info(s)
# logger.info(json.dumps(a_list_of_snapshots, indent=4))






# List LUNs
list_of_luns = list_luns(base_url, login_token)

def find_ldev_id_in_api_list_of_luns(api_list_luns, hex_dev_num, storage_array_id):
    dec_dev_num = int(hex_dev_num)
    for volume in api_list_luns:
        if volume['dev_num'] == dec_dev_num and volume['storage_array_id'] == storage_array_id:
            return volume['id']
    return None

api_luns_list = []
for hex_ldev in hex_ldevs_list:
    ldev1_internal_id = find_ldev_id_in_api_list_of_luns(list_of_luns, hex_ldev, sn1_id)
    logger.info(f'Internal API LUN id of {hex(hex_ldev)} is {ldev1_internal_id}')
    api_luns_list.append(ldev1_internal_id)
logger.info(api_luns_list)




#Which snapshots to mount
snap_list_str = ""
for snapshot in a_list_of_snapshots:
    if snapshot['primary_lun_id'] in api_luns_list and snapshot['storage_array_id'] == sn1_id:
        snap_list_str = join_strings(snap_list_str, str(snapshot['id']))
snap_list_str = snap_list_str[1:]
# logger.info(f'snap_list_str: {snap_list_str}')


# Mount snapshots
# mounted_snapshots = mount_snapshot(base_url, login_token, cluster_id, snap_list_str)
# logger.info(json.dumps(mounted_snapshots, indent=4))

# unmount snapshots
# unmounted_snapshots = unmount_snapshot(base_url, login_token, cluster_id, snap_list_str)
# logger.info(json.dumps(unmounted_snapshots, indent=4))


# Delete snapshots
# deleted_snapshot = delete_snapshot(base_url, login_token, snap_list_str)
# deleted_snapshot = delete_snapshot(base_url, login_token, "211,212,213,214")
# logger.info(json.dumps(deleted_snapshot, indent=4))

# Delete snapshots of a storage system
a_list_of_snapshots = list_snapshots(base_url, login_token)
logger.info(json.dumps(a_list_of_snapshots, indent=4))

all_snapshots_of_a_storage_system = []

for snapshot in a_list_of_snapshots:
    if snapshot['storage_array_id'] == sn1_id:
        all_snapshots_of_a_storage_system.append(snapshot['id'])
all_snapshots_of_a_storage_system_unique = list(set(all_snapshots_of_a_storage_system))
all_snapshots_of_a_storage_system_unique_str = ','.join(map(str, all_snapshots_of_a_storage_system_unique))
logger.info(f'Going to delete these snaphots: {all_snapshots_of_a_storage_system_unique_str}')
deleted_snapshot = delete_snapshot(base_url, login_token, all_snapshots_of_a_storage_system_unique_str)


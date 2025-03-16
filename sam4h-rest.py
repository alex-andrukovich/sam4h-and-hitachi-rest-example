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
    logger.info(encoded_data)
    login_response = session.post(login_url, verify=False, data=encoded_data, headers=headers)
    if login_response.status_code == 200:
        logger.info(login_response.json())
        login_data = login_response.json()
        token = login_data.get('auth_token')
        return token
    elif login_response.status_code == 401:
        login_data = login_response.json()
        status = login_data.get('status')
        message = login_data.get('message')
        logger.info(status + ": " + message)
    else:
        raise Exception(f'Request failed with status code {login_response.status_code}')


@log_decorator
def list_clusters(session, base_url, login_token):
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
        clusters_response = session.get(clusters_url, verify=False, headers=headers, params=params)
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


@log_decorator
def list_arrays(session, base_url, login_token):
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
        arrays_response = session.get(arrays_url, verify=False, headers=headers, params=params)
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
def get_details_of_a_cluster(session, base_url, login_token, cluster_id):
    clusters_suffix = "clusters"
    single_cluster_url = base_url + clusters_suffix + "/" + str(cluster_id)
    logger.info("Using the following clusters URL:" + single_cluster_url)
    headers = {
        "Accept": "application/vnd.sam4h.v1+json",
        "Authorization": login_token
    }
    single_cluster_response = session.get(single_cluster_url, verify=False, headers=headers)
    if single_cluster_response.status_code == 200:
        return single_cluster_response.json()
    else:
        raise Exception(f'Request failed with status code {single_cluster_response.status_code}')

@log_decorator
def get_mapping_tables_of_a_cluster(session, base_url, login_token, cluster_id):
    clusters_suffix = "clusters"
    single_cluster_mapping_url = base_url + clusters_suffix + "/" + str(cluster_id) + "/" + "mapping_tables"
    logger.info("Using the following clusters URL:" + single_cluster_mapping_url)
    headers = {
        "Accept": "application/vnd.sam4h.v1+json",
        "Authorization": login_token
    }
    single_cluster_mapping_response = session.get(single_cluster_mapping_url, verify=False, headers=headers)
    if single_cluster_mapping_response.status_code == 200:
        return single_cluster_mapping_response.json()
    else:
        raise Exception(f'Request failed with status code {single_cluster_mapping_response.status_code}')

@log_decorator
def export_dp_vol_sizes(session, base_url, login_token):
    dp_vol_sizes_suffix = "dp_vol_sizes"
    dp_vol_sizes_url = base_url + dp_vol_sizes_suffix
    logger.info("Using the following clusters URL:" + dp_vol_sizes_url)
    headers = {
        "Accept": "application/vnd.sam4h.v1+json",
        "Authorization": login_token
    }
    single_cluster_mapping_response = session.get(dp_vol_sizes_url, verify=False, headers=headers)
    if single_cluster_mapping_response.status_code == 200:
        return single_cluster_mapping_response.json()
    else:
        raise Exception(f'Request failed with status code {single_cluster_mapping_response.status_code}')


@log_decorator
def import_dp_vol_sizes(session, base_url, login_token, size, name):
    dp_vol_sizes_import_suffix = "dp_vol_sizes/import"
    dp_vol_sizes_import_url = base_url + dp_vol_sizes_import_suffix
    logger.info("Using the following clusters URL:" + dp_vol_sizes_import_url)
    headers = {
        "Accept": "application/vnd.sam4h.v1+json",
        "Authorization": login_token,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {
        "dp_vol_sizes[][data][id]": "",
        "dp_vol_sizes[][data][type]": "dp_vol_size",
        "dp_vol_sizes[][data][attributes][display_name]": name,
        "dp_vol_sizes[][data][attributes][blocks]": size
    }
    encoded_data = urllib.parse.urlencode(data)
    logger.info(encoded_data)
    import_vol_size = session.post(dp_vol_sizes_import_url, verify=False, headers=headers, data=encoded_data)
    if import_vol_size.status_code == 204:
        return import_vol_size
    else:
        raise Exception(f'Request failed with status code {import_vol_size.status_code}')


@log_decorator
def get_storage_clusters(session, base_url, login_token):
    get_storage_clusters_suffix = "storage_clusters"
    get_storage_clusters_suffix_url = base_url + get_storage_clusters_suffix
    logger.info("Using the following storage clusters URL:" + get_storage_clusters_suffix_url)
    headers = {
        "Accept": "application/vnd.sam4h.v1+json",
        "Authorization": login_token
    }
    get_storage_clusters_response = session.get(get_storage_clusters_suffix_url,
                                                                   verify=False, headers=headers)
    if get_storage_clusters_response.status_code == 200:
        return get_storage_clusters_response.json()
    else:
        raise Exception(f'Request failed with status code {get_storage_clusters_response.status_code}')


@log_decorator
def export_all_dpv_config_templates_details(session, base_url, login_token):
    export_all_dpv_config_templates_details_suffix = "dpv_config_templates/index_detailed"
    export_all_dpv_config_templates_details_url = base_url + export_all_dpv_config_templates_details_suffix
    logger.info("Using the following clusters URL:" + export_all_dpv_config_templates_details_url)
    headers = {
        "Accept": "application/vnd.sam4h.v1+json",
        "Authorization": login_token
    }
    export_all_dpv_config_templates_details_response = session.get(export_all_dpv_config_templates_details_url,
                                                                   verify=False, headers=headers)
    if export_all_dpv_config_templates_details_response.status_code == 200:
        return export_all_dpv_config_templates_details_response.json()
    else:
        raise Exception(f'Request failed with status code {export_all_dpv_config_templates_details_response.status_code}')

@log_decorator
def create_new_dp_vols(session, base_url, login_token, storage_cluster, dpv_config_template, size, amount, cluster, ctg):
    create_new_dp_vols_suffix = "dp_vols"
    create_new_dp_vols_url = base_url + create_new_dp_vols_suffix
    logger.info("Using the following URL:" + create_new_dp_vols_url)
    headers = {
        "Accept": "application/vnd.sam4h.v1+json",
        "Authorization": login_token,
        "Content-Type": "application/x-www-form-urlencoded"
    }

    data = {
        "storage_cluster": storage_cluster,         # ID or name of the StorageCluster (required)
        "dpv_config_template": dpv_config_template, # ID or api_key of the DpvConfigTemplate (required)
        "size": size,                               # Number with Unit (can have a space between number and unit,
                                                        # but does not need have one) Example: '100000' or '10000blks'
                                                        # or '100000G' or '10000 GB'. Could be alternatively
                                                        # specified as 'size_in_blocks' (required)
        "amount": amount,                            # Amount of DpVols to create (required)
        "map_to": cluster,                           # Map to Cluster instance ID or name
        "ctg": ctg                                   # Consistency group number. Leave empty, if it should
                                                        # not be added to a consistency group.
                                                        # In order to create a new one, specify "new"
        # "snap_ctg": "new",                         # Consistency group for snapshots. Leave empty, if it should
                                                        # not be added to a consistency group.
                                                        # In order to create a new one, specify "new"
        # "primary_serial_nr": "800001",             # Primary serial number for creating replications
                                                        #(must belong to storage_cluster)
        # "secondary_serial_nr": "800002",           # Secondary serial number for creating replications
                                                        #(must belong to storage_cluster)
        # "explicit_lun_start_nr": "1",              # 	Start nr for LUN-Mapping. Leave empty,
                                                        # to use the definition specified in the config template
        # "lun_label": "%h%l"                        # Schema for labeling LUNs. You can use the following parameters:
                                                        # %h: HostGroup-name, %l: CuUa, %p: Pool-Nr., %t: Template-Name.

    }
    encoded_data = urllib.parse.urlencode(data)
    logger.info(encoded_data)
    create_vols = session.post(create_new_dp_vols_url, verify=False, headers=headers, data=encoded_data)
    if create_vols.status_code == 200:
        return create_vols.json()
    elif create_vols.status_code == 404:
        output_data = create_vols.json()
        status = output_data.get('status')
        message = output_data.get('message')
        logger.error(status + ": " + message)
    elif create_vols.status_code == 422:
        logger.error(create_vols.json())
    else:
        raise Exception(f'Request failed with status code {create_vols.status_code}')

@log_decorator
def delete_dp_vols(session, base_url, login_token, storage_array, internal_lun_ids, do_unmap):
    delete_dp_vols_suffix = "dp_vols"
    delete_dp_vols_url = base_url + delete_dp_vols_suffix
    logger.info("Using the following URL:" + delete_dp_vols_url)
    headers = {
        "Accept": "application/vnd.sam4h.v1+json",
        "Authorization": login_token,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    data = {
        "storage_array": storage_array,         # ID, serial-number or name of a storage array (required)
        "lun_ids": internal_lun_ids,                    # Comma-separated string of integers (IDs of LUNs) (required)
        "do_unmap": do_unmap                    # Default value is false
    }
    encoded_data = urllib.parse.urlencode(data)
    logger.info(encoded_data)
    delete_dp_vols_response = session.delete(delete_dp_vols_url, verify=False, headers=headers, data=encoded_data)
    if delete_dp_vols_response.status_code == 200:
        return delete_dp_vols_response.json()
    elif delete_dp_vols_response.status_code == 422:
        logger.error(delete_dp_vols_response.json())
    elif delete_dp_vols_response.status_code == 404:
        logger.error(delete_dp_vols_response.json())
    else:
        raise Exception(f'Request failed with status code {delete_dp_vols_response.status_code}')

@log_decorator
def listing_dp_vols(session, base_url, login_token, storage_cluster_id):
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
    list_dp_vols_response = session.get(list_dp_vols_url, verify=False, headers=headers, params=params)
    if list_dp_vols_response.status_code == 200:
        return list_dp_vols_response.json()




@log_decorator
def expand_dp_vols(session, base_url, login_token, storage_cluster, internal_dp_vol_ids, target_size_or_additional_size, capacity):
    expand_dp_vols_suffix = "dp_vols"
    expand_dp_vols_url = base_url + expand_dp_vols_suffix
    logger.info("Using the following URL:" + expand_dp_vols_url)
    headers = {
        "Accept": "application/vnd.sam4h.v1+json",
        "Authorization": login_token,
        "Content-Type": "application/x-www-form-urlencoded"
    }
    if target_size_or_additional_size == "additional_size":
        data = {
            "storage_cluster": storage_cluster,         # ID or name of the StorageCluster (required)
            "dp_vol_ids": internal_dp_vol_ids,           # Comma-separated string of integers (IDs of DpVols) (required)
            "additional_size": capacity  # Default value is false
        }
    encoded_data = urllib.parse.urlencode(data)
    logger.info(encoded_data)
    expand_dp_vols_response = session.put(expand_dp_vols_url, verify=False, headers=headers, data=encoded_data)
    if expand_dp_vols_response.status_code == 200:
        return expand_dp_vols_response.json()
    elif expand_dp_vols_response.status_code == 422:
        logger.error(expand_dp_vols_response.json())
    elif expand_dp_vols_response.status_code == 404:
        logger.error(expand_dp_vols_response.json())
    else:
        raise Exception(f'Request failed with status code {expand_dp_vols_response.status_code}')


@log_decorator
def list_luns(session, base_url, login_token):
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
        clusters_response = session.get(luns_url, verify=False, headers=headers, params=params)
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

@log_decorator
def find_ldev_id_in_api_dp_vols(api_dp_vols_json, hex_dev_num, storage_array_id):
    dec_dev_num = int(hex_dev_num)
    for volume in api_dp_vols_json['data']:
        attributes = volume.get("attributes", {})
        if attributes.get("dev_num") == dec_dev_num and attributes.get("storage_array_id") == storage_array_id:
            return volume.get("id")
    return None

@log_decorator
def find_storage_array_id_by_serial_number(api_storage_arrays_list, serial_number):
    for storage in api_storage_arrays_list:
        if storage['serial_number'] == serial_number:
            return storage['id']
    return None



@log_decorator
def join_strings(*args):
    return ','.join(args)

user_input = get_arguments()
sam4hserver = user_input.sam4hserver
sam4huser = user_input.sam4huser
sam4hpassword = user_input.sam4hpassword

logger.info("sam4hserver = " + sam4hserver)
logger.info("sam4huser = " + sam4huser)
logger.info("sam4hpassword = " + sam4hpassword)

# Create a new CookieJar object
jar = CookieJar()
# Create a session
session = requests.session()
# Use the CookieJar as the session's cookie store
session.cookies = jar
# Now you can send requests through the session, and cookies will be stored in the jar
# response = session.get('https://example.com')
# The cookies received in the response are now stored in the jar

base_url = "https://" + sam4hserver + ":" + "443" + "/api/"
logger.info("base_url = " + base_url)

# Get and print the login token
login_token = get_login_token(base_url, sam4huser, sam4hpassword)
logger.info(f'login_token: {login_token}')

# Get and print the list of clusters
# clusters = list_clusters(session, base_url, login_token)
# logger.info(json.dumps(clusters, indent=4))
# for cluster in clusters:
#     print(cluster)


# Get and print the details of one cluster id
# cluster_details_example = get_details_of_a_cluster(session, base_url, login_token, 2)
# logger.info(json.dumps(cluster_details_example, indent=4))

# Get and print the mapping details of one cluster id
# cluster_details_mapping_example = get_mapping_tables_of_a_cluster(session, base_url, login_token, 2)
# logger.info(json.dumps(cluster_details_mapping_example, indent=4))

# Get and print the list of dp vol sizes
# dp_vol_sizes_list = export_dp_vol_sizes(session, base_url, login_token)
# logger.info(json.dumps(dp_vol_sizes_list, indent=4))

# import dp vol size template, if using existing name, template  will be overwritten
# import_dp_vol_sizes(session, base_url, login_token, 221111, "amazing_lun2")

# get all DP VOL templates
# all_dpv_config_templates_details = export_all_dpv_config_templates_details(session, base_url, login_token)
# logger.info(json.dumps(all_dpv_config_templates_details, indent=4))
# for dpv_tmpl in all_dpv_config_templates_details['dpv_config_templates']:
#     print(dpv_tmpl)
#
# storage_clusters_list = get_storage_clusters(session, base_url, login_token)
# logger.info(json.dumps(storage_clusters_list, indent=4))



# Create LDEVs and allocate to a cluster
# create_new_dp_vols(session, base_url, login_token, "2DC", 1, "10G", 1, "cluster_1", "new") #--  !!!!!! stopped working by name
# create_new_dp_vols(session, base_url, login_token, "3", 1, "11G", 1, "cluster_1", "new")
#

# List storage arrays
storage_arrays = list_arrays(session, base_url, login_token)
logger.info(json.dumps(storage_arrays, indent=4))
sn1_id = find_storage_array_id_by_serial_number(storage_arrays, 800001)
logger.info(f'800001: {sn1_id}')
sn2_id = find_storage_array_id_by_serial_number(storage_arrays, 800002)
logger.info(f'800002: {sn2_id}')
#
#
# #List volumes
# a_list_of_ldevs = listing_dp_vols(session, base_url, login_token, 3)
# logger.info(json.dumps(a_list_of_ldevs, indent=4))
# #
# api_dp_vol_id_of_an_ldev1 = find_ldev_id_in_api_dp_vols(a_list_of_ldevs, 0x9e, sn1_id)
# logger.info(json.dumps(api_dp_vol_id_of_an_ldev1, indent=4))
# api_dp_vol_id_of_an_ldev2 = find_ldev_id_in_api_dp_vols(a_list_of_ldevs, 0x9e, sn2_id)
# logger.info(json.dumps(api_dp_vol_id_of_an_ldev2, indent=4))

# # Expand LDEV - use storage_cluster name not storage system id, use the IDs from api/dp_vols table
# str_of_ldevs_to_expand =join_strings(api_dp_vol_id_of_an_ldev1, api_dp_vol_id_of_an_ldev2)
# expand_dp_vols(session, base_url, login_token, "3", str_of_ldevs_to_expand, "additional_size", "100G")
#
#

# List LUNs
list_of_luns = list_luns(session, base_url, login_token)
# print(list_of_luns[1])
# logger.info(json.dumps(list_of_luns, indent=4))

@log_decorator
def find_ldev_id_in_api_list_of_luns(api_list_luns, hex_dev_num, storage_array_id):
    dec_dev_num = int(hex_dev_num)
    for volume in api_list_luns:
        if volume['dev_num'] == dec_dev_num and volume['storage_array_id'] == storage_array_id:
            return volume['id']
    return None

ldev1_internal_id = find_ldev_id_in_api_list_of_luns(list_of_luns, 0x9B, sn1_id)
ldev2_internal_id = find_ldev_id_in_api_list_of_luns(list_of_luns, 0x9B, sn2_id)

print(ldev1_internal_id)
print(ldev2_internal_id)

# Delete volumes, must use the LUN table to get the internal IDs
delete_dp_vols_job_status = delete_dp_vols(session, base_url, login_token, "vsp-one-800001", ldev1_internal_id, "true")
logger.info(json.dumps(delete_dp_vols_job_status, indent=4))
delete_dp_vols_job_status = delete_dp_vols(session, base_url, login_token, "vsp-one-800002", ldev2_internal_id, "true")
logger.info(json.dumps(delete_dp_vols_job_status, indent=4))

#!/usr/bin/env python3
# Usage: -s1 10.0.0.10 -s2 10.0.0.12 -s1u maintenance -s2u maintenance -s1p raid-maintenance -s2p raid-maintenance
import requests
import urllib.parse
import argparse
import json
from http.cookiejar import CookieJar
import sys
import os
import re
import subprocess
import time
import logging
import functools
from requests.auth import HTTPBasicAuth
import urllib3

# Suppress only the single InsecureRequestWarning from urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Create a logger
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
# Create handlers
file_handler = logging.FileHandler('hitachi_rest_create_replication.log')  # Log to a file
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
    parser.add_argument("-s1", "--storage1", dest="storage1",  help="Enter storage 1 IP address")
    parser.add_argument("-s2", "--storage2", dest="storage2",  help="Enter storage 2 IP address")
    parser.add_argument("-s1u", "--storage1user", dest="storage1user",  help="Enter storage 1 user name")
    parser.add_argument("-s2u", "--storage2user", dest="storage2user",  help="Enter storage 2 user name")
    parser.add_argument("-s1p", "--storage1password", dest="storage1password",  help="Enter storage 1 password")
    parser.add_argument("-s2p", "--storage2password", dest="storage2password",  help="Enter storage 2 password")
    arguments = parser.parse_args()
    if not arguments.storage1:
        parser.exit("[-] Enter missing info.")
    elif not arguments.storage2:
        parser.exit("[-] Enter missing info.")
    elif not arguments.storage1user:
        parser.exit("[-] Enter missing info.")
    elif not arguments.storage2user:
        parser.exit("[-] Enter missing info.")
    elif not arguments.storage1password:
        parser.exit("[-] Enter missing info.")
    elif not arguments.storage2password:
        parser.exit("[-] Enter missing info.")
    return arguments


@log_decorator
def send_request_without_data_post(session, url, auth):
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    response = session.post(url, verify=False, headers=headers, auth=auth)
    logger.info(url)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f'Request failed with status code {response.status_code}')

@log_decorator
def send_request_with_data_l_r_token_post(session, url, data, token, remote_token):
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Session {token}",
        "Remote-Authorization": f"Session {remote_token}"
    }
    response = session.post(url, data=data, verify=False, headers=headers)
    logger.info(data)
    logger.info(url)
    if response.status_code == 200:
        return response.json()
    else:
        raise Exception(f'Request failed with status code {response.status_code}')

def send_request_with_data_l_token_post(session, url, data, token):
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Session {token}",
    }
    response = session.post(url, data=data, verify=False, headers=headers)
    logger.info(data)
    logger.info(url)
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 202:
        return response.json()
    else:
        raise Exception(f'Request failed with status code {response.status_code}')



@log_decorator
def send_request_without_data_get(session, url):
    response = session.get(url, verify=False)
    logger.info(url)
    if response.status_code == 200:
        return response.json()
    if response.status_code == 202:
        return response.json()
    else:
        raise Exception(f'Request failed with status code {response.status_code}')

@log_decorator
def send_request_without_data_get_with_l_token(session, url, token):
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Session {token}",
    }
    response = session.get(url, verify=False, headers=headers)
    logger.info(url)
    if response.status_code == 200:
        return response.json()
    if response.status_code == 202:
        return response.json()
    else:
        raise Exception(f'Request failed with status code {response.status_code}')

def get_login_token(base_url, login_suffix, user, password):
    login_url = base_url + login_suffix
    auth = HTTPBasicAuth(user, password)
    login_response = session.post(login_url, verify=False, auth=auth)
    login_data = login_response.json()
    token = login_data.get('token')
    return token

# Create a new CookieJar object
jar = CookieJar()
# Create a session
session = requests.session()
# Use the CookieJar as the session's cookie store
session.cookies = jar
# Now you can send requests through the session, and cookies will be stored in the jar
# response = session.get('https://example.com')
# The cookies received in the response are now stored in the jar


user_input = get_arguments()

storage1 = user_input.storage1
storage2 = user_input.storage2
storage1user = user_input.storage1user
storage2user = user_input.storage2user
storage1password = user_input.storage1password
storage2password = user_input.storage2password

logger.info("storage1 = " + storage1)
logger.info("storage2 = " + storage2)
logger.info("storage1user = " + storage1user)
logger.info("storage2user = " + storage2user)
logger.info("storage1password = " + storage1password)
logger.info("storage2password = " + storage2password)


base_url1 = "https://" + storage1 + ":" + "443" + "/ConfigurationManager/"
base_url2 = "https://" + storage2 + ":" + "443" + "/ConfigurationManager/"

login_suffix = "v1/objects/sessions"
token1 = get_login_token(base_url1, login_suffix, storage1user, storage1password)
token2 = get_login_token(base_url2, login_suffix, storage2user, storage2password)

logger.info("token1 = " + token1)
logger.info("token2 = " + token2)

"""Get storages"""
storages_suffix = "v1/objects/storages"

"""Get storages list of storage 1"""
storage1_info = send_request_without_data_get(session, base_url1 + storages_suffix)
logger.info("storage1_info = ")
logger.info(storage1_info)

"""Get storages list of storage 2"""
storage2_info = send_request_without_data_get(session, base_url2 + storages_suffix)
logger.info("storage2_info = ")
logger.info(storage2_info)

"""Create the JSON for creating storage 2 as remote storage of storage 1"""
remote_storage_of_storage1 = {'storageDeviceId': storage2_info['data'][0]['storageDeviceId'],
                  'restServerIp': storage2_info['data'][0]['ip'],
                  'restServerPort': 443,
                  'isMutualDiscovery': True}
remote_storage_of_storage1_json = json.dumps(remote_storage_of_storage1)
logger.info("remote_storage_of_storage1")
logger.info(remote_storage_of_storage1)

"""Get remote storages list of storage 1"""
remote_storages_suffix = "v1/objects/remote-storages"
get_remote_storages_of_storage1 = send_request_without_data_get_with_l_token(session, base_url1 + remote_storages_suffix, token1)
logger.info("get_remote_storages_of_storage1 = ______________________")
logger.info(get_remote_storages_of_storage1['data'])
# for x in get_remote_storages_of_storage1['data']:
#     print(x)

"""Get remote storages list of storage 2"""
remote_storages_suffix = "v1/objects/remote-storages"
get_remote_storages_of_storage2 = send_request_without_data_get_with_l_token(session, base_url2 + remote_storages_suffix, token2)
logger.info("get_remote_storages_of_storage2 = ______________________")
logger.info(get_remote_storages_of_storage2['data'])
# for x in get_remote_storages_of_storage2['data']:
#     print(x)

# """Create storage 2 as remote storage of storage 1"""
# send_request_with_data_l_r_token_post(session, base_url1 + remote_storages_suffix, remote_storage_of_storage1_json, token1, token2)


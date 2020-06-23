#!/usr/bin/env python
# -*- coding: utf-8 -*-

import requests
import sys
import simplejson
import logging

# submits a hash to the "/v2/file/report" virus total api.
# if matches are found details (vendor and malicious match) and mal_score are returned
# returns a dict of mal_score and details
def check_hash(api_key: str, file_hash: str, file_name: str) -> dict:
    GET_REPORT_URL  = "https://www.virustotal.com/vtapi/v2/file/report"

    logging.info("VTotal - Attempting virus total lookup of hash for: %s" % file_name)

    params = {'apikey': api_key, 'resource': file_hash}

    try:
        response = requests.get(GET_REPORT_URL, params=params)
    except Exception as e:
        logging.error("VTotal - Could not connect to virus total because: %s" % e)
        return

    response_dict = simplejson.loads(response.text)

    REACHED_REQ_LIMIT = -2
    NO_MATCH = 0
    MATCH = 1

    response_code = response_dict.get('response_code')

    if response_code == REACHED_REQ_LIMIT:
        logging.error("VTotal - API request limit reached", file=sys.stderr)
    elif response_code == NO_MATCH:
        logging.info("VTotal - No match found on hash for: %s" % file_name)
    elif response_code == MATCH:
        vendors = response_dict['scans']
        vendor_count = len(vendors.items())
        vendor_detected_count = 0
        details = "Virus Total Results\n"
        mal_score = 0

        for vendor, value in vendors.items():
            if value['detected']:
                vendor_detected_count += 1
                mal_score += 4
                details += "\t - Detected by: \"" + vendor + "\"" + "as \"" + value['result'] + "\"\n"

        percent = percentage(vendor_detected_count, vendor_count)
        
        logging.warning("VTotal - %d/%d (%d percent) of vendors identified the file as malicious" % (vendor_detected_count, vendor_count, percent))
        return {'details': details, 'mal_score': mal_score, 'vtotal_matches':
                "%d/%d" % (vendor_detected_count, vendor_count)} 

def percentage(part, whole) -> float:
    return 100 * float(part)/float(whole)

#!/usr/bin/python
# REQUIREMENT: virus_total_apis ("pip install virustotal-api") and requests ("pip install requests")

from __future__ import print_function
import os, re, sys, json
import requests
from time import sleep
from urllib import parse
from virus_total_apis import PublicApi as VirusTotalPublicApi
from virus_total_apis import PrivateApi as VirusTotalPrivateApi
import logging
from logging import handlers

# Custom imports
from filescan_config import vt_pub_key, vt_priv_key, proxy, proxy_http, proxy_https, vt_log

# Suppressing SSL Warnings (InsecureRequestWarning, InsecurePlatformWarning, SNIMissingWarning)
#req.packages.urllib3.disable_warnings()
import urllib3
urllib3.disable_warnings()

debug=True


########################### VIRUS TOTAL API SETUP ###############################################################################################
if proxy:
	proxies = {'http': proxy_http, 'https': proxy_https}
	vt = VirusTotalPublicApi(vt_pub_key, proxies)
	vt_private = VirusTotalPrivateApi(vt_priv_key, proxies)
else:
	vt = VirusTotalPublicApi(vt_pub_key)
	vt_private = VirusTotalPrivateApi(vt_priv_key)
wait_time = 40

########################### STATUS CHECKS #######################################################################################################
def check_response(response):
	status = ''
	try:
		# Check if report was successfully found in dataset or scan finished		
		if response['response_code'] == 200 and response['results']['response_code'] == 1:
			status = 'success'
			
		# Check for successful queries but invalid criteria or data not in dataset
		elif response['response_code'] == 200 and response['results']['response_code'] != 1:
			status = response['results']['verbose_msg']
				
		# Check for other error conditions
		# 204 = request rate of 4 requests per minute exceeded / 403 = request requires Private API key	
		else:
			try:
				status = str(response['response_code']) + ' ' + response['results']['verbose_msg']
			except:
				status = 'An unknown VirusTotal error occured'
				if debug:
					print(json.dumps(response, sort_keys=False, indent=4)) # print full json dump
				return status
	except:
		if debug:
			print(json.dumps(response, sort_keys=False, indent=4)) # print full json dump		
		return status

	return status

# IN DEVELOPMENT
def check_scan(scan, value):
	status = ''
	queued = 'no'
	
	# Not finished processing				 	
	if scan['results']['response_code'] == 1 and re.search('successfully queued', scan['results']['verbose_msg']):
		queued = 'yes'
		if debug: print('[*] VirusTotal scan request successfully queued, waiting '+wait_time+' seconds before checking report status.')

		while queued == 'yes':	
			sleep(wait_time)			
			report =  vt.get_url_report(value)
			
			if re.search('finished', report['results']['verbose_msg']) or re.search('in dataset', report['results']['verbose_msg']):
				queued = 'no'
			else:
				if debug: print('[*] VirusTotal scan still processing, waiting '+wait_time+' seconds before checking again.')	
				
		status = 'success'
		return status, report

	# Finished processing
	elif scan['results']['response_code'] == 1 and re.search('finished', scan['results']['verbose_msg']):
		if debug: print('[*] VirusTotal scan complete for '+value)	
		status = 'success'	
		return status, scan
	
	# Unknown error
	else:
		if debug: print(json.dumps(scan, sort_keys=False, indent=4)) # print full json dump			
		status = 'error'
		return status, scan
	

########################### SEARCHING ###########################################################################################################
def search_url(urlVar):
	status = ''
	error = ''
	detection_ratio = ''
	scan_date = ''
	permalink = ''
	error = ''
	# Private API
	private = True
	resolution= ''
	country= ''
	categories = []

	if private:
		response =  vt_private.get_url_report(urlVar)
	else:
		response =  vt.get_url_report(urlVar)	
	status = check_response(response)
	
	if status == 'success':
		permalink = response['results']['permalink']	
		scan_date = response['results']['scan_date']	
		detection_ratio = str(response['results']['positives']) +'/'+ str(response['results']['total'])	
		# Private API
		if private:
			for item in response['results']['additional_info']:
				if item == 'resolution':
					resolution = response['results']['additional_info']['resolution']
				if item == 'resolution_country':
					country = response['results']['additional_info']['resolution_country']
				if item == 'categories':	
					for items in response['results']['additional_info']['categories']:
						categories.append(items)

		url_summary = { 'url' : urlVar, 'detection_ratio' : detection_ratio, 'scan_date' : scan_date, 'permalink' : permalink, 'error' : error }	
		
	else:
		error = status
		if debug:
			print('[*] VirusTotal message: '+str(status))

		url_summary = { 'url' : urlVar, 'error' : error }		
		
	# JSON Results for URL
	container = {}
	container['virustotal_url'] = url_summary
	
	return container

def search_domain(domainVar):
	# Declare variables for later use
	status = ''
	error = ''
	permalink = ''
	subdomains = ''	
	siblings = ''	
	resolutions = ''
	detected_urls = ''	
	detected_samples = ''
	categories = []
	# Private API
	private = True

	if private:
		response =  vt_private.get_domain_report(domainVar)
	else:
		response =  vt.get_domain_report(domainVar)
	status = check_response(response)
	
	# Parse domain results if report exists
	# Gather results as counts / statistics due to unknown volumes of detections or resolutions for a domain
	if status == 'success':
		permalink = 'https://virustotal.com/en/domain/{}/information/'.format(domainVar)
		for item in response['results']:
			if 'subdomains' == item:	
				subdomains = sum(1 for items in response['results']['subdomains'])
			if 'domain_siblings' == item and response['results']['domain_siblings']:	
				siblings = sum(1 for items in response['results']['domain_siblings'])
			if 'resolutions' == item:
				resolutions = sum(1 for items in response['results']['resolutions'])
			if 'detected_urls' == item:	
				detected_urls = sum(1 for items in response['results']['detected_urls'])			
			if 'detected_referrer_samples' == item:	
				detected_samples = sum(1 for items in response['results']['detected_referrer_samples'])
			if 'categories' == item and response['results']['categories']:		
				for items in response['results']['categories']:
					categories.append(items)

		domain_summary = { 'domain' : domainVar, 'permalink' : permalink, 'subdomains' : subdomains, 'siblings' : siblings, 'resolutions' : resolutions, 
						'detected_urls' : detected_urls, 'detected_samples' : detected_samples, 'categories' : categories, 'error' : error }	
					
	else:
		error = status
		if debug: 
			print('[*] VirusTotal message: '+str(status))

		domain_summary = { 'domain' : domainVar, 'error' : error }	

	# JSON Results for Domain
	container = {}	
	container['virustotal_domain'] = domain_summary
	return container

def search_file(hashVar):
	# Declare variables for later use
	status = ''
	error = ''
	tags = []
	additional_info = {}
	
	response =  vt.get_file_report(hashVar)
	status = check_response(response)

	# Parse file results if report exists
	if status == 'success':
		permalink = response['results']['permalink']		
		scan_date = response['results']['scan_date']	
		detection_ratio = str(response['results']['positives']) +'/'+ str(response['results']['total'])	
		# Private API
		# If the file had detections, gather additional data
		if response['results']['positives'] > 0:
			private =  vt_private.get_file_report(hashVar)			
			if 'results' in private:
				for item in private['results']:
					if item == 'first_seen':
						first_seen = private['results']['first_seen']
					if item == 'last_seen':
						last_seen = private['results']['last_seen']
					if item == 'submission_names':
						submission_names = sum(1 for items in private['results']['submission_names'])		
					if item == 'times_submitted':
						times_submitted = private['results']['times_submitted']
					if item == 'unique_sources':
						unique_sources = private['results']['unique_sources']
					if item == 'harmless_votes':
						harmless_votes = private['results']['harmless_votes']
					if item == 'malicious_votes':
						malicious_votes = private['results']['malicious_votes']
					if item == 'tags':
						for items in private['results']['tags']:
							tags.append(items)
				
				additional_info = { 'first_seen' : first_seen, 'last_seen' : last_seen, 'submission_names' : submission_names, 'times_submitted' : times_submitted,
					'unique_sources' : unique_sources, 'harmless_votes' : harmless_votes, 'malicious_votes' : malicious_votes, 'tags' : tags }

		file_summary = { 'file' : hashVar, 'detection_ratio' : detection_ratio, 'scan_date' : scan_date, 'permalink' : permalink, 'error' : error }
		
	else:
		error = status
		if debug:
			print('[*] VirusTotal message: '+str(status))
			
		file_summary = { 'file' : hashVar, 'error' : error}
	
	# JSON Results for file	
	container = {}	
	container['virustotal_file'] = file_summary
	# Append Private API data if there were file detections
	if additional_info:
		container['virustotal_file']['additional_info'] = additional_info

	return container

def search_ip(ipVar):
	# Declare variables for later use
	status = ''
	error = ''
	permalink = ''
	asn = ''	
	owner = ''	
	country = ''
	resolutions = ''	
	detected_urls = ''
	detected_communicating_samples = ''
	detected_downloaded_samples = ''

	response =  vt.get_ip_report(ipVar)
	status = check_response(response)
	
	# Parse ip results if report exists
	# Gather results as counts / statistics due to unknown volumes of detections or resolutions for a ip
	if status == 'success':
		permalink = 'https://virustotal.com/en/ip-address/{}/information/'.format(ipVar)
		for item in response['results']:
			#whois.arin.net for info on ASN
			if 'asn' == item:
				asn = response['results']['asn']
			if 'as_owner' == item:
				owner = response['results']['as_owner']
			if 'country' == item:
				country = response['results']['country']
			if 'resolutions' == item:	
				resolutions = sum(1 for items in response['results']['resolutions'])
			if 'detected_urls' == item:	
				detected_urls = sum(1 for items in response['results']['detected_urls'])				
			if 'detected_communicating_samples' == item:	
				detected_communicating_samples = sum(1 for items in response['results']['detected_communicating_samples'])
			if 'detected_downloaded_samples' == item:	
				detected_downloaded_samples = sum(1 for items in response['results']['detected_downloaded_samples'])				

		ip_summary = { 'ip' : ipVar, 'permalink' : permalink, 'asn' : asn, 'as_owner' : owner, 'country' : country, 'resolutions' : resolutions, 'detected_urls' : detected_urls,   
						'detected_communicating_samples' : detected_communicating_samples, 'detected_downloaded_samples' : detected_downloaded_samples, 'error' : error }	
				
	else:
		error = status
		if debug: 
			print('[*] VirusTotal message: '+str(status))
			
		ip_summary = { 'ip' : ipVar, 'error' : error }	

	# JSON Results for IP
	container = {}
	container['virustotal_ip'] = ip_summary
	return container

					
########################### SCANNING ###########################################################################################################
# IN DEVELOPMENT	
def scan_url(urlVar):
	response = vt.scan_url(inputVar)
	print(response)
	if response['results']['response_code'] == 1:
		if debug: print('[*] VirusTotal scan request successfully queued, waiting ', wait_time, ' seconds before checking report status.')
		sleep(wait_time)
		results = virustotal_search_url(urlVar)
		status, output = check_scan(results, urlVar)
		# Parse output based on status
	else:
		print('[!] ERROR: VirusTotal returned an unkwown error')
	
	
########################### MAIN ################################################################################################################
if __name__ == '__main__':
	#print(search_url('forpartinsa.ru/ls5/gate.php'))
	#print(search_ip('95.215.111.222')) #64.233.192.99
	#''lumy.galaxygiveaways.com'
	#print(search_domain('jrcnet.co.jp'))
	
	print(search_file('3c6f1916f8929e20bc476e694b50475eee89a0130902b6905d238fb8685a2ff8'))
	

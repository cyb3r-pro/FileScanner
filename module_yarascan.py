#!/usr/bin/env python

# Main function is handler_<object>
# Return should be structured as JSON, { <module> : { result : <result>, risk : <risk>, indicators : <[indicators]>, additional_info : { <custom> : <custom> } } }

from __future__ import print_function
from subprocess import Popen, PIPE
import os, yara, sys, re

# Custom imports
import filescan_config

# Set variables from config for later use
filescanner_source_dir = filescan_config.files_source_directory
filescanner_logs_dir = filescan_config.scan_logs_directory
yara_rule_dir = filescan_config.yara_dir

# Output JSON
module = 'yara'
output = {}

##
# MAIN
##
def handler_yara(file, md5, tool, args, source_dir):	
	result = 'No YARA matches'
	risk = 'Unknown Risk'
	indicators = []
	yara_rules = []
	
	# Create list of yara signatures to test against
	for each in os.listdir(yara_rule_dir):
		if re.search('.*\.yar$', each.lower()):
			yara_rules.append(yara_rule_dir+each)

	for rule in yara_rules:
		rules = yara.compile(rule)
		matches = rules.match(source_dir+file)
		if matches:
			risk = 'High Risk'
			for match in matches:
				for item in match.strings:
					detection = '[!] YARA: rule '+str(match.rule)+' - tags '+str(match.tags)+' : offset '+str(item[0]) + ' string '+str(item[2].decode())
					indicators.append(detection)
			#detection = '[!] YARA: '+str(matches[0].rule)+' - '+str(matches[0].tags)+' : '+str(matches[0].strings[3])
			#indicators.append(detection)
			with open(filescanner_logs_dir+file+'.txt', 'a') as l:
				print(detection, file=l)
	if indicators:
		matches = str(len(indicators))
		result = 'Matched '+matches+ ' YARA signature(s)'
	else:
		with open(filescanner_logs_dir+file+'.txt', 'a') as l:
			print('[*] No Yara rule matches', file=l)	
	
	##
	# OUTPUT
	##
	output[module] = {'result' : result, 'risk' : risk, 'indicators' : indicators } 
	output[module]['additional_info'] = {'md5' : md5}

	return output
	
#if __name__ == '__main__':
	#scan()
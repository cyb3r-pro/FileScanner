#!/usr/bin/env python

# Main function is handler_<object>
# Return should be structured as JSON, { <module> : { result : <result>, risk : <risk>, indicators : <[indicators]>, additional_info : { <custom> : <custom> } } }

from __future__ import print_function
from subprocess import Popen, PIPE
import re, sys

# Custom imports
import filescan_config

# Set variables from config for later use
filescanner_logs_dir = filescan_config.scan_logs_directory
filescanner_proc_dir = filescan_config.files_out_directory
peframe_exe = filescan_config.peframe_exe

# Output JSON
module = 'pe'
output = {}

##
# SUPPORT FUNCTIONS
##
def read_file(file_to_read):
	f = open(file_to_read, mode='r')
	lines = f.readlines()
	f.close()
	return lines


##        
# MAIN
##
def handler_pe(file, md5, tool, args, environment):
	risk = 'Unknown Risk'
	result = 'See detailed txt log'

	# List to hold summary of findings from pe analysis
	indicators = []    

	scan_exe_cmd = peframe_exe+' "'+filescanner_proc_dir+file+'" >> "'+filescanner_logs_dir+file+'.txt"'
	scan_exe_cmd_results = Popen(scan_exe_cmd, shell=True, stdout=PIPE).communicate()[0]      

	# Read exe results for printing to console
	data = read_file(filescanner_logs_dir+file+'.txt')
	
	# Print specific indicators to console
	for line in data:
		# Append discovered items to indicator list 
		# Example: Anti Debug discovered [4]
		if re.search(r"discovered", line):
			indicator = line.replace(' discovered',':').rstrip()
			indicator = indicator.replace('[','')
			indicator = indicator.replace(']','')			
			indicators.append(indicator)
		# Print indicator metadata to console             
		elif re.search(r"LegalCopyright", line): 
			print(" "+line.replace('\n',''))  
			sys.stdout.flush()				
		elif re.search(r"InternalName", line):     
			print(" "+line.replace('\n','')) 
			sys.stdout.flush()			
		elif re.search(r"CompanyName", line): 
			print(" "+line.replace('\n','')) 
			sys.stdout.flush()			
		elif re.search(r"FileDescription", line): 
			print(" "+line.replace('\n','')) 
			sys.stdout.flush()			
		elif re.search(r"OriginalFileName", line): 
			print(" "+line.replace('\n','')) 
			sys.stdout.flush()			
		elif re.search(r"(Packer)\W{2,}(?!.*Yes)", line): 
			print(" "+line.replace('\n',''))
			sys.stdout.flush()            
		elif re.search(r"Url\W\W", line): 
			print(" "+line.replace('\n',''))   
			sys.stdout.flush()
	
	##
	# OUTPUT
	##
	output[module] = {'result' : result, 'risk' : risk, 'indicators' : indicators } 
	output[module]['additional_info'] = {'md5' : md5}

	return output
	
#if __name__ == '__main__':
	#scan_exe()
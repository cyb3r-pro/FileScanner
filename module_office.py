#!/usr/bin/env python

# Main function is handler_<object>
# Return should be structured as JSON, { <module> : { result : <result>, risk : <risk>, indicators : <[indicators]>, additional_info : { <custom> : <custom> } } }

# Requires minimum oletools v0.50
from __future__ import print_function
import sys, os, re, argparse, time, platform
from subprocess import Popen, PIPE
import oletools.oleid
import oletools.mraptor
from oletools.olevba import VBA_Parser
from oletools.rtfobj import RtfObjParser

# Custom imports
import filescan_config

# Set variables from config for later use
working_dir = filescan_config.working_directory
filescanner_logs_dir = filescan_config.scan_logs_directory
filescanner_proc_dir = filescan_config.files_out_directory
rtfdump_dir = filescan_config.rtfdump_directory
rtfdump = filescan_config.rtfdump
oledump = filescan_config.oledump

# Output JSON
module = 'office'
output = {}

##
# SUPPORT FUNCTIONS
##
def string_clean(line):
	try:
		return ''.join([x for x in line if x in string.printable])
	except:
		return line

# If mode is shell, print string to console and to text log
def print_output(file, text, mode):
	if mode == 'shell': 
		print(text)
		sys.stdout.flush()
	outputfile = open(filescanner_logs_dir+file+'.txt', mode='a')
	outputfile.write(text)
	outputfile.write('\n')
	outputfile.close()        
		
def read_file(file_to_read):
	f = open(file_to_read, mode='r')
	lines = f.readlines()
	f.close()
	return lines
	
##        
# FLASH FUNCTIONS
##
# TODO


##
# MAIN RTF
##
def module_rtf(file, md5, tool, args):    
	has_objects = False
	objects_result = 'No embedded objects.'	
	has_shellcode = False 
	shellcode_result = 'No shellcode.' 	
	has_ole = False
	ole_result = 'No OLE package.'	
	has_pe = False
	pe_result = 'No executable.'  
	indicators = [] 	
	
	print_output(file, '\n\n-----------------------------------------\n[Scanning for embedded objects in RTF]\n-----------------------------------------\n', 'text') 
	# Read file for parsing
	data = open(filescanner_proc_dir+file, 'rb').read()	
	
	rtfp = RtfObjParser(data)
	rtfp.parse()

	for rtfobj in rtfp.objects:
		if rtfobj.is_ole:
			print_output(file, '[-] FOUND OLE OBJECT format_id: {} class name: {} size: {}'.format(rtfobj.format_id, rtfobj.class_name, rtfobj.oledata_size), 'shell')
			has_objects = True			
			objects_result = 'EMBEDDED OBJECTS FOUND.'	
			indicators.append(rtfobj.class_name)				
			
			if rtfobj.is_package:
				print_output(file, '[-] OLE PACKAGE filename: {} source path: {} temp path: {}'.format(rtfobj.filename, rtfobj.src_path, rtfobj.temp_path), 'shell')
				has_ole = True	
				ole_result = 'OLE PACKAGE'
				indicators.append(rtfobj.filename)
				
				# Check if the file extension is executable:
				objname, ext = os.path.splitext(rtfobj.filename)
				if re_executable_extensions.match(ext):
					print_output(file, '[!] EXECUTABLE FILE', 'shell')
					has_pe = True	
					pe_result = 'EXECUTABLE.'						
			else:
				print_output(file, '[-] Not an OLE Package', 'text')
		else:
			print_output(file, '[-] Not a well-formed OLE object', 'text')
		
	rtfdump_scan(file, '-i -f O') 

	if filescan.yara_scan(file, md5, tool, args, filescanner_proc_dir):
		has_shellcode = True  
		shellcode_result = 'SHELLCODE FOUND.'
		
	# Determine risk level and overall results        
	if has_objects == True and (has_ole == True or has_shellcode == True or has_pe == True):
		risk = 'High Risk'
	elif has_objects == True:
		risk = 'Medium Risk'

	result = objects_result + ' ' + ole_result + ' ' + shellcode_result + ' ' + pe_result  

	##
	# OUTPUT
	##
	output[module] = {'result' : result, 'risk' : risk, 'indicators' : indicators } 
	output[module]['additional_info'] = {'md5' : md5}	
	
	return output
	
def rtfdump_scan(file, option):  
	# File directory is assumed to be filescanner_proc_dir
	rtfdump_scan = rtfdump+' '+option+' "'+filescanner_proc_dir+file+'" >> "'+filescanner_logs_dir+file+'.txt"'
	rtfdump_scan_results = Popen(rtfdump_scan, shell=True, stdout=PIPE).communicate()[0]


##
# MAIN XML
##
def handler_xml(file, md5, tool, args): 
	printer_settings_bin = False
	suspicious_bin = False    
	has_macros = False
	indicators = []

	print_output(file, '\n\n[*] Scanning for embedded binaries', 'shell')
	# oledump with vbadecompress and extra calculated output (i.e. hashes)    
	oledump_scan(file, '-c -v')

	# Read results file to identify any embedded binary files        
	data = read_file(filescanner_logs_dir+file+'.txt')
	for line in data: 
		# Example: A: xl/printerSettings/printerSettings1.bin
		if re.search("(printerSettings).+\.bin", line):        
			printer_settings_bin = True
		# Example A: word/embeddings/oleObject1.bin            
		elif re.search(".*\.bin$", line):
			suspicious_bin = True
			bin_file = line.split('/')[-1].rstrip()
			
			# Print each found binary file to console and append to bin_files and indicators lists    
			print_output(file, '[-] '+bin_file, 'shell')           
			indicators.append('BINARY: '+bin_file)
	
	# Check for existance of macros    
	has_macros, ole_macro_result, macro_indicators = parse_vba(file)
	
	# Update indicators list with any detections from parsed VBA    
	indicators = macro_indicators + indicators	
	
	# Determine risk level based on binary and macro existence
	risk = 'Low Risk'   
	if printer_settings_bin == True and suspicious_bin == False and has_macros == False:
		risk = 'Low Risk'    
		result = 'Inflated. printerSettings.bin found'            
	elif suspicious_bin == True and has_macros == False:
		risk = 'Medium Risk'    
		result = 'Inflated. BINARY FOUND'            
	elif suspicious_bin == False and has_macros == True:
		risk = 'Medium Risk'
		result = 'Inflated. VB-MACRO FOUND'            
	elif suspicious_bin == True and has_macros == True:
		risk = 'High Risk'
		result = 'Inflated. BINARY FOUND. VB-MACRO FOUND'
	else:
		result = "Inflated. No binary found"    
			  
	##
	# OUTPUT
	##
	output[module] = {'result' : result, 'risk' : risk, 'indicators' : indicators } 
	output[module]['additional_info'] = {'md5' : md5}

	return output               
			

##
# MAIN OLE
##
def handler_ole(file, md5, tool, args):
	print_output(file, '\n-----------------------------------------\n[Analyzing with oleid]\n-----------------------------------------\n', 'text')	
	is_rtf = False  # FUTURE check to see if file is RTF and not OLE    
	has_macros = False
	has_flash = False
	has_shellcode = False   
	ole_macro_result = 'no vb-macro'
	ole_shellcode_result = 'no shellcode traces'
	ole_flash_result = 'no swf' 

	# TODO: Scan for shellcode with yara 
	# need to get rid of maldoc_OLE_file_magic_number in maldoc.yara but may be useful for RTF and XML
	
	oid = oletools.oleid.OleID(filescanner_proc_dir+file)

	results = oid.check()    
	print_output(file, '[-] Indicator', 'text')
	print_output(file, '', 'shell')	
	for i in results:
		#print_output(file, '{}: {}'.format(i.name, repr(i.value)), 'text')
		if i.value == True:
			print_output(file, '{}: {}'.format(i.name, repr(i.value)), 'shell')
		elif i.value == False:
			print_output(file, '{}: {}'.format(i.name, repr(i.value)), 'text')				
		else:
			print_output(file, '{}: {}'.format(i.name, repr(i.value)), 'shell')	
			
		# Macro Check        
		if i.name == 'VBA Macros' and i.value == True:
			has_macros = True  
			ole_macro_result = 'VB-MACRO FOUND'             
		# Flash Check                
		if i.name == 'Flash objects' and i.value != 0:
			has_flash = True  
			ole_flash_result = 'EMBEDDED SWF FOUND'             

	has_macros, ole_macro_result, macro_indicators = parse_vba(file)
	
	# Determine risk level and overall results
	result = ole_macro_result+'. '+ole_shellcode_result+'. '+ole_flash_result
	indicators = macro_indicators
	risk = 'No Risk'
	
	if has_macros == False and has_shellcode == False and has_flash == False:
		risk = 'Low Risk'   
	if has_macros == True or has_shellcode == True or has_flash == True:
		risk = 'Medium Risk'
	if has_macros == True and has_shellcode == True:
		risk = 'High Risk'  

	##
	# OUTPUT
	##
	output[module] = {'result' : result, 'risk' : risk, 'indicators' : indicators } 
	output[module]['additional_info'] = {'md5' : md5, 'is_rtf' : is_rtf}

	return output  
	
	  
def oledump_scan(file, option): 
	print_output(file, '\n-----------------------------------------\n[Analyzing with oledump]\n-----------------------------------------\n', 'text')
	# File directory is assumed to be filescanner_proc_dir
	oledump_scan = oledump+' '+option+' "'+filescanner_proc_dir+file+'" >> "'+filescanner_logs_dir+file+'.txt"'
	oledump_scan_results = Popen(oledump_scan, shell=True, stdout=PIPE).communicate()[0] 

	
##
# VBA Functions 
##
def parse_vba(file):
	print_output(file, '\n\n-----------------------------------------\n[Analyzing with olevba]\n-----------------------------------------\n', 'text')
	ole_macro_result = 'no vb-macro'    
	has_macros = False
	
	indicators = []
	macro_indicators = []	
	
	vbaparser = VBA_Parser(filescanner_proc_dir+file)
	# Check for Macros
	if not vbaparser.detect_vba_macros():
		print_output(file, '[-] No Macros Found', 'text') 
		return has_macros, ole_macro_result, indicators

	if True:
		print_output(file, '[-] MACROS FOUND', 'text')   
		has_macros = True
		ole_macro_result = 'VB-MACRO FOUND'     
		
		# Variable to be passed to MacroRaptor    
		vba_code_all_modules = ''
	
		for (filename, stream_path, vba_filename, vba_code) in vbaparser.extract_all_macros():
			vba_code_all_modules += vba_code + '\n'        
		
		for (filename, stream_path, vba_filename, vba_code) in vbaparser.extract_macros():
			print_output(file, '\nOLE Stream: {0}'.format(string_clean(stream_path)), 'text')
			print_output(file, 'VBA Filename: {0}'.format(string_clean(vba_filename)), 'text')            
			# Analyse the VBA Code      
			results = vbaparser.analyze_macros(show_decoded_strings=True)
			for kw_type, keyword, description in results:                
				# Add IOC detections to indicators list
				if kw_type == 'IOC':            
					indicators.append(description+': '+keyword)
					print_output(file, '{} - {} - {}'.format(kw_type, keyword, description), 'shell')
					
				else:            
					print_output(file, '{} - {} - {}'.format(kw_type, keyword, description), 'text')					

			# Deobfusgate and return macro code
			# print_output(file, '\n'+vbaparser.reveal(), 'text')
			
		# Print number of items in each category and append to indicators list
		print_output(file, '', 'shell')       
		print_output(file, 'AutoExec keywords: {}'.format(vbaparser.nb_autoexec), 'shell')
		if vbaparser.nb_autoexec != 0: 
			indicators.append('AutoExec keywords: {}'.format(vbaparser.nb_autoexec)) 	
			
		print_output(file, 'Suspicious keywords: {}'.format(vbaparser.nb_suspicious), 'shell')
		if vbaparser.nb_suspicious != 0: 
			indicators.append('Suspicious keywords: {}'.format(vbaparser.nb_suspicious)) 		
		
		print_output(file, 'IOCs: {}'.format(vbaparser.nb_iocs), 'shell')
		
		print_output(file, 'Hex obfuscated strings: {}'.format(vbaparser.nb_hexstrings), 'shell')
		if vbaparser.nb_hexstrings != 0: 
			indicators.append('Hex obfuscated strings: {}'.format(vbaparser.nb_hexstrings)) 		
		
		print_output(file, 'Base64 obfuscated strings: {}'.format(vbaparser.nb_base64strings), 'shell')
		if vbaparser.nb_base64strings != 0: 
			indicators.append('Base64 obfuscated strings: {}'.format(vbaparser.nb_base64strings)) 		
		
		print_output(file, 'Dridex obfuscated strings: {}'.format(vbaparser.nb_dridexstrings), 'shell')
		if vbaparser.nb_dridexstrings != 0: 
			indicators.append('Dridex obfuscated strings: {}'.format(vbaparser.nb_dridexstrings)) 		
		
		print_output(file, 'VBA obfuscated strings: {}'.format(vbaparser.nb_vbastrings), 'shell')  
		if vbaparser.nb_vbastrings != 0: 
			indicators.append('VBA obfuscated strings: {}'.format(vbaparser.nb_vbastrings)) 
		
		# Update indicators list with matches from MRaptor
		macro_indicators = scan_macro(file, vba_code_all_modules)
		indicators = indicators + macro_indicators
		
		# Use oledump to gather VBA code for archiving		
		oledump_scan(file, '-p plugin_vba_summary.py')
		
	# Close the file
	vbaparser.close()   
	
	return has_macros, ole_macro_result, indicators

def scan_macro(file, vba_code):
	print_output(file, '\n\n-----------------------------------------\n[Analyzing with MacroRaptor]\n-----------------------------------------', 'text')
	exitcode = -1
	global_result = None   
	indicators = []  	
	
	mraptor = oletools.mraptor.MacroRaptor(vba_code)

	mraptor.scan()
	if mraptor.suspicious:
		result = oletools.mraptor.Result_Suspicious
	else:
		result = oletools.mraptor.Result_MacroOK

	mraptor_results = '\n[-] ' + result.name.lstrip() + '  ' +mraptor.get_flags()       
	print_output(file, mraptor_results, 'shell')
	
	if mraptor.matches:
		# Add matches to indicators list  	
		indicators = mraptor.matches  	
		mraptor_matches = '[-] Matches: %r' % mraptor.matches + '\n'   
		print_output(file, mraptor_matches, 'shell')
	else:
		result = oletools.mraptor.Result_NoMacro
		mraptor_nomatches = result.name        
		print_output(file, mraptor_nomatches, 'shell')

	if result.exit_code > exitcode:
		global_result = result
		exitcode = result.exit_code

	print_output(file, 'Flags: A=AutoExec, W=Write, X=Execute', 'text')      
	print_output(file, 'Exit code: {} - {}'.format(exitcode, global_result.name)+'\n', 'text')

	return indicators	

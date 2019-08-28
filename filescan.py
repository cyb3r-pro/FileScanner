#!/usr/bin/env python
# FileScanner - Static Analysis Threat Indicator Scanner - 2019 
#
# FileScanner is a Python 3.x script which utilizes a variety of other tools/scripts to analyze multiple filetypes. Static analysis is
# supported for Office files, PDFs, and PEs/DLLs. Limited analysis of all other filetypes through Yara and VirusTotal search.
# 
# -----------------------------------------------------------------------------------------------
# CHANGE LOG:
#
# TODO:
# Error controls
# Standardize YARA and VirusTotal modules
#
# Common imports
from __future__ import print_function
from subprocess import Popen, PIPE
import argparse
import shutil, re, os, datetime, hashlib, io, sys, string, zipfile, platform
import csv, operator
import sqlite3
import magic, mimetypes, yara

# Custom imports
import filescan_config
import module_pdf, module_office, module_pe, module_yarascan, module_virustotal

# Determine environment to run tools appropriately
environment = platform.system() # Will return 'Windows' for Windows OS

# Account for unrecognized characters in print_console_head() (Python3.x)
sys.stdout = io.TextIOWrapper(sys.stdout.buffer,encoding=sys.stdout.encoding,errors='replace')

# Set variables from config for later use
python2 = filescan_config.python2
# Directories
working_dir = filescan_config.working_directory
filescanner_csv = filescan_config.filescanner_csv_log
filescanner_source_dir = filescan_config.files_source_directory
filescanner_skipped_dir = filescan_config.files_not_scanned_directory
filescanner_proc_dir = filescan_config.files_out_directory
filescanner_bad_dir = filescan_config.custom_bad_directory
filescanner_good_dir = filescan_config.custom_good_directory
filescanner_undecided_dir = filescan_config.custom_undecided_directory
filescanner_unsupported_dir = filescan_config.custom_unsupported_directory
filescanner_logs_dir = filescan_config.scan_logs_directory
# Tools
yara_dir = filescan_config.yara_dir
pdf_dir = filescan_config.pdf_tools_directory
ole_dir = filescan_config.oledump_directory
rtf_dir = filescan_config.rtfdump_directory
pe_dir = filescan_config.peframe_directory
peepdf = filescan_config.peepdf
vt_pub_key = filescan_config.vt_pub_key
vt_priv_key = filescan_config.vt_priv_key


def set_directories():
	# Make processing directories if necessary
	for directory in filescan_config.processing_dirs:
		if not os.path.exists(directory): os.mkdir(directory)
	# Ensure tool directories exist
	tool_directories = [yara_dir, pdf_dir, ole_dir, rtf_dir, pe_dir]
	for directory in tool_directories:
		if not os.path.exists(directory):
			print('[!] ERROR: Tool directory '+directory+' does not exist and is required for processing')
			sys.exit()

########################### CLEAR DIRECTORIES & ERROR LOGS #####################################################################################################################
def clear_files(dir):
	files = os.listdir(dir)
	for f in files:
		try: os.remove(dir+f)
		except: pass #print('[!] ERROR: Unable to remove files in ' +dir+ '\n\n')
def clear_errors(dir):
	try: os.remove(dir+'errors.txt')  	# Clear peepdf errors file if exists
	except: pass
	try: os.remove(dir+'has.bin')     	# Leftover has binary log if exists
	except: pass
	try: os.remove(dir+'jserror.log')	# Leftover jserror log if exists
	except: pass
########################### RENAME FILES BASED ON MD5 HASH #####################################################################################################################
def rename_filescan_source_dir(args, dir):    
	listing = os.listdir(dir)
	for file in listing:
		if os.path.isfile(dir+file):
			# Gather MD5 for renaming file and log results appropriately		
			md5 = get_hash(dir,file)
			if args.output == 'csv':			
				output_to_csv(md5, file, 'Filename')
			elif args.output == 'sql':			
				# Default DB Name assumed filescanner.sqlite
				output_to_file_db(database_directory+'filescanner.sqlite', md5, file)	
				
			# Rename file
			new_file = md5
				
			# If new_file already exists, i.e. different files with same hash, delete original file to avoid duplicate scanning
			if not os.path.exists(dir+new_file):
				os.rename(os.path.join(dir,file), os.path.join(dir, new_file))
			# Check if provided file was already named as MD5
			elif new_file == file:
				break					
			else:
				os.remove(dir+file)  			
			
########################### ZIP SUPPORT ########################################################################################################################################
def check_zip(dir):
	passwords = ['infected','virus']
	listing = os.listdir(dir)

	for file in listing:
		if re.search('.*\.zip$', file.lower()):
			zf = zipfile.ZipFile(dir+file,'r')
			for name in zf.namelist():
				try:
					zf.extract(name,dir,pwd=None)
				except:
					for password in passwords:				
						password = bytes([ord(x) for x in password]) #Python3., must convert to bytes
						try:
							zf.extract(name,dir,pwd=password)
						except:
							#passw = password.decode('utf-8') # Python3.x
							#print('[!] ERROR: "'+passw+'" is not a valid password for archive '+name)				
							break
			zf.close()
			os.remove(dir+file)
################################ HEADER ################################################################################################################################################
def get_filetype(dir):
	for file in os.listdir(dir):
		if os.path.isfile(dir+file):	
			# Get MIME type of file
			mime = magic.from_file(dir+file)
			# Attempt to guess the appropriate extension (doesn't always work); if all else fails, assign '.txt'
			ext = mimetypes.guess_extension(mime, strict=1)
			file_name = os.path.splitext(file)[0]
			if not ext:
				if re.search('PE32 executable', mime, re.I):
					ext = '.exe'
				elif re.search('pdf', mime, re.I):
					ext = '.pdf'
				else:
					ext = '.txt'
			os.rename(os.path.join(dir,file), os.path.join(dir, file_name+ext))
def scan_header(file):
	with open(filescanner_logs_dir+file+'.txt', 'a') as l:
		print(magic.from_file(filescanner_source_dir+file), file=l)
def eval_header(file, md5, args):
	tool = 'Filetype Head/Magic'
	header_results = [] # For those files where split detection of signatures; ie, 20 % / 80 %
	risk = 'Unknown Risk'	
	
	data = read_file(filescanner_logs_dir+file+'.txt')
	for line in data:
		# Matches 1, 2 or 3 digit percent detections in log	
		if re.search('^\s{0,2}[0-9]{1,3}\.[0-9]%', line):
			header_results.append(line[:-1].lstrip())

	# Results
	string_header = ' | '.join(header_results)	
	# Print to command line and add to CSV output (if specified) for each header result
	for each in header_results:	
		print(' '+each)
		sys.stdout.flush()
		if args.output == 'csv':        
			output_to_csv(md5, each, tool)
	# If output is SQL join header results by pipe and only create one entry
	if args.output == 'sql':
		# Default DB Name assumed filescanner.sqlite	        
		output_to_summary_db(args.incident, database_directory+'filescanner.sqlite', md5, tool, string_header, risk, '')
			
################################ HASHING ##############################################################################################################################################
def get_hash(dir,file):
	hasher = hashlib.md5()
	with open(dir+file,'rb') as f:
		for chunk in iter(lambda: f.read(8192), b''):
			hasher.update(chunk)
	return hasher.hexdigest()

########################### MOVE OUT FILES FROM SOURCE NOT WORTH SCANNING ######################################################################################################
def filter_filetype(args, file):
	# Move unsupported filetypes thereby reducing the time used scanning
	unsupported_filetypes = ['msg', 'html', 'htm', 'css', 'txt', 'csv', 'png', 'jpg', 'jpeg', 'gif', 'dat', 'wav', 'ics', 'mp4', 'wmz', 'mso', 
							'eml', 'p7s', 'tnef', 'rle', 'bmp', '3g2', 'm4v', 'vcf']
	if os.path.isfile(filescanner_source_dir+file):
		for each in unsupported_filetypes:
			if re.search('.*\.'+each+'$', file):
				md5 = get_hash(filescanner_source_dir,file)
				try:
					shutil.move(filescanner_source_dir+file, filescanner_skipped_dir+file)
					print('')					
					print('-'*(110-(len(file)))+file+'\nUNSUPPORTED FILE EXTENSION\n\nMoving file to: '+filescanner_skipped_dir)
					print('-'*110)					
					if args.output == 'csv':                    
						output_to_csv(md5, 'UNSUPPORTED FILETYPE', 'N/A')						
				except: 
					print('[!] ERROR: Failed to move '+file+' to '+filescanner_skipped_dir)  
					sys.stdout.flush()			
########################### VIRUSTOTAL ###########################################################################################################################################
def virustotal_search(args,dir):
	# Ensure files exist in source directory to scan
	count = sum(1 for file in os.listdir(dir) if os.path.isfile(os.path.join(dir, file)))
	if count == 0:
		print('\n[!] No files were found in the source directory.....please try again\n')
		sys.stdout.flush()	
		sys.exit()
	else:
		# Skip VT search if specified via argument
		if args.novt:	
			print('\n[*] Skipping VirusTotal search...Proceeding to scan '+str(count)+' files.....')
			sys.stdout.flush()		
			move_files(dir,filescanner_proc_dir)
		# Skip VT search if no API key was provided
		elif not vt_priv_key and not vt_pub_key:
			print('\n[*] Skipping VirusTotal search (No API key provided)...Proceeding to scan '+str(count)+' files.....')
			sys.stdout.flush()		
			move_files(dir,filescanner_proc_dir)			

		# Search each file in source directory
		else:
			print('='*35)
			sys.stdout.flush()
			print('\n[*] Searching VirusTotal for '+str(count)+' file(s)...')
			sys.stdout.flush()
			
			for file in os.listdir(dir):		
				if os.path.isfile(dir+file):
					md5 = get_hash(dir,file)
					risk = 'Unknown Risk'	
					vt_result = ''						

					print_to_log(file,'virustotal')
					# TODO: Based on results determine risk, and build list of detections
					detections = ''
					
					# Results
					r = module_virustotal.search_file(md5)
					if not r['virustotal_file']['error']:
						vt_result = r['virustotal_file']['detection_ratio']
				
					if args.output == 'csv':                    
						output_to_csv(md5, vt_result, 'virustotal')						
					elif args.output == 'sql': 
						# Default DB Name assumed filescanner.sqlite						
						output_to_summary_db(args.incident, database_directory+'filescanner.sqlite', md5, "virustotal", vt_result, risk, detections)							

			move_files(dir,filescanner_proc_dir)

############################### READ FILE ###########################################################################################################################################
def read_file(file_to_read):
	f = open(file_to_read, mode='r')
	lines = f.readlines()
	f.close()
	return lines
################################# SORT FILES #########################################################################################################################################
def sort_files(args, dir):
	for file in os.listdir(dir):
		if os.path.isfile(dir+file):
			all_files.append(file)
	# Sort all files list into filetype stacks
	for file in all_files:
		if re.search('.*\.pdf$', file.lower()):
			pdf_files.append(file)
		elif ( re.search('.*\.do(c$|cm$)', file.lower()) or re.search('.*\.xl(s$|sm$)', file.lower()) or re.search('.*\.pp(t$|tm$)', file.lower()) or re.search('.*\.pp(s$|sm$)', file.lower()) or re.search('.*\.md(b$|bm$)', file.lower()) ):
			ole_files.append(file)
			# MACRO .docm, .xlsm, .pptm, .dotm, .xltm, .xlam, .potm, .ppam, .ppsm, .sldm
		elif ( re.search('.*\.docx$', file.lower()) or re.search('.*\.xlsx$', file.lower()) or re.search('.*\.pptx$', file.lower()) or re.search('.*\.mdbx$', file.lower()) ):
			xml_files.append(file)
		elif ( re.search('.*\.rtf$', file.lower()) ):
			rtf_files.append(file)
		elif ( re.search('.*\.exe$', file.lower()) or re.search('.*\.dll$', file.lower())):
			exe_files.append(file)
		else:
			md5 = get_hash(dir,file)
			print('')
			print('-'*(110-(len(file))) +file+ '\nUNSUPPORTED FILE EXTENSION\n\nMoving file to: '+filescanner_unsupported_dir)			
			print('-'*110)	

			shutil.move(dir+file,filescanner_unsupported_dir+file)
			if args.output == 'csv':        
				output_to_csv(md5, 'UNSUPPORTED FILETYPE', 'Filetype Head/Magic')
############################## MOVE AROUND ##############################################################################################################################################
def copy_file(file,src,dst):
	# Make directory if it doesn't exist
	if not os.path.exists(dst):
		os.mkdir(dst)
	shutil.copy(src+file, dst)
def move_files(src,dst):
	listing = os.listdir(src)
	for file in listing:
		if os.path.isfile(src+file):
			shutil.move(src+file, dst+file)
def move_file_good(file):
	dst = filescanner_good_dir+file
	if os.path.exists(dst):                                # If destination file already exists, delete it prior to moving source file
		os.remove(dst)
	shutil.move(filescanner_proc_dir+file, dst)                        # Move file
	copy_file(file+'.txt',filescanner_logs_dir,filescanner_good_dir)            # Copy results txt file
def move_file_bad(file):
	if not os.path.isdir(filescanner_bad_dir+file):                 # If destination is not a directory
		if os.path.isfile(filescanner_bad_dir+file):                # If destination file already exists, delete it prior to moving source file
			os.remove(filescanner_bad_dir+file)
		shutil.move(filescanner_proc_dir+file, filescanner_bad_dir+file)        # Move file
		copy_file(file+'.txt',filescanner_logs_dir,filescanner_bad_dir)        # Copy results txt file
	else:                                                # If the destination is a file specific directory
		filescanner_bad_dirFile = os.path.normcase(filescanner_bad_dir+file+'/')
		if os.path.isfile(filescanner_bad_dirFile+file):            # If destination file already exists, delete it prior to moving source file
			os.remove(filescanner_bad_dirFile+file)
		shutil.move(filescanner_proc_dir+file, filescanner_bad_dirFile+file)    # Move file
		copy_file(file+'.txt',filescanner_logs_dir, filescanner_bad_dirFile)    # Copy results txt file
############################### PRINTING #############################################################################################################################################
def print_console_head(file):
	print('')
	print('-'*(110-(len(file)))+' '+file)
	sys.stdout.flush()	
def print_console_tail(file):
	print('-'*110)
	sys.stdout.flush()	
def print_to_log(file, string):
	outputfile = open(filescanner_logs_dir+file+'.txt', mode='a')
	outputfile.write('\n-----------------------------------------\n')	
	outputfile.write('['+string+']')
	outputfile.write('\n-----------------------------------------\n')
	outputfile.close()
############################### DATETIME FORMATTING ######################################################################################################################################
def get_datetime():
	datetime1 = datetime.datetime.today()
	datetime2 = str(datetime1)
	#datetime3 = datetime2[:-7].replace(' ','_') YYYY-MM-DD_hh:mm:ss
	datetime3 = datetime2[:-7]
	return(datetime3)
############################### CSV LOGGING #############################################################################################################################################
def print_csv_header(f,list):
	filewriter = csv.writer(f, delimiter=',', lineterminator='\n')
	filewriter.writerow(list)
	f.close()
	
# Write data to CSV
def output_to_csv(md5, result, tool):
	timestamp = get_datetime()
	completed_without_error = False
	while(completed_without_error == False):
		try:
			with open(filescanner_csv, 'a') as f:	# For Python 3.x use newline ='' in open command, remove lineterminator in writer
				filewriter = csv.writer(f, delimiter=',', lineterminator='\n')
				filewriter.writerow([timestamp,md5,result,tool])
				completed_without_error = True
		except: 
				print('[!] ERROR: '+filescanner_csv+' is currently in use')	

# Ensure CSV exists for writing data to
def generate_filescanner_csv(dir):
	# Create CSV log if one doesn't exist
	num = sum(1 for file in os.listdir(dir) if re.search('.*\.csv$', file.lower()))
	if num == 0:
		with open(filescanner_csv, 'a') as f:
			print_csv_header(f,["TIMESTAMP","HASH","TOOL RESULT","TOOL"])
	else:
		log_exists = os.path.isfile(filescanner_csv)
		if not log_exists:
			with open(filescanner_csv, 'a') as f:
				print_csv_header(f,["TIMESTAMP","HASH","TOOL RESULT","TOOL"])

# Sort CSV by filename to group scan results for the same file
def sort_csv(csv_file):
	data = csv.reader(open(csv_file))
	# Skip header line to sort list	
	next(data, None)
	sortedlist = sorted(data, key=operator.itemgetter(1),reverse=True)
	# Write data back to csv_file
	with open(csv_file, 'w') as f:
		filewriter = csv.writer(f, delimiter=',', lineterminator='\n')
		filewriter.writerow(["TIMESTAMP","HASH","TOOL RESULT","TOOL"])
		for row in sortedlist:
			filewriter.writerow(row)
			
############################### DATABASE #################################################################################################################################################     
# Write to SQLite3 database_directory filescanner.sqlite	
def output_to_summary_db(incident, database, md5, tool, result, risk, indicators):
	try:
		timestamp = get_datetime()
		
		connect = sqlite3.connect(database)
		cursor = connect.cursor()
		tup = ( incident, timestamp, md5, tool, result, risk, indicators, timestamp )
		# Insert the record; if the record exists, ignore the error caused by the conflict with existing primary key combination		
		cursor.execute("INSERT OR IGNORE INTO fs_summary VALUES(?,?,?,?,?,?,?,?)",tup)
		# Update Archer incident if an incident was provided; update last_scanned timestamp and indicators of the record
		if incident:
			cursor.execute("UPDATE fs_summary SET last_scanned='"+timestamp+"', indicators='"+indicators+"', incident='"+incident+"' WHERE md5 = '"+md5+"' AND tool_result = '"+result+"'")	
		else:	
			cursor.execute("UPDATE fs_summary SET last_scanned='"+timestamp+"', indicators='"+indicators+"' WHERE md5 = '"+md5+"' AND tool_result = '"+result+"'")	
		del tup
		connect.commit()
		cursor.close()       
		
		return
	except sqlite3.Error as e:
		print('[!] ERROR: '+e.args[0])
		return

def output_to_file_db(database, md5, file):
	try:
		timestamp = get_datetime()
		
		connect = sqlite3.connect(database)
		cursor = connect.cursor()
		tup = ( timestamp, md5, file )
		# Insert the record; if the record exists, ignore the error caused by the conflict with existing primary key combination		
		cursor.execute("INSERT OR IGNORE INTO fs_filenames VALUES(?,?,?)",tup)
		del tup
		connect.commit()
		cursor.close()       
		
		return
	except sqlite3.Error as e:
		print('[!] ERROR: '+e.args[0])
		return

############################# SUPPORTIVE TOOLS ######################################################################################################################################
def submit_to_sandbox(args, file, md5):
	if environment == 'Windows':
		newline = '\r\n'		
	else:
		newline = '\n'

	print('\n[*] Sandbox integration not yet implemented')
	#sys.stdout.flush()
	#try:
		# If sample doesn't already exist in sandbox, submit it		
		# Else sample found -- create list of risk counts from sandboxes for printing and logging			
	#except:
		#print('[!] ERROR: Unable to submit to sandbox\n')
	# CSV logging
	#if args.output == 'csv':
		#output_to_csv(md5, 'Submitted', 'ThreatAnalyzer')
def yara_scan(args, file, source_dir):
	tool = 'yara'
	match_exists = False
	
	if os.path.isfile(source_dir+file):
		md5 = get_hash(source_dir,file)
		print_to_log(file,'Scanning against YARA signatures')
		r = module_yarascan.handler_yara(file, md5, tool, args, source_dir)
		# Check for matches
		key = list(r)[0]
		indicators = r[key]['indicators']
		if indicators:
			match_exists = True
		
		# Results
		print(' [*] Scanning against YARA signatures ... ')
		process_module_results(r, file, tool, environment, args)
		
	return match_exists
	
############################ MODULE PROCESSING ###########################################################################################################################################
def run_module(module, file, tool, args):
	print_console_head(file)
	md5 = get_hash(filescanner_proc_dir,file)
	print(' MD5: '+md5+'\n')
	sys.stdout.flush()
	eval_header(file, md5, args)	
		
	# Execute module
	r = module(file, md5, tool, args)
		
	return r
	
def process_module_results(r, file, tool, environment, args):
	key = list(r)[0]
	result = r[key]['result']
	risk = r[key]['risk']
	indicators = r[key]['indicators']
	additional_info = r[key]['additional_info']
	md5 = additional_info['md5']
	
	# Print indicators and overall risk to console
	for each in indicators:
		print(' '+each)
		sys.stdout.flush()
	if not tool == 'yara':
		print('\n Maliciousness: '+risk)
		sys.stdout.flush()

	# Bad files
	if risk == 'High Risk' or risk == 'Medium Risk':
		print('\n[!] '+file+' '+result)
		sys.stdout.flush()
		if args.sandbox:
			submit_to_sandbox(args, file, md5)
		if not tool == 'yara':
			move_file_bad(file)
		
		# Additional processing for PDFs
		if environment == 'Windows' and 'pdf' in tool.lower():
			print('[*] Opening '+file+ ' in peepdf for further review -- type help for options')
			sys.stdout.flush()				 
			# Additional scanning for suspicious PDFs using peepdf
			os.system('start /MIN '+peepdf+' -f -i "'+filescanner_bad_dir+file+'"')
			# Automatically open TXT log results for review
			os.system('start /MIN notepad.exe "'+filescanner_bad_dir+file+'.txt"')    #os.startfile(filescanner_bad_dir+file+'.txt')			

	# Good files
	else:
		if args.sandbox and tool == 'peframe':
			submit_to_sandbox(args, file, md5)
		if not tool == 'yara':
			move_file_good(file)
		
	# Save results
	string_indicators = ' | '.join(indicators)  		
	if args.output == 'csv':        
		output_to_csv(md5, risk+'. '+string_indicators, tool)			
	elif args.output == 'sql':
		# Default DB Name assumed filescanner.sqlite				
		output_to_summary_db(args.incident, database_directory+'filescanner.sqlite', md5, tool, result, risk, string_indicators)			

		
############################ FILETYPE PROCESSING #######################################################################################################################################
def process_pdf(args):
	# Determine PDF scanning tool for data output based on provided command line argument
	if args.pdf == 'pdfid':
		tool = 'PDFiD'
	else:
		tool = 'peepdf'
	
	for file in pdf_files:
		r = run_module(module_pdf.handler_pdf, file, tool, args)
		process_module_results(r, file, tool, environment, args)						
		print_console_tail(file)
def process_xml(args):
	tool = 'oletools'	
	for file in xml_files:
		# Scan XML with various oletools
		r = run_module(module_office.handler_xml, file, tool, args)
		process_module_results(r, file, tool, environment, args)
		print_console_tail(file)
def process_ole(args):
	tool = 'oletools'
	for file in ole_files:
		# Scan OLE with various oletools
		r = run_module(module_office.handler_ole, file, tool, args)

		# Check for RTF
		key = list(r)[0]
		additional_info = r[key]['additional_info']
		is_rtf = additional_info['is_rtf']	
		if is_rtf == True:
			print('[!] Found'+file[-4:]+'that is really Rich Text Format. Skipping OLE commands and adding to RTF stack to scan next.')
			sys.stdout.flush()		
			# Append to RTF file for re-scanning
			rtf_files.append(file)
		else:
			process_module_results(r, file, tool, environment, args)				
		print_console_tail(file)
def process_rtf(args):
	tool = 'oletools'	
	for file in rtf_files:
		# Scan RTF with RTFObj and RTFDump / Yara
		r = run_module(module_office.handler_rtf, file, tool, args)
		process_module_results(r, file, tool, environment, args)			
		print_console_tail(file)
def process_exe(args):
	tool = 'peframe'		
	for file in exe_files:
		# Scan EXE/DLL file with PEFRAME
		r = run_module(module_pe.handler_pe, file, tool, args)
		process_module_results(r, file, tool, environment, args)			
		print_console_tail(file)

############################# MAIN ######################################################################################################################################################
def main():
	# Command line parsing
	#global args
	parser = argparse.ArgumentParser(description='File Scanner', epilog='Example: filescan.py')	
	parser.add_argument('-d', '--deletesamples', choices=['benign','all'], default='benign', dest='deletesamples', help='delete previously scanned files excluding Files_BAD ("benign") or delete "all" previously scanned files')
	parser.add_argument('-f','--file', action='store', help='file to scan if not in Files_SOURCE directory')	
	parser.add_argument('-i','--incident', action='store', dest='incident', default='', help='Incident tracking number')
	parser.add_argument('-y','--yara', '--yarascan', action='store_true', default=False, dest='yara', help='scan files with yara signatures stored in \yara directory')
	parser.add_argument('-n','--novt', action='store_true', default=False, dest='novt', help='skip searching file hash in Virus Total, default=False')
	parser.add_argument('-s','--sandbox', action='store_true', default=False, dest='sandbox', help='submit to sandbox (not implemented), default=False')
	parser.add_argument('--pdf', choices=['pdfid','peepdf'], default='peepdf', dest='pdf', help='pdf scan choice, either pdfid & pdf-parser or peepdf (default is peepdf)')
	parser.add_argument('-o','--output', choices=['csv','sql', 'txt'], default='csv', dest='output', help=argparse.SUPPRESS)
	args = parser.parse_args()

	# Override some processing defaults so script works appropriately for Linux
	if environment != 'Windows':
		args.output = 'sql'
	
	# Ensure required directories exist
	set_directories()
	
	# Move any stuck files from last processing
	try: 
		move_files(filescanner_proc_dir,filescanner_source_dir)
	except: 
		pass
	
	# Clear directories from last use
	if args.deletesamples:    
		clear_files(filescanner_skipped_dir)
		clear_files(filescanner_unsupported_dir)
		clear_files(filescanner_good_dir)
		clear_files(filescanner_undecided_dir)
		if args.deletesamples == 'all':    
			shutil.rmtree(filescanner_bad_dir)
			sys.exit()
			
	# Clear error logs if exist
	clear_errors(working_dir)

	# CSV logging
	if args.output == 'csv':
		generate_filescanner_csv(filescanner_logs_dir)

	# If single file was provided, copy file to Files_SOURCE for scanning        
	if args.file:
		if not os.path.exists(args.file):
			parser.error('[!] ERROR: The provided file does not exist! Please ensure the full path is being provided!', args.file)
			sys.exit()
		shutil.copy(args.file, filescanner_source_dir)
	
	# Check for zipped samples and extract -- only supports passwords "infected", "virus" currently
	check_zip(filescanner_source_dir)
	# Rename files based on MD5 hash -- eliminates duplicate scanning
	rename_filescan_source_dir(args, filescanner_source_dir)
	# Get filetype from Magic bytes to ensure correct file extension for processing
	get_filetype(filescanner_source_dir)

	for file in os.listdir(filescanner_source_dir):
		if os.path.isfile(filescanner_source_dir+file):	
			# Collect header details for logging
			scan_header(file)
			# Scan against Yara rules
			if args.yara:		
				if yara_scan(args, file, filescanner_source_dir):
					pass					
			# Remove files not worth scanning further based on filetype
			filter_filetype(args, file)

	# Search against VirusTotal unless otherwise specified
	virustotal_search(args,filescanner_source_dir)

	# Sort files from Files_OUT into filetype stacks
	sort_files(args, filescanner_proc_dir)
	# Process various filetypes
	process_pdf(args)
	process_xml(args)
	process_ole(args)
	process_rtf(args)
	process_exe(args)
	
	# CSV log formatting
	if args.output == 'csv':
		sort_csv(filescanner_csv)
		print('\n[*] Most Recent Log appended to: '+filescanner_csv+'\n')	
		#if environment == 'Windows':			
			#excel_cmd = 'C:\Program Files (x86)\Microsoft Office\Office14\excel.exe '+filescanner_csv
			#opepsn_excel_with_log = Popen(excel_cmd, shell=True, stdout=PIPE).communicate()[0]    
			
all_files = []
pdf_files = []
ole_files = []
xml_files = []
rtf_files = []
exe_files = []
bad_files = []
good_files = []
yara_files = []
if __name__ == '__main__':
	main()

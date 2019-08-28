#!/usr/bin/env python

# Main function is handler_<object>
# Return should be structured as JSON, { <module> : { result : <result>, risk : <risk>, indicators : <[indicators]>, additional_info : { <custom> : <custom> } } }

from __future__ import print_function
from subprocess import Popen, PIPE
import re, os, string, sys

# Custom imports
import filescan_config

# Set variables from config for later use
filescanner_logs_dir = filescan_config.scan_logs_directory
filescanner_proc_dir = filescan_config.files_out_directory
pdf_tools = filescan_config.pdf_tools_directory
peepdf_dir = filescan_config.peepdf_directory
peepdf = filescan_config.peepdf
pdfid = filescan_config.pdfid
pdfparser = filescan_config.pdfparser

# Output JSON
module = 'pdf'
output = {}

##
# SUPPORT FUNCTIONS
##
def read_file(file_to_read):
    f = open(file_to_read, mode='r')
    lines = f.readlines()
    f.close()
    return lines
def print_to_log(file, string):
	outputfile = open(filescanner_logs_dir+file+'.txt', mode='a')
	outputfile.write('\n-----------------------------------------\n')	
	outputfile.write('['+string+']')
	outputfile.write('\n-----------------------------------------\n')
	outputfile.close()

##
# MAIN
##
def handler_pdf(file, md5, tool, args):	
	suspicious_indicator = 0	# variable to contain count for suspicious indicator groups
	indicators = []				# list to hold all suspicious indicator strings
	peepdf_error = ''			# variable to identify peepdf errors, either 'Y' or empty
	
	if tool == 'PDFiD':	
	     # PDFiD scan command
	     pdfid_cmd = pdfid+' "'+filescanner_proc_dir+file+'" >> "'+filescanner_logs_dir+file+'.txt"'    
	     pdfid_cmd_results = Popen(pdfid_cmd, shell=True, stdout=PIPE).communicate()[0]	
	else:	 
	     open(peepdf_dir+'errors.txt', 'w').close()	#clear any previous errors for peepdf 
	     # peepdf scan command
	     peepdf_cmd = peepdf+' -g -f "'+filescanner_proc_dir+file+'" >> "'+filescanner_logs_dir+file+'.txt"'
	     # print header to TXT results file
	     print_to_log(file,'PDF Structure')
	     try:	 
	         peepdf_cmd_results = Popen(peepdf_cmd, shell=True, stdout=PIPE, stderr=PIPE).communicate() #communicate() returns a tuple (stdout[0], stderr[1])	 
	     # Use PDFiD to scan PDF if peepdf returned an error
	     except:
		 #if peepdf_cmd_results[1]:
	         peepdf_error = 'Y'
	         pdfid_cmd = pdfid+' "'+filescanner_proc_dir+file+'" >> "'+filescanner_logs_dir+file+'.txt"'
	         pdfid_cmd_results = Popen(pdfid_cmd, shell=True, stdout=PIPE).communicate()[0] 	 

	# Determine obects contained within PDF based on scan results
	Page, Producer, Encrypt, AA, OpenAction, JS, JavaScript, RichMedia, EmbeddedFile, EmbeddedFiles, URI, doswf, exe, swf, ftpdown, laaan, U3D, PRC, Launch, AcroForm, XFA, Win, Action, JBIG2Decode, Names, SubmitForm, ImportData, CVE = pdf_objects(file)		 
	##############################################          	
		 		 
	if Producer: 
	     process_pdf_object(file, Producer, 'Producer', tool, peepdf_error)	 
	if Encrypt:	
	     process_pdf_object(file, Encrypt, 'Encrypt', tool, peepdf_error)
	     indicators.append('/Encrypt')		 
	if AA: 	
	     process_pdf_object(file, AA, 'AA', tool, peepdf_error)
	     indicators.append('/AA')			 
	if OpenAction:	
	     process_pdf_object(file, OpenAction, 'OpenAction', tool, peepdf_error)
	     indicators.append('/OpenAction')			 
	if JS:	
	     process_pdf_object(file, JS, 'JS', tool, peepdf_error)
	     indicators.append('/JS')			 
	if JavaScript:	
	     process_pdf_object(file, JavaScript, 'JavaScript', tool, peepdf_error)
	     indicators.append('/JavaScript')			 
	if RichMedia: 
	     process_pdf_object(file, RichMedia, 'RichMedia', tool, peepdf_error)	
	     indicators.append('/RichMedia')			 
	if EmbeddedFile:	
	     process_pdf_object(file, EmbeddedFile, 'EmbeddedFile', tool, peepdf_error)
	     indicators.append('/EmbeddedFile')			 
	if EmbeddedFiles:  #peepdf only
	     process_pdf_object(file, EmbeddedFiles, 'EmbeddedFiles', tool, peepdf_error)	
	     indicators.append('/EmbeddedFiles')			 
	if URI:		
	     process_pdf_object(file, URI, 'URI', tool, peepdf_error)
	     indicators.append('/URI')			 
	if doswf:		
	     process_pdf_object(file, doswf, 'doswf', tool, peepdf_error) 
	     indicators.append('dos')			 
	if exe:	
	     process_pdf_object(file, exe, 'exe', tool, peepdf_error)
	     indicators.append('exe')			 
	if swf:
	     process_pdf_object(file, swf, 'swf', tool, peepdf_error)
	     indicators.append('swf')			 
	if ftpdown:	
	     process_pdf_object(file, ftpdown, 'ftpdown', tool, peepdf_error)
	     indicators.append('ftpdown')			 
	if laaan:	
	     process_pdf_object(file, laaan, 'laaan', tool, peepdf_error)
	     indicators.append('laaan')			 
	if U3D: #peepdf only
	     process_pdf_object(file, U3D, 'U3D', tool, peepdf_error)	
	     indicators.append('/U3D')			 
	if PRC: #peepdf only
	     process_pdf_object(file, PRC, 'PRC', tool, peepdf_error)
	     indicators.append('/PRC')			 
	if Launch: 	
	     process_pdf_object(file, Launch, 'Launch', tool, peepdf_error) 
	     indicators.append('/Launch')			 
	if AcroForm:
	     process_pdf_object(file, AcroForm, 'AcroForm', tool, peepdf_error)
	     indicators.append('/AcroForm')			 
	if XFA:
	     process_pdf_object(file, XFA, 'XFA', tool, peepdf_error)
	     indicators.append('/XFA')			 
	if Win:		
	     process_pdf_object(file, Win, 'Win', tool, peepdf_error)
	     indicators.append('/Win')			 
	if Action:
	     process_pdf_object(file, Action, 'Action', tool, peepdf_error)
	     indicators.append('/Action')			 
	if JBIG2Decode:		
	     process_pdf_object(file, JBIG2Decode, 'JBIG2Decode', tool, peepdf_error)
	     indicators.append('/JBIG2Decode')			 
	if Names: #peepdf only	
	     process_pdf_object(file, Names, 'Names', tool, peepdf_error)
	     indicators.append('/Names')			 
	if SubmitForm: #peepdf only	
	     process_pdf_object(file, SubmitForm, 'SubmitForm', tool, peepdf_error)
	     indicators.append('/SubmitForm')			 
	if ImportData: #peepdf only		
	     process_pdf_object(file, ImportData, 'ImportData', tool, peepdf_error)
	     indicators.append('/ImportData')			 
	try:	
	    os.remove(pdf_tools+'peepdftemp.txt') 	 # remove peepdf tempfile
	except:	
	    pass				 
	###############################################	
	if CVE:
		suspicious_indicator = suspicious_indicator + 1
		CVE = CVE.split(':')[0].lstrip()
		indicators.append(CVE)		
	if AA or OpenAction:
		suspicious_indicator = suspicious_indicator + 1
	if JS or JavaScript or RichMedia or EmbeddedFile or EmbeddedFiles or URI or doswf or exe or swf or ftpdown or laaan or U3D or PRC or Action:
		suspicious_indicator = suspicious_indicator + 1         
	if Encrypt or Launch or AcroForm or XFA or Win or JBIG2Decode or Names or SubmitForm or ImportData:
		suspicious_indicator = suspicious_indicator + 1
		
	# Determine risk level based on identified strings
	if suspicious_indicator == 0:  
	    risk = 'No Risk'
	    indicators.append('No suspect strings found.')		
	elif suspicious_indicator == 1: risk = 'Low Risk'
	elif suspicious_indicator == 2: risk = 'Medium Risk'
	elif suspicious_indicator > 2: risk = 'High Risk'
	
	# Populate result
	# 2 or more suspicious indicator groupings in PDF
	if risk == 'High Risk' or risk == 'Medium Risk':
		result = 'Suspicious object combination found'			 
	# 1 or less suspicious indicator groupings in PDF
	else:
		result = 'No suspicious object combinations found'
			
	##
	# OUTPUT
	##
	output[module] = {'result' : result, 'risk' : risk, 'indicators' : indicators } 
	output[module]['additional_info'] = {'md5' : md5}

	return output

############################# PDF OBJECTS TO BE SCANNED ##################################################################################################################################
def pdf_objects(file): 			
	# Reset all pdf objs
	Page = ''
	Producer = ''	
	AA = ''    
	OpenAction = ''    
	JS = ''    
	JavaScript = ''
	RichMedia = ''
	EmbeddedFile = ''  
	EmbeddedFiles = '' #peepdf only   
	URI = ''       
	doswf = ''           
	exe = ''       
	swf = ''  
	ftpdown = ''  
	laaan = '' 
	U3D = '' #peepdf only
	PRC = '' #peepdf only   
	Encrypt = ''
	Launch = ''	
	AcroForm = ''
	XFA = ''
	Win = ''
	Action = ''
	JBIG2Decode = ''
	Names = '' #peepdf only  
	SubmitForm = '' #peepdf only  
	ImportData = ''#peepdf only
	CVE = ''#peepdf only
	
	# Read results file
	data = read_file(filescanner_logs_dir+file+'.txt')
	for line in data:
		if re.search(r"/Page.*[0-9]{1,9}", line): Page = line
		elif re.search(r"/Producer.*[1-9]{1,9}", line): Producer = line		
		elif re.search(r"/Encrypt.*[1-9]{1,9}", line): Encrypt = line
		# May autorun when opened; however, launches can be user enticed manual links in pdf
		elif re.search(r"/AA.*[1-9]{1,9}", line): AA = line
		elif re.search(r"/OpenAction.*[1-9]{1,9}", line): OpenAction = line
		# Embedding: script, code, files, or media
		elif re.search(r"/JS.*[1-9]{1,9}", line): JS = line
		elif re.search(r"/JavaScript.*[1-9]{1,9}", line): JavaScript = line
		elif re.search(r"/RichMedia.*[1-9]{1,9}", line): RichMedia = line
		elif re.search(r"/EmbeddedFile.*[1-9]{1,9}", line): EmbeddedFile = line
		elif re.search(r"/EmbeddedFiles.*[1-9]{1,9}", line): EmbeddedFiles = line         
		elif re.search(r"/URI.*[1-9]{1,9}", line): URI = line
		# Embedding: non-traditional indicators        
		elif re.search(r"doswf.*[1-9]{1,9}", line): doswf = line
		elif re.search(r"exe.*[1-9]{1,9}", line): exe = line
		elif re.search(r"swf.*[1-9]{1,9}", line): swf = line   
		elif re.search(r"ftpdown.*[1-9]{1,9}", line): ftpdown = line   
		elif re.search(r"laaan.*[1-9]{1,9}", line): laaan = line
		elif re.search(r"/U3D.*[1-9]{1,9}", line): U3D = line
		elif re.search(r"/PRC.*[1-9]{1,9}", line): PRC = line        
		# Supporting object types: facilitating obfuscation, encryption, compression, etc.
		elif re.search(r"/Launch.*[1-9]{1,9}", line): Launch = line
		elif re.search(r"/AcroForm.*[1-9]{1,9}", line): AcroForm = line
		elif re.search(r"/XFA.*[1-9]{1,9}", line): XFA = line
		elif re.search(r"/Win.*[1-9]{1,9}", line): Win = line
		elif re.search(r"/Action.*[1-9]{1,9}", line): Action = line
		elif re.search(r"/JBIG2Decode.*[1-9]{1,9}", line): JBIG2Decode = line
		elif re.search(r"/Names.*[1-9]{1,9}", line): Names = line
		elif re.search(r"/SubmitForm.*[1-9]{1,9}", line): SubmitForm = line        
		elif re.search(r"/ImportData.*[1-9]{1,9}", line): ImportData = line
		elif re.search(r"CVE-[0-9]{4}.*", line): CVE = line
		
	return Page, Producer, Encrypt, AA, OpenAction, JS, JavaScript, RichMedia, EmbeddedFile, EmbeddedFiles, URI, doswf, exe, swf, ftpdown, laaan, U3D, PRC, Launch, AcroForm, XFA, Win, Action, JBIG2Decode, Names, SubmitForm, ImportData, CVE
	
############################# PDF PROCESSING (PEEPDF) ####################################################################################################################################
# Process PDF objects
def process_pdf_object(file, object, strobject, tool, peepdf_error):
	if tool == 'PDFiD' or peepdf_error == 'Y': 
	    scan_pdfid_object(file,strobject)
	else:
	    objectScan = process_line(object)	         
	    # scan each object found in peepdf and pipe results to log, limit to 30 objects to iterate through
	    objects = len(objectScan)
	    if objects > 30: objectScan = objectScan[:30] 		
	    for num in objectScan: 
	        scan_pdf_object(file,strobject,num) 
# Process PDF string lines to pull out object numbers to iterate through
def process_line(string):
	stringScan = ''.join(string.split(':')[1:])
	stringScan_r1 = stringScan.replace('[','')	     
	stringScan_r2 = stringScan_r1.replace(']','')		 
	stringScan_l = stringScan_r2.split(',')		 
	return stringScan_l
# Scan suspicious PDF ojbects
def scan_pdf_object(file,strobject,num):
     open(pdf_tools+'peepdftemp.txt', 'w').close()	#ensure peepdf temp file exists and clear contents if so
     pdf_object_header = 'Examining '+strobject+' Object:'+num.replace('\n','')+''	  
     print_to_log(file, pdf_object_header)
     write_temp_pdf_object(num)
     scan_pdf_object = peepdf+' -f -i "'+filescanner_proc_dir+file+'" -s "'+pdf_tools+'peepdftemp.txt" >> "'+filescanner_logs_dir+file+'.txt"'  	 
     scan_pdf_object_results = Popen(scan_pdf_object, shell=True, stdout=PIPE).communicate()[0]
# Write PDF objects to temp file for scripting
def write_temp_pdf_object(num):
     t = open(pdf_tools+'peepdftemp.txt', 'w')
     t.write('object'+num+' ')
     t.close()
	 
############################ PDF PROCESSING (PDFID, PDF-PARSER) ##########################################################################################################################
def scan_pdfid_object(file,strobject):
    pdf_object_header = 'Searching '+strobject+' Objects'
    print_to_log(file, pdf_object_header)
    scan_pdfid_object = pdfparser+' --search ' +strobject+' "'+filescanner_proc_dir+file+'" >> "'+filescanner_logs_dir+file+'.txt"'	
    scan_pdfid_object_results = Popen(scan_pdfid_object, shell=True, stdout=PIPE).communicate()[0]

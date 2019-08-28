#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time, os, platform

environment = platform.system()

#[PYTHON]
python2 = 'python2'
python3 = ''

#[DIRECTORIES]
working_directory = os.path.normcase(os.getcwd()+'/')
parent_directory = os.path.abspath(os.path.join(working_directory, os.pardir))

#[FILESCANNER PROCESSING DIRECTORIES]
files_source_directory = os.path.normcase(working_directory+'Files_SOURCE/')
files_scanned_directory = os.path.normcase(working_directory+'Files_SCANNED/')
files_not_scanned_directory = os.path.normcase(working_directory+'Files_NOT_SCANNED/')
files_out_directory = os.path.normcase(working_directory+'Files_OUT/')
custom_bad_directory = os.path.normcase(working_directory+'Files_SCANNED/Custom_BAD/')
custom_good_directory = os.path.normcase(working_directory+'Files_SCANNED/Custom_GOOD/')
custom_undecided_directory = os.path.normcase(working_directory+'Files_SCANNED/Custom_UNDECIDED/')
custom_unsupported_directory = os.path.normcase(working_directory+'Files_SCANNED/Custom_UNSUPPORTED/')
scan_logs_directory = os.path.normcase(working_directory+'Logs/')
database_directory = os.path.normcase(working_directory+'SQLite/')

processing_dirs = [ files_source_directory, files_scanned_directory, files_not_scanned_directory, files_out_directory, custom_bad_directory, custom_good_directory, custom_undecided_directory, custom_unsupported_directory, scan_logs_directory, database_directory ]
 
#[LOGGING]
timestr = time.strftime('%Y-%m-%d')
filescanner_csv_log = scan_logs_directory+'fsLogFile_'+timestr+'.csv'
vt_log = os.path.normcase(working_directory+'Logs/vtLogFile_'+timestr+'.txt')

#[YARA]
yara_dir = os.path.normcase(working_directory+'yara/')

#[PDF TOOLS]
pdf_tools_directory = os.path.normcase(parent_directory+'/pdftools/')
peepdf_directory = os.path.normcase(parent_directory+'/pdftools/peepdf/')
peepdf = python2+' '+peepdf_directory+'peepdf.py'
pdfid = python2+' '+pdf_tools_directory+'pdfid.py'
pdfparser = python2+' '+pdf_tools_directory+'pdf-parser.py'

#[OFFICE TOOLS]
oledump_directory = os.path.normcase(parent_directory+'/oledump/')
rtfdump_directory = os.path.normcase(parent_directory+'/rtfdump/')
oledump = python2+' '+oledump_directory+'oledump.py'
rtfdump = python2+' '+rtfdump_directory+'rtfdump.py'

#[PE TOOLS]
peframe_directory = os.path.normcase(parent_directory+'/peframe/') 
peframe = python2+' peframe.py'    # For Linux, peframe can be executed directly from the shell
# Specify peframe exe location based on OS    
if environment == 'Windows':
	peframe_exe = 'cd '+peframe_directory+' & '+peframe
else:
	peframe_exe = 'peframe'   

#[String Validation]
url_pattern = r'(https?:\/\/)?((?:(\w+-)*\w+)\.)+(?:[a-z]{2})(\/?\w?-?=?_?\??&?)+[\.]?([a-z0-9\?=&_\-%#])?'	
url_scheme_pattern = r'^(http|ftp|mailto|telnet|ssh)(s){0,1}\:\/\/.*'
ip_pattern = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'	
md5_pattern = r'([a-f0-9]{32}|[A-F0-9]{32})'
sha1_pattern = r'([a-f0-9]{40}|[A-F0-9]{40})'	
sha256_pattern = r'([a-f0-9]{64}|[A-F0-9]{64})'
filename_pattern = r'([A-Za-z0-9-_\.]+\.(exe|dll|bat|sys|htm|html|js|jar|jpg|png|vb|scr|pif|chm|zip|rar|cab|pdf|doc|docx|ppt|pptx|xls|xlsx|swf|gif))'		
email_pattern = r'([a-z][_a-z0-9-.]+@[a-z0-9-]+\.[a-z\.]+)'

#[VirusTotal]
vt_pub_key = ''	
vt_priv_key = ''

#[Proxy]
proxy = False
proxy_port = ''
proxy_host = ''
proxy_http = 'http://{}:{}/'.format(proxy_host, proxy_port)
proxy_https = 'https://{}:{}/'.format(proxy_host, proxy_port)


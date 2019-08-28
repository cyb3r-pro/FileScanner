# FileScanner
FileScanner is a Python 3.x script which utilizes a variety of other tools/scripts to analyze multiple filetypes. Static analysis is supported for Office files, PDFs, and PEs/DLLs. Limited analysis of all other filetypes through YARA and VirusTotal search

pip install -r REQUIREMENTS

Modify filescan_config.py with the following
<br />-directory to PDF tools (peepdf and pdfid/pdf-parser), expected to be in the same directory as FileScanner by default
<br />-directory to PEFRAME, expected to be in the same directory as FileScanner by default
<br />-directory to Oledump and Rtfdump, expected to be in the same directory as FileScanner by default
<br />-VirusTotal private or public API key
<br />-proxy if applicable

For modules, the general idea is to is to name the module as module_<insert>.py and create a main method as handler_<module_type>()
The main method in a module should return JSON as:
{ module : 
{ result : 'result', risk : 'risk', indicators : [indicators], additional_info : { custom : 'custom' } } 
}

This project is not in a completed state

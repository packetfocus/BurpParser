# BurpParser
    Parser to convert BURP Pro .XML to .CSV and build a Word .Docx Template
    *NOTE: The order in which the vulns are presented depends on the order they are in 
    when the .xml file is generated. In Burp Pro, goto Issues and sort them 'High to Low'
    in the view. That will sort them when put into the Word and CSV document. 

# Install

    pip install -r requirements.txt
   Then:
    python BurpXMLParser.py -i examples\vuln_app_example.xml -o output\exampleOut.doc -c output\exampleOut.csv

# Requirements
    Requires Python 3.x

Requires Beautiful Soup 4

    apt-get install python3-bs4 (for Python 3)
 OR
 
    pip install beautifulsoup4

Requires Python Docx

    pip install python-docx
  
# Get .XML from Burp
  Using burp Pro, go into the issues section. Highlight the issues you want to report on then right-click and save as .xml report. Use the standard options and layout for the .XML file. 

# USAGE
Provide the single .xml input file to be used, and the Word Output file.

    python BurpXMLParser.py -i xml\auth-scan-1.xml -o output\josh_out.docx -c output\outfile.csv

Process an entire dir of .xml files
            
           python BurpXMLParser.py  -o output\outfile.doc -c output\outfile.csv -d examples


C:\code\BurpParser>python BurpXMLParser.py -help

Usage: BurpXMLParser.py [options]

Options:

     -h, --help            show this help message and exit
     -i XML_INPUTFILE, --xml-inputFile=XML_INPUTFILE
                        *[REQUIRED]: Specify XML Input File
     -o DOC_OUTPUTFILE, --word-outputFile=DOC_OUTPUTFILE
                        *[REQUIRED]: Specify WORD .Doc/Docx Output File
     -c CSV_OUTPUTFILE, --csv-outputFile=CSV_OUTPUTFILE
                        *[REQUIRED]: Specify CSV Output File
     -d XML_PROCESSDIR, --xml-directoryImport=XML_PROCESSDIR
                        [OPTIONAL]: Provide just a DIR to process all xml
                        files




# ISSUES!?!

Haven't tested using full paths yet, so until its tested use paths for -i , -c and -o as shown below. 
The xml/ and output/ directories are created by default.

        python BurpXMLParser.py -i xml\auth-scan-1.xml -o output\josh_out.docx -c output\outfile.csv

        
        
# Tested
        -Tested on Windows 10 with python 3 (WORKING)
        -Tested on Linux (WORKING)
        -NotTested on Mac
        
# Examples

   There is an example .xml file in the examples/ folder.
   
   Process a single .xml file
    
           python BurpXMLParser.py -i examples\vuln_app_example.xml -o output\exampleOut.doc -c output\exampleOut.csv  
   
   Process an entire dir of .xml files
            
           python BurpXMLParser.py  -o output\outfile.doc -c output\outfile.csv -d examples

       
# Known Constraints
            TBD
        
 # TO DO
    Add Multiple Word Templates
   
# Features
    Parses .XML scan files from Burp Pro (Not sure if you can export .xml in CE)
    Added Logging into logs
    Added CLI options
    Added ability to parse all .xml files in directory with -d
    Usable supplied Word Doc Output Template
    Craeates output CSV file

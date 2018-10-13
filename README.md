# BurpParser
    Parser to convert BURP Pro .XML to .CSV and build a Word .Docx Template

# Install

    pip install -r requirements.txt

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
*Provide the single .xml input file to be used, and the Word Output file.

    python BurpXMLParser.py -i xml\auth-scan-1.xml -o output\josh_out.docx


C:\code\BurpParser>python BurpXMLParser.py -help

 2018-10-12 19:02 -  INFO - Using XML Input File:
 
 2018-10-12 19:02 -  INFO - Creating Word Dcument : output\demo.docx
 
Usage: BurpXMLParser.py [options]


Options:

      -h, --help            show this help message and exit
      -i XML_INPUTFILE, --xml-inputFile=XML_INPUTFILE
                        *[REQUIRED]: Specify XML Input File
      -o DOC_OUTPUTFILE, --word-outputFile=DOC_OUTPUTFILE
                        *[REQUIRED]: Specify WORD .Doc/Docx Output File


# ISSUES!?!

Haven't tested using full paths yet, so until its tested use paths for -i and -o as shown below. 
The xml/ and output/ directories are created by default.

        python BurpXMLParser.py -i xml\auth-scan-1.xml -o output\josh_out.docx
        
        
# Tested
        -Tested on Windows 10 with python 3 (WORKING)
        -NotTested on Linux
        -NotTested on Mac
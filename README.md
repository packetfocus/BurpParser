# BurpParser
Parser to convert BURP Pro .XML to .CSV and build a Word .Docx Template

#Install
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

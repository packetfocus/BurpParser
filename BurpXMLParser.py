# Burp Pro XML parser
# Converts to CSV and makes a Word Template

from docx import Document
from docx.shared import Inches
# from BeautifulSoup import BeautifulSoup
from bs4 import BeautifulSoup
import csv
import base64
import os
import optparse
import sys

import logging
import logging.config
from logging.config import fileConfig

LOGGING_LEVELS = {'critical': logging.CRITICAL,
                  'error': logging.ERROR,
                  'warning': logging.WARNING,
                  'info': logging.INFO,
                  'debug': logging.DEBUG}


#logging conf gile
logging.config.fileConfig('logging.conf')

# create logger
logger = logging.getLogger()
status_logger = logging.getLogger('xmlparser.status')

# define globals
global issueList
global xmlFileIn
global docOutFile
global cli_XMLFILE
global cli_WORDFILE
global cli_CSVFILE
cli_XMLFILE = ""
cli_WORDFILE = ""
cli_CSVFILE = ""

# Set input and output files
#xmlFileIn = 'xml\sample.xml'
xmlFileIn = cli_XMLFILE



#docOutFile = os.path.join('output', 'demo.docx')
docOutFile = cli_WORDFILE


# init Document
document = Document()

"""

{TITLE HEADER} ({Risk Level})

{Header 3.text 'Overview'}
{Paragraph with finding overview}

{Header 3.text 'Evidence'}
{Paragraph with finding Evidence}

{SCREENSHOT OR SNIPPET}

{Header 3.text 'Recommendation'}
{Paragraph with Recommendation}


"""


def buildWordDoc(name, severity, host,  ip, path, location, issueBackground, issueDetail, remediationBackground):
    # refer to https://python-docx.readthedocs.io/en/latest/
    # we init the doc at the start of this script
    #then save it in the main function after everything is built.
    location = str(location)
    orig_location = location

    loc_count = location.count('/')
    status_logger.debug('Location String {} location count : {}'.format(location, loc_count))
    if loc_count < 2:
        status_logger.debug('Location/Path is Default "/" ')
        #full_location = os.path.join(host, location)
        full_location = host + location
        location = full_location
    status_logger.debug('Location is Now {}'.format(location))
    #reformat data if needed
    issueBackground = str(issueBackground).replace('|', ',')
    remediationBackground = str(remediationBackground).replace('</p>', '')


    # init Document
    #document = Document()
    severity = str(severity)
    severity = severity + ' Risk'
    # use title to fix Capitals
    severity = severity.title()
    build_header = '{} ({})'.format(name, severity)
    status_logger.info('Creating Issue: {}'.format(build_header))
    document.add_heading(build_header, level=1)
    # added severity to issue title
    #document.add_heading("Severity:", level=3)
    #paragraph = document.add_paragraph(severity)
    document.add_heading("Vulnerable Host:", level=3)
    paragraph = document.add_paragraph(host)
    document.add_heading("Vulnerable URL:", level=3)
    if 'http' in location:
        location = orig_location
    host_url = host + location
    paragraph = document.add_paragraph(host_url)
    document.add_heading("Technical Details:", level=3)
    table = document.add_table(rows=1, cols=2)


    hdr_cells = table.rows[0].cells
    hdr_cells[0].text = 'IP:'
    hdr_cells[0].width = Inches(.00)
    hdr_cells[1].text = ip
    hdr_cells[1].width = Inches(.5)
    hdr_cells[1].left_margin = .1
    row_cells = table.add_row().cells
    row_cells[0].text = 'Path:'
    row_cells[0].width = Inches(.00)
    row_cells[1].text = path
    row_cells[1].width = Inches(.5)
    row_cells[1].left_margin = .1


    #for cell in table.rows[0].cells:
        #cell.width = Inches(.4)



    #document.add_heading("IP:", level=3)
    #paragraph = document.add_paragraph(ip)
    document.add_heading("Overview:", level=3)
    issueBackground = issueBackground.replace('<ol>', "").replace('</ol>', "").replace('<li>', "").replace('</li>', "")
    issueBackground = issueBackground.replace('<ul>', "").replace('</ul>', "").replace('<br>', "").replace('</br>', "")
    paragraph = document.add_paragraph(issueBackground)

    document.add_heading("Evidence:", level=3)
    issueDetail = str(issueDetail).replace('<br>', "").replace('<strong>', "").replace('</strong>', "")
    issueDetail = issueDetail.replace("</td>", "").replace('</tr>', "").replace('<tr>', "").replace('<td>', "")
    issueDetail = issueDetail.replace('<b>', "").replace('</b>', "").replace('<h4>', "").replace('</h4>', "")
    issueDetail = issueDetail.replace('&nbsp', " ").replace('</table>', " ").replace('<table>', " ")
    issueDetail = issueDetail.replace('<ol>', "").replace('</ol>', "").replace('<li>', "").replace('</li>', "")
    issueDetail = issueDetail.replace('<ul>', "").replace('</ul>', "")
    # replace the commas we decoded
    issueDetail = issueDetail.replace('","', "")
    paragraph = document.add_paragraph(issueDetail)
    document.add_heading("Recommendation:", level=3)
    remediationBackground= str(remediationBackground).replace('&quot;', " ").replace('<b>', "").replace('</b>', "")
    remediationBackground = str(remediationBackground).replace('&nbsp', " ").replace('</table>', " ").replace('<table>', " ")
    remediationBackground = str(remediationBackground).replace('<ol>', "").replace('</ol>', "").replace('<li>', "").replace('</li>', "")
    remediationBackground = str(remediationBackground).replace('<ul>', "").replace('</ul>', "")
    paragraph = document.add_paragraph(remediationBackground)
    paragraph_format = paragraph.paragraph_format
    #formatting to keep our vulns together instead of line breaks
    paragraph_format.keep_together



def process(xmlInFile):
    cwd = os.getcwd()
    xmlFileIn = os.path.join(cwd, xmlInFile)
    global issueList
    issueList = []
    # inputfile for the XML
    # THIS WILL BREAK IS YOU CHANGE HTML.PARSER!
    #try:
    if not os.path.isfile(xmlFileIn):
        status_logger.critical('Cant open XML! {}'.format(xmlInFile))
        exit(1)

    soup = BeautifulSoup(open(xmlInFile, 'r'), 'html.parser')
    status_logger.info('Using XML Input File {}'.format(xmlInFile))

    # pull all issue tags from XML
    issues = soup.findAll('issue')

    for i in issues:
        name = i.find('name').text
        host = i.find('host')
        ip = host['ip']
        host = host.text
        path = i.find('path').text
        location = i.find('location').text
        severity = i.find('severity').text
        confidence = i.find('confidence').text
        issueBackground = i.find('issuebackground').text
        issueBackground = str(issueBackground).replace('<p>', "").replace('</p>', "")
        # have to replace commas before making csv. Replaced with | for now.
        issueBackground = issueBackground.replace(',', "|")

        try:
            remediationBackground = i.find('remediationbackground').text
            remediationBackground = str(remediationBackground).replace('<p>', "")


        except:
            remediationBackground = 'BLANK'
            status_logger.error('Remediation Background is BLANK')

        try:
            vulnerabilityClassification = i.find('vulnerabilityclassifications').text
            vulnerabilityClassification = str(vulnerabilityClassification).replace("<ul>", "").replace("</ul>", "")
            vulnerabilityClassification = vulnerabilityClassification.replace("\n", "")

        except:
            vulnerabilityClassification = 'BLANK'
            status_logger.error('Vuln Classification is BLANK')

        try:
            # print(request)
            # request = base64.b64decode(i.find('requestresponse').find('request').text)
            # print('Decoding Request:')
            request = i.find('requestresponse').find('request').text
            request = base64.b64decode(request)
            request = str(request)
            request = response.replace(',', '","')
            # print(request)
        except:
            request = 'BLANK'
            status_logger.error('Request is blank for {}'.format(request))

        try:
            # print(response)
            # print('Decoding Response:')
            response = i.find('requestresponse').find('response').text
            response = base64.b64decode(response)
            response = str(response)
            response = response.replace(',', '","')
            # print(response)

        except:
            response = 'BLANK'
            status_logger.error('Response is blank for {}'.format(response))

        try:
            # print(response)
            # print('Issue Detail:')
            issueDetail = i.find('issuedetail').text
            issueDetail = str(issueDetail).replace(',', '","')



        except:
            issueDetail = 'BLANK'
            status_logger.error('Issue Detail is blank for {}'.format(issueDetail))

        #build our word document here
        buildWordDoc(name, severity, host, ip, path, location, issueBackground, issueDetail, remediationBackground)



        """
        result = (name, host, ip, location, severity, confidence, issueBackground, remediationBackground,
                  vulnerabilityClassification, issueDetail, request, response)
        """
        # document.add_page_break()
        result = (name, host, ip, location, severity, confidence, issueBackground, remediationBackground,
                  vulnerabilityClassification, issueDetail)
        issueList.append(result)
    status_logger.info('{} issues to report on'.format(len(issueList)))
    #logger.info('{} issues to report on'.format(len(issueList)))
    status_logger.info('Successfully Generate Data for Word Doc Creation')


def writeCSV(csvFile):
    outfile = 'NOTSET'
    #csvFile = 'NOTSET'
    cwd = os.getcwd()
    csvFile = os.path.join(cwd, csvFile)
    status_logger.info('Saving to CSV file: {}'.format(csvFile))
    # need to fix this logic, still fires error instead of except:
    try:
        outfile = open(csvFile, "w", newline='')
    except:
        status_logger.critical('Cant open CSV outfile : {}'.format(outfile))

    status_logger.info('Writing to CSV'.format(csvFile))
    writer = csv.writer(outfile, delimiter=',')
    """
    writer.writerow(
        ["Name", "Host", "IP", "Path", "Severity", "Confidence", "Issue Background", "Remediation Background",
         "Vulnerability Classification", "Issue Details", "Request", "Response"])
    """
    writer.writerow(
        ["Name", "Host", "IP", "Path", "Severity", "Confidence", "Issue Background", "Remediation Background",
         "Vulnerability Classification", "Issue Details"])
    writer.writerows(issueList)


def main():
    parser = optparse.OptionParser()
    parser.add_option('-i', '--xml-inputFile', help='*[REQUIRED]: Specify XML Input File', dest='xml_inputFile')
    parser.add_option('-o', '--word-outputFile', help='*[REQUIRED]: Specify WORD .Doc/Docx Output File',
                      dest='doc_outputFile')
    parser.add_option('-c', '--csv-outputFile', help='*[REQUIRED]: Specify CSV Output File',
                      dest='csv_outputFile')
    (options, args) = parser.parse_args()
    cli_XMLFILE = options.xml_inputFile
    cli_WORDFILE = options.doc_outputFile
    cli_CSVFILE = options.csv_outputFile
    status_logger.info('Using XML Input File: {}'.format(cli_XMLFILE))
    status_logger.info('Creating Word Dcument : {}'.format(cli_WORDFILE))

    status_logger.debug('cli_XMLFILE is Set to {}'.format(cli_XMLFILE))
    status_logger.debug('cli_WORDFILE is Set to {}'.format(cli_WORDFILE))
    #cli_XMLFILE =  sys.argv[1]
    xmlFileIn = cli_XMLFILE
    docOutFile = cli_WORDFILE
    if not cli_XMLFILE or cli_XMLFILE == 'None':
        status_logger.critical('INPUT XML FILE NOT FOUND OR SUPPLIED. Use -i xmlFile.xml ')
        exit(1)
    if not cli_WORDFILE or cli_WORDFILE == 'None' or '.doc' not in cli_WORDFILE:
        status_logger.critical('OUTPUT WORD FILE NOT FOUND OR SUPPLIED.')
        status_logger.critical('Doc/Docx Format! Use -o word.doc{word.docx}')
        exit(1)
    if not cli_CSVFILE or cli_CSVFILE == 'None' or '.csv' not in cli_CSVFILE:
        status_logger.critical('OUTPUT CSV FILE NOT FOUND OR SUPPLIED.')
        status_logger.critical('CSV Format! Use -c outFile.csv')
        exit(1)

    #status_logger.info('Command line XML Input file {}'.format(options.xml_inputFile))
    logger.info('Starting The Script {}'.format(os.path.basename(__file__)))
    status_logger.info('Starting The Script {}'.format(os.path.basename(__file__)))

    process(xmlFileIn)
    writeCSV(cli_CSVFILE)
    # Save Word Doc

    document.save(docOutFile)

    status_logger.info('Task Has Completed')





if __name__ == '__main__':
    main()

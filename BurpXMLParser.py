# Burp Pro XML parser
# Converts to CSV and makes a Word Template

from docx import Document
# from BeautifulSoup import BeautifulSoup
from bs4 import BeautifulSoup
import csv
import base64
import os

# define globals
global issueList
global xmlFileIn
global docOutFile

# Set input and output files
xmlFileIn = 'xml\sample.xml'
docOutFile = os.path.join('output', 'demo.docx')

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

    loc_count = location.count('/')
    print('DEBUG!!! Location String {} location count : {}'.format(location, loc_count))
    if loc_count < 2:
        print('[DEBUG] LOCATION IS DEFAULT')
        #full_location = os.path.join(host, location)
        full_location = host + location
        location = full_location
        print('[DEBUG] LOCATION IS NOW IN IF FUNCTION {}'.format(location))
        print('[DEBUG] FULL_LOCATION IS NOW IN IF FUNCTION {}'.format(full_location))
    print('[DEBUG] LOCATION IS NOW {}'.format(location))
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
    document.add_heading(build_header, level=1)
    # added severity to issue title
    #document.add_heading("Severity:", level=3)
    #paragraph = document.add_paragraph(severity)
    document.add_heading("Affected Host:", level=3)
    paragraph = document.add_paragraph(host)
    document.add_heading("Technical Details:", level=3)
    table = document.add_table(rows=1, cols=3)
    hdr_cells = table.rows[0].cells
    hdr_cells[0].text = 'IP'
    hdr_cells[1].text = 'Location'
    hdr_cells[2].text = 'Path'
    row_cells = table.add_row().cells
    row_cells[0].text = ip
    row_cells[1].text = location
    row_cells[2].text = path

    #document.add_heading("IP:", level=3)
    #paragraph = document.add_paragraph(ip)
    document.add_heading("Overview:", level=3)
    paragraph = document.add_paragraph(issueBackground)
    document.add_heading("Evidence:", level=3)
    paragraph = document.add_paragraph(issueDetail)
    document.add_heading("Recommendation:", level=3)
    paragraph = document.add_paragraph(remediationBackground)
    paragraph_format = paragraph.paragraph_format
    #formatting to keep our vulns together instead of line breaks
    paragraph_format.keep_together



def process():
    global issueList
    issueList = []
    # inputfile for the XML
    print('[DEBUG] Using file: {}'.format(xmlFileIn))
    # THIS WILL BREAK IS YOU CHANGE HTML.PARSER!
    soup = BeautifulSoup(open(xmlFileIn, 'r'), 'html.parser')
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

        try:
            vulnerabilityClassification = i.find('vulnerabilityclassifications').text
            vulnerabilityClassification = str(vulnerabilityClassification).replace("<ul>", "").replace("</ul>", "")
            vulnerabilityClassification = vulnerabilityClassification.replace("\n", "")

        except:
            vulnerabilityClassification = 'BLANK'

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
            print('[ERROR] Request is blank for {}'.format(i))
            request = 'BLANK'

        try:
            # print(response)
            # print('Decoding Response:')
            response = i.find('requestresponse').find('response').text
            response = base64.b64decode(response)
            response = str(response)
            response = response.replace(',', '","')
            # print(response)

        except:
            print('[ERROR] Response is blank for {}'.format(i))
            response = 'BLANK'

        try:
            # print(response)
            # print('Issue Detail:')
            issueDetail = i.find('issuedetail').text
            issueDetail = str(issueDetail).replace(',', '","')



        except:
            print('[ERROR] Issue Detail is blank for {}'.format(i))
            issueDetail = 'BLANK'

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
    print('{} issues to report on'.format(len(issueList)))


def writeCSV():
    # need to fix this logic, still fires error instead of except:
    try:
        outfile = open("output/burpOutput.csv", "w", newline='')
    except:
        print('[CRITICAL] Cant open CSV outfile : {}'.format(outfile))
    print('Writing to CSV'.format(outfile))
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
    print('Staring to process the XML file and convert to CSV.')
    print('[DEBUG] Word Output file: {}'.format(docOutFile))
    process()
    writeCSV()
    # Save Word Doc

    document.save(docOutFile)


if __name__ == '__main__':
    main()

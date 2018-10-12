# Burp Pro XML parser
# COnverts to CSV and makes a Word Template

from docx import Document
# from BeautifulSoup import BeautifulSoup
from bs4 import BeautifulSoup
import csv
import base64

global issueList
global xmlFileIn
# init Document
document = Document()

xmlFileIn = 'xml\sample.xml'


def process():
    global issueList
    issueList = []
    # inputfile for the XML
    # filePath = 'xml\sample.xml'
    print('[DEBUG] Using file: {}'.format(xmlFileIn))
    # THIS WILL BREAK IS YOU CHANGE HTML.PARSER!
    soup = BeautifulSoup(open(xmlFileIn, 'r'), 'html.parser')
    # pull all issue tags from XML
    issues = soup.findAll('issue')

    for i in issues:
        name = i.find('name').text
        # add vuln name in word
        # need to break this out to give more control of order.
        document.add_heading(name, level=1)
        host = i.find('host')
        ip = host['ip']
        host = host.text
        document.add_heading("Host: {}".format(host), level=3)
        document.add_heading("IP: {}".format(ip), level=3)
        path = i.find('path').text
        document.add_heading("Path: {}".format(path), level=3)
        location = i.find('location').text
        document.add_heading("Location: {}".format(location), level=3)
        severity = i.find('severity').text
        document.add_heading("Severity: {}".format(severity), level=3)
        confidence = i.find('confidence').text
        document.add_heading("Confidence: {}".format(confidence), level=3)
        issueBackground = i.find('issuebackground').text  # .replace("<p>","").replace("</p>","")
        issueBackground = str(issueBackground).replace('<p>', "").replace('</p>', "")
        # issueBackground = i.find('issuebackground').text
        document.add_heading("Issue Background: {}".format(issueBackground), level=3)
        # have to replace commas before making csv. Replaced with | for now.
        issueBackground = issueBackground.replace(',', "|")

        try:
            remediationBackground = i.find('remediationbackground').text
            remediationBackground = str(remediationBackground).replace('<p>', "")
            document.add_heading("Remedition: {}".format(remediationBackground), level=3)
        except:
            remediationBackground = 'BLANK'

        try:

            vulnerabilityClassification = i.find('vulnerabilityclassifications').text
            vulnerabilityClassification = str(vulnerabilityClassification).replace("<ul>", "").replace("</ul>", "")
            vulnerabilityClassification = vulnerabilityClassification.replace("\n", "")
            document.add_heading("Vuln Classification: {}".format(vulnerabilityClassification), level=3)
        except:
            vulnerabilityClassification = 'BLANK'
        # request = base64.b64decode(i.find('requestresponse').find('request').text)

        try:
            # print(request)
            print('Decoding Request:')
            request = i.find('requestresponse').find('request').text
            request = base64.b64decode(request)
            request = str(request)
            request = response.replace(',', '","')

            print(request)
        except:
            print('[ERROR] Request is blank for {}'.format(i))
            request = 'BLANK'

        try:
            # print(response)
            print('Decoding Response:')
            response = i.find('requestresponse').find('response').text
            response = base64.b64decode(response)
            response = str(response)
            response = response.replace(',', '","')
            print(response)

        except:
            print('[ERROR] Response is blank for {}'.format(i))
            response = 'BLANK'

        try:
            # print(response)
            print('Issue Detail:')
            issueDetail = i.find('issuedetail').text
            issueDetail = str(issueDetail).replace(',', '","')
            document.add_heading("Issue Detail: {}".format(issueDetail), level=3)


        except:
            print('[ERROR] Issue Detail is blank for {}'.format(i))
            issueDetail = 'BLANK'
        """
        result = (name, host, ip, location, severity, confidence, issueBackground, remediationBackground,
                  vulnerabilityClassification, issueDetail, request, response)
        """
        document.add_page_break()
        result = (name, host, ip, location, severity, confidence, issueBackground, remediationBackground,
                  vulnerabilityClassification, issueDetail)
        issueList.append(result)
    print('{} issues to report on'.format(len(issueList)))


def writeCSV():
    #need to fix this logic, still fires error instead of except:
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
    process()
    writeCSV()
    # Save Word Doc
    document.save('output/demo.docx')


if __name__ == '__main__':
    main()

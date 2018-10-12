# Burp Parser XML to CSV
# Simple, Easy to Use

from docx import Document
# from BeautifulSoup import BeautifulSoup
from bs4 import BeautifulSoup
import csv
import os
import random
import base64
global issueOutput

document = Document()



def process():
    filePath = 'xml\sample.xml'
    print('[DEBUG] Using file: {}'.format(filePath))
    # THIS WILL BREAK IS YOU CHANGE HTML.PARSER!
    soup = BeautifulSoup(open(filePath, 'r'), 'html.parser')
    issues = soup.findAll('issue')
    global issueOutput
    issueOutput = []
    for i in issues:
        print(i)
        #exit(1)
        name = i.find('name').text
        document.add_heading(name, level=1)
        print(name)
        #exit(1)
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
        issueBackground = str(issueBackground).replace(',',"|").replace('<p>', "")
        # issueBackground = i.find('issuebackground').text
        document.add_heading("Issue Background: {}".format(issueBackground), level=3)

        try:
            remediationBackground = i.find('remediationbackground').text
            remediationBackground = str(remediationBackground).replace('<p>', "")
            document.add_heading("Remedition: {}".format(remediationBackground), level=3)
        except:
            remediationBackground = 'BLANK'

        #remediationBackground = str(remediationBackground).replace(",", "")

        try:

            vulnerabilityClassification = i.find('vulnerabilityclassifications').text
            vulnerabilityClassification = str(vulnerabilityClassification).replace("<ul>", "").replace("</ul>","").replace("\n", "")
            document.add_heading("Vuln Classification: {}".format(vulnerabilityClassification), level=3)
        except:
            vulnerabilityClassification = 'BLANK'
        # request = base64.b64decode(i.find('requestresponse').find('request').text)


        try :
            #print(request)
            print('Decoding Request:')
            request = i.find('requestresponse').find('request').text
            request = base64.b64decode(request)
            request = str(request)
            request = response.replace(',', '","')
            #request=response.replace(','," ")
            print(request)
        except:
            print('[ERROR] Request is blank for {}'.format(i))
            request = 'BLANK'


        try :
            #print(response)
            print('Decoding Response:')
            response = i.find('requestresponse').find('response').text
            response = base64.b64decode(response)
            response = str(response)
            response = response.replace(',', '","')
            print(response)

        except:
            print('[ERROR] Response is blank for {}'.format(i))
            response = 'BLANK'

        # response = base64.b64decode(i.find('requestresponse').find('response').text)
        #response = i.find('requestresponse').find('response').text
        #response = base64.b64decode(response)
        #issueDetail = i.find('issuedetail').text

        try:
            # print(response)
            print('Issue Detail:')
            issueDetail = i.find('issuedetail').text

            issueDetail = str(issueDetail).replace(',', '","')
            document.add_heading("Issue Detail: {}".format(issueDetail), level=3)
            with open('issues.txt' , 'w') as f2:
                f2.write(name + "\n")
                #f2.write(issueDetail + "\n")
                #f2.write(response + "\n")
                #f2.write(request + " \n")


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
        issueOutput.append(result)
    print('{} issues to report on'.format(len(issueOutput)))
    #for result in issueOutput:
     #   print(result)

        #
        #exit(1)
    # print filePath

    # rando = random.randint(2000,3000)
    # filenameout = "BurpOutput %s" % rando

def writeCSV():


    outfile = open("burpOutput.csv", "w" , newline='')
    print('Writing to CSV'.format(outfile))
    writer = csv.writer(outfile, delimiter=',')
    writer.writerow(
        ["Name", "Host", "IP", "Path", "Severity", "Confidence", "Issue Background", "Remediation Background",
         "Vulnerability Classification", "Issue Details", "Request", "Response"])

    writer.writerows(issueOutput)



def main():
    print('Staring to process the XML file and convert to CSV.')
    process()
    writeCSV()

    document.add_page_break()
    document.save('demo.docx')



if __name__ == '__main__':
    main()

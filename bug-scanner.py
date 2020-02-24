#! /usr/bin/env python
import argparse
import validators # it is use to validate the url
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from bs4 import Comment
parser =argparse.ArgumentParser(description='##### The Vulnerbility Scanner #####')

parser.add_argument('-v','--version', action='version', version='%(prog)s 1.0')
parser.add_argument('url', type=str , help='The URL of the HTML to analyse')
parser.add_argument('-o','--output', help='report output file path')
args =parser.parse_args()


report=''

url =args.url
if(validators.url(url)):
    result_html =requests.get(url).text # it will prints the html document texts
    parsed_html =BeautifulSoup(result_html, 'html.parser')


    forms =(parsed_html.find_all('form'))
    comments =parsed_html.find_all(string=lambda  text:isinstance(text,Comment))
    password_input =parsed_html.find_all('input', {'name': 'password'})
    print('URL validates')

    for form in forms:
        if((form.get('action').find('https') <0) and (urlparse(url).scheme !='https')):
            form_is_secure= False
            report +='Form Issue: Insecure form action' " "+  form.get('action')  + " " 'found in document\n'
            
    for comment in comments:
        if(comment.find('key:') >-1):
            report +='comment issue: key'+ comment.find('key:') + 'is found in HTML document\n'          

    for password in password_input:
        if(password.get('type') !='password'):
            report += 'Input issue: plaintext password '
else:
    print('Invalid URL, Please type Full URL !!! ')

if(report == ""):
    print('Your HTML document is secure!!!')
else:
    print('Vulnerability report as follows\n')
    print('================================\n')
    print(report)

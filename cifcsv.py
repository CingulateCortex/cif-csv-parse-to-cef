#!/usr/bin/python
import csv, sys,socket
from optparse import OptionParser

def parsecsv(file):
  mtype = options.mtype
  reader = csv.DictReader(open(file))
  for row in reader:
     address = row.get('# address')
     altid = row.get('alternativeid')
     confidence = row.get('confidence')
     description = row.get('description')
     message= "CEF:0|CIF|CIF 0.1|100|1|CIF Malicious %s|1|shost=%s cs1=%s cs1Label=Source  cs2=%s cs2Label=ConfidenceLevel cs3=%s cs3Label=Description" %(mtype,address,altid,confidence,description)
     syslog(message, options.host, options.port)

def syslog(message,host,port):
   syslog = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
   data = '<%d>%s' % (5 + 8*3, message)
   print data
   syslog.sendto(data,(host,port))
   syslog.close()

parser = OptionParser(usage="%prog [-f] [-s]", version="%prog 0.01")
parser.add_option("-f", action="store",dest="fname", help="Name of the file you would like to parse")
parser.add_option("-s", action="store",dest="host", help="IP address or FQDN of syslog host to send CEF Messages to")
parser.add_option("-p", action="store", type="int",dest="Port", default=514,help="PORT to send syslog messages to. Usually 514 please check your Connector configuration [DEFAULT: 514]")
parser.add_option("-t", action="store",dest="mtype", default="Domain",help="Domain or IP this will help generate the CEF Message that is sent. If Domain the CEF Name will be CIF Malicious Domain. If IP the CEF Name will be CIF Malicious IP")
(options, args) = parser.parse_args()
if options.fname == None :
   parser.error("You must specify a filename ")
   sys.exit(1)
elif options.host == None:
   parser.error("You must specify a host")
   sys.exit(1)
else:
   parsecsv(options.fname)
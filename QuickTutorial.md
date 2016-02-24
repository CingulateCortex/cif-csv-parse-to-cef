#Quick Tutorial of the cifcsv.py script.

# Overview #

The idea behind this script is you want to take the data that is in CIF Feeds and throw it in an active list or two in your ArcSight implementation. For example purposes let's assume you generate feeds that are have confidence levels of 95,85 and severity of High,Medium.
For example:

```
cif -q domain/malware -s medium -c 85 -p csv > dom_malware.csv
cif -q infrastructure/malware -s medium -c 85 -p csv > infra_malware.csv
```

# CIF CSV #

Things you must know for running the CIF CSV parser:
  * Filename: dom\_malware.csv
  * Syslog host: ArcSight Syslog Reciever
  * Syslog port: Typically 514 but it could be something else
  * Message Type: What is the context for the csv: Domain, IP, Scanner

To run cifcsv.py you need to pass the following arguments:
  * -f filename
  * -s syslog host
  * -p port
  * -t message type

```
./cifcsv.py -f dom_malware.csv -s 192.168.100.154 -p 514 -t Domain
```

The CIF CSV parser currently sends these CIF related fields in the CEF Message:
  * shost (Domain name or IP Address)
  * cs1 (CIF Source i.e. spamhaus, emergingthreats
  * cs2 (Confidence level)
  * cs3 (Description)

This will then parse the dom\_malware.csv file and generate a syslog message and send it to the host 192.168.100.154 on port 514 with the CEF Name field of CIF Malicious Domain:
```
<29>CEF:0|CIF|CIF 0.1|100|1|CIF Malicious Domain|1|shost=e46l.cc cs1=www.emergingthreats.net cs1Label=Source  cs2=85 cs2Label=ConfidenceLevel cs3=russian business network cs3Label=Description
```

If you are monitoring for events in your ArcSight Console with an active Channel a filter that should work to find these events is.
```
Device Vendor=CIF
```
You should see the following fields being populated:
  * Name
  * Attacker Address or Attacker Hostname
  * Device Custom String 1
  * Device Custom String 2
  * Device Custom String 3

# Suggested CIF Feeds #
The following feeds and CIF CSV Parser -T argument are ones we suggest to use:

|**CIF Feed Query** | **CIF CSV Arguments** |
|:------------------|:----------------------|
| cif -q domain/malware -s medium -c 85 -p csv > dom\_malware.csv | -T Domain             |
| cif -q domain/botnet -s medium -c 85 -p csv > dom\_botnet.csv | -T Domain             |
| cif -q infrastructure/malware -s medium -c 85 -p csv > infra\_malware.csv | -T IP                 |
| cif -q infrastructure/botnet -s medium -c 85 -p csv > infra\_botnet.csv | -T IP                 |
| cif -q infrastructure/malware -s medium -c 85 -p csv > infra\_scan.csv | -T Scanner            |
#!/bin/sh
from glob import glob
from optparse import OptionParser
import re
import sys
import os

parser = OptionParser()
parser.add_option("-i", dest="input_target", type="string", help="rules files to remove thresholds from and stick in a file standard glob stuff supported")
parser.add_option("-o", dest="output_target", type="string", help="dir to dump new files and threshold.config")
threshold_ar = []

(options, args) = parser.parse_args()
if options == []:
   print parser.print_help()
   sys.exit(-1)
if not options.input_target or options.input_target == "":
   print parser.print_help()
   sys.exit(-1)
if not options.output_target or options.output_target == "":
   print parser.print_help()
   sys.exit(-1)

try:
    if not os.path.exists(options.output_target):
        os.makedirs(options.output_target)
except:
    print("failed to create directory %s bailing" % (options.output_target))
    
#    threshold: \
#        type <limit|threshold|both>, \
#        track <by_src|by_dst>, \
#        count <c>, seconds <s>;
#type threshold, track by_src, count 3, seconds 10
#event_filter gen_id 0, sig_id 0, type limit, track by_src, count 1, seconds 60
rules_files = glob(options.input_target)
rules_files.sort()
for e in rules_files:
    print "working on %s " % (e)
    rules_file_tmp_ar = []
    lines = open(e,"rb").readlines()
    for l in lines:
        m = re.match(r"^\s*#*\s*alert.+\bthreshold\x3a\s*(?P<threshold>[^\x3b]+)\s*\x3b.*",l,re.I|re.S)
        if m == None:
            rules_file_tmp_ar.append(l)
        else:
            #print m.group("threshold")
            tmp_type = None
            tmp_track = None
            tmp_count = None
            tmp_seconds = None 
            tmp_sid = None

            type_e = re.search(r"\btype\s*?(?P<type>(threshold|limit|both))",m.group("threshold"),re.I)
            if type_e == None:
                print("The following rule does not have a threshold type arg bailing\n%s" % (m.group(0)))
                sys.exit(1)
            else:
                tmp_type = type_e.group("type") 

            type_e = re.search(r"\btrack\s*?(?P<track>by_(src|dst))",m.group("threshold"),re.I)
            if type_e == None:
                print("The following rule does not have a threshold track arg bailing\n%s" % (m.group(0)))
                sys.exit(1)
            else:
                tmp_track = type_e.group("track")

            type_e = re.search(r"\bcount\s*?(?P<count>\d+)",m.group("threshold"),re.I)
            if type_e == None:
                print("The following rule does not have a threshold count arg bailing\n%s" % (m.group(0)))
                sys.exit(1)
            else:
                tmp_count = type_e.group("count")

            type_e = re.search(r"\bseconds\s*?(?P<seconds>\d+)",m.group("threshold"),re.I)
            if type_e == None:
                print("The following rule does not have a threshold second arg bailing\n%s" % (m.group(0)))
                sys.exit(1)
            else:
                tmp_seconds = type_e.group("seconds")

            type_e = re.search(r"\bsid\s*\x3a\s*(?P<sid>\d+)",m.group(0),re.I)
            if type_e == None:
                print("The following rule does not have a threshold sid arg bailing\n%s" % (m.group(0)))
                sys.exit(1)
            else:
                tmp_sid = type_e.group("sid")
            
            tmp_evt_filter = "event_filter gen_id 1, sig_id %s, type %s, track %s, count %s, seconds %s\n" % (tmp_sid,tmp_type,tmp_track,tmp_count,tmp_seconds)
            if tmp_evt_filter not in threshold_ar:
                threshold_ar.append(tmp_evt_filter)

            tmp_rule = re.sub(r"\x20*threshold\s*\x3a[^\x3b]+\x3b\x20*"," ",m.group(0))
            rules_file_tmp_ar.append(tmp_rule)

	    #print("event_filter gen_id 1, sig_id %s, type %s, track %s, count %s, seconds %s" % (tgmp_sid,tmp_type,tmp_track,tmp_count,tmp_seconds)) 
            #print("before\n%s" % (m.group(0)))
            #print("after\n%s" % (tmp_rule))

    new_rule_file = "%s/%s" % (options.output_target,os.path.basename(e))
    try:
        f = open(new_rule_file,"wb")
    except Exception as ferr:
        print "failed to open new output file: %s error: %s" % (new_rule_file,ferr)
        sys.exit(1)
 
    for l in rules_file_tmp_ar:
        if "\n" in l:
            f.write(l)
        else:
            f.write(l + '\n')
    f.close()

new_threshold_file = "%s/threshold.conf" % (options.output_target)
try:
    f = open(new_threshold_file,"wb")
except Exception as ferr:
    print "failed to open new output file: %s error: %s" % (new_threshold_file,ferr)
    sys.exit(1)

for l in threshold_ar:
    f.write(l)
f.close()

print "Done\n"             

#!/usr/bin/env python2.7
"""
SYNOPSIS

This is the actual Automatic Signature Generator (ASG) that takes a STIX/
CybOX XML file from the detector as input and produces Suricata (Snort) rules.

DESCRIPTION

We first use the DetectorEvent class to receive XML from the detector and
transform it into an internal representation. The packet and metadata is then
transmitted to the C/C++ language ASG module.
"""
import logging
import sys
import os
import argparse
import AsgEngine
#import boost_log
import ctypes
from properties.envProperties import EnvProperties
from DetectorReports.detectorEvent import DetectorEvent
from DetectorReports.detector_xmt_ext import DetectorReport;

def process_detection(filename,properties,debug):
    # de = DetectorEvent(filename)
    # xml_again = de.toStixXml()
    # ofh = open('stix_again.xml','w')
    # ofh.write(xml_again)
    # ofh.close()
    # dr = DetectorReport()
    # for attack in de.attackInstanceList:
    #     dr.appendAttack()
    #     for attack_packet in attack.packetList:
    #         dr.appendPacket(attack_packet.timeStamp, attack_packet.protocol,
    #                         attack_packet.Sport, attack_packet.Dport,
    #                         attack_packet.payload, attack_packet.probAttack)
    max_depth = int(properties.getProperty('ASG.MaxDepth'))
    asg_e = AsgEngine.PyAsgEngine(filename,properties,debug)
    asg_e.loadDetectorEvent()
    asg_e.makeCandidateSignatureStringSet()
    #asg_e.makeTries()

def setup():
    parser = argparse.ArgumentParser(
        description='Takes homegrown file for description of an event and '+
        'converts it to a FASGuard STIX XML file')
    parser.add_argument("in_file",help='File with homebrew attack info',
                        default='stix.xml')
    parser.add_argument('-d','--debug',required=False,action='store_true',
                        help='run with debug logging')
    parser.add_argument('-p','--properties',type=str,required=False,
                        default='asg.properties',help='properties file')

    args = parser.parse_args()
    #print "In file: ",args.in_file
    FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    logging_level  = logging.DEBUG if args.debug else logging.INFO
    logger = logging.getLogger('simple_example')
    logger.setLevel(logging_level)
    #formatter = logging.Formatter(FORMAT)
    ch = logging.StreamHandler()
    ch.setLevel(logging_level)
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    ch.setFormatter(formatter)
    #logger.setLevel(logging_level)
    #logger.setLevel(logging.DEBUG)
    #ch.setFormatter(formatter)
    print 'logging.DEBUG',logging.DEBUG
    logger.addHandler(ch)

    logger.debug('debug message')

    logger.debug("In file: %s",args.in_file)
    #sys.exit(-1)
    properties = EnvProperties(args.properties)
    process_detection(args.in_file,properties,args.debug)
if __name__ == '__main__':
    my_lib = ctypes.cdll.LoadLibrary(
        '/usr/lib/x86_64-linux-gnu/libboost_log.so.1.54.0')
    setup()

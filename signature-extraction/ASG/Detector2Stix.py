#!/usr/bin/env python2.7
"""
SYNOPSIS

This method takes a homegrown file format for an incident and converts it into
the FASGuard STIX format for detectors. It is intended primarily for testing.

DESCRIPTION

The input file format is:

____
ATTACK_INSTANCE_NUM = 1
PCAP_FILE_NAME = attack_instance_1.pcap
****
PKT_NUM = 1
PROB_OF_ATTACK = 0.3
****
PKT_NUM = 2
PROB_OF_ATTACK = 0.4
****
PKT_NUM = 3
PROB_OF_ATTACK = 0.5
****
PKT_NUM = 4
PROB_OF_ATTACK = 0.4
****
____
ATTACK_INSTANCE_NUM = 2
PCAP_FILE_NAME = attack_instance_2.pcap
****
PKT_NUM = 1
PROB_OF_ATTACK = 0.3
****
PKT_NUM = 2
PROB_OF_ATTACK = 0.4
****
____

"""
import logging
import sys
import os
import argparse
from asg.DetectorReports.detectorEvent import DetectorEvent

def handle_file(filename):
    de = DetectorEvent(filename)
    xml = de.toStixXml()
    logger = logging.getLogger('simple_example')
    ofh = open('stix.xml','w')
    ofh.write(xml)
    ofh.close()
    #logger.debug('XML: $s',xml)
def setup():
    parser = argparse.ArgumentParser(
        description='Takes homegrown file for description of an event and '+
        'converts it to a FASGuard STIX XML file')
    parser.add_argument("in_file",help='File with homebrew attack info')
    parser.add_argument('-d','--debug',required=False,action='store_true',
                        help='run with debug logging')

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
    handle_file(args.in_file)
if __name__ == '__main__':
    setup()

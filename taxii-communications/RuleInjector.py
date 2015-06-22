#!/usr/bin/env python2.7
"""
SYNOPSIS

This program reads an index from a pipe which is used to access the sqlite DB
to extract a STIX format file with rules.

DESCRIPTION
"""
import logging
import sys
import os
import os.path
import argparse
from stixFromDb import StixFromDb
from fasguardStixRule import FASGuardStixRule
from properties.envProperties import EnvProperties

def setup():
    parser = argparse.ArgumentParser(
        description='Receives Snort rules in STIX transmission and injects '+
        'them into a running Suricata')
    parser.add_argument('-d','--debug',required=False,action='store_true',
                        help='run with debug logging')
    parser.add_argument('-p','--properties',type=str,required=False,
                        default='rinject.properties',help='properties file')

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
    properties = EnvProperties(args.properties)

    # Connect to database
    stx_frm_db = StixFromDb(properties)
    logger.debug('Created StixFromDb')
    stix_xml_filename = properties.getProperty('StixFromDb.StixXmlFilename')
    while stx_frm_db.processStix():
        fsr = FASGuardStixRule()
        fh = open(stix_xml_filename,'r')
        xml = fh.read()
        fh.close()
        fsr.parseXML(xml)
        cnt = 0
        for rule in fsr.ruleList:
            logger.debug('Rule %d: %s',cnt,rule)
            cnt+=1

if __name__ == '__main__':
    setup()

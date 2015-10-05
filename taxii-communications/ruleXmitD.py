#!/usr/bin/env python2.7
"""
SYNOPSIS

Transmit FASGuard/STIX rule files to remote Suricata using TAXII.

DESCRIPTION

We watch the directory where the ASG places the  FASGuard/STIX
XML rule files. When a new one is added, we transmit it to the recipient via
TAXII/Yeti.
"""
import logging
import sys
import os
import argparse

from properties.envProperties import EnvProperties
from watchAndXmit import WatchAndXmit

def setup():
    parser = argparse.ArgumentParser(
        description='Watches for rule file from ASG '+
        'and transmists it via TAXII')
    parser.add_argument('-d','--debug',required=False,action='store_true',
                        help='run with debug logging')
    parser.add_argument('-p','--properties',type=str,required=False,
                        default='rxd.properties',help='properties file')

    args = parser.parse_args()
    #print "In file: ",args.in_file
    FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    logging_level  = logging.DEBUG if args.debug else logging.INFO
    logger = logging.getLogger('simple_example')
    logger.setLevel(logging_level)

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

    #sys.exit(-1)
    properties = EnvProperties(args.properties)

    # Retrieve the rule file directory where we'll watch for new files

    atk_file_dir = properties.getProperty('RuleXmitD.RuleFileDir')

    logger.debug('Rule File Dir: %s',atk_file_dir)

    watch_and_xmit = WatchAndXmit(atk_file_dir, properties)
    watch_and_xmit.startLoop()

if __name__ == '__main__':
    setup()

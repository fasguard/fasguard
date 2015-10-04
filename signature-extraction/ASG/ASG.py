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
import os.path
import argparse
import re
import asg.asgEngine
#import boost_log
import ctypes
import xml.etree.ElementTree as ET
from asg.properties.envProperties import EnvProperties
from asg.DetectorReports.detectorEvent import DetectorEvent
from asg.DetectorReports.detector_xmt_ext import DetectorReport
from asg.stixFromDb import StixFromDb
from asg.fasguardStixRule import FASGuardStixRule

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
    asg_e = asg.asgEngine.PyAsgEngine(filename,properties,debug)
    asg_e.loadDetectorEvent()
    asg_e.makeCandidateSignatureStringSet()
    #asg_e.makeTries()


def setup():
    parser = argparse.ArgumentParser(
        description='Takes homegrown file for description of an event and '+
        'converts it to a FASGuard STIX XML file')
    parser.add_argument("in_file",nargs='?',
                        help='File with homebrew attack info',
                        default='stix.xml')
    parser.add_argument('-d','--debug',required=False,action='store_true',
                        help='run with debug logging')
    parser.add_argument('-s','--sqldb',required=False,action='store_true',
                        help='retrieve FASGuard STIX XML file from sql db')
    parser.add_argument('-p','--properties',type=str,required=False,
                        default=os.path.join(os.path.dirname(__file__),
                                             'asg.properties'),
                        help='properties file')

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

    if args.sqldb:
        # Connect to database
        stx_frm_db = StixFromDb(properties)
        logger.debug('Created StixFromDb')
        stix_xml_filename = properties.getProperty('StixFromDb.StixXmlFilename')
        joined_xmit = False
        snippet_xmit = False
        cluster_xmit = False
        xmit_string = properties.getProperty('ASG.TransmitRuleSets')
        xmit_list = xmit_string.split(',')
        for rule_type in xmit_list:
            if rule_type == 'Joined':
                joined_xmit = True
            elif rule_type == 'Snippet':
                snippet_xmit = True
            elif rule_type == 'Cluster':
                cluster_xmit = True
        joined_rule_file = properties.getProperty('ASG.SuricataRuleFile')
        snippet_rule_file = properties.getProperty('ASG.SuricataPcreRuleFile')
        cluster_rule_file = properties.getProperty(
            'ASG.SuricataUnsupervisedClusterRuleFile')
        ruleDir = properties.getProperty('ASG.FASGuardStixRuleDir')
        while stx_frm_db.processStix():
            process_detection(stix_xml_filename,properties,args.debug)
            rule_list = []
            # Xmit requested rule sets
            if joined_xmit and os.path.isfile(joined_rule_file):
                for rule in open(joined_rule_file,'r'):
                    if re.search(r'(pass|drop|reject|alert)',rule):
                        rule_list.append(rule)
            if snippet_xmit and os.path.isfile(snippet_rule_file):
                for rule in open(snippet_rule_file,'r'):
                    if re.search(r'(pass|drop|reject|alert)',rule):
                        rule_list.append(rule)
            if cluster_xmit and os.path.isfile(cluster_rule_file):
                for rule in open(cluster_rule_file,'r'):
                    if re.search(r'(pass|drop|reject|alert)',rule):
                        rule_list.append(rule)

            fsr = FASGuardStixRule(rule_list)
            xml = fsr.toStixXml("High","Low")
            fh = open(ruleDir+'/stix-rules.xml','w')
            fh.write(xml)
            fh.close()
        sys.exit(-1)

    logger.debug("In file: %s",args.in_file)
    #sys.exit(-1)

    process_detection(args.in_file,properties,args.debug)
if __name__ == '__main__':
    setup()

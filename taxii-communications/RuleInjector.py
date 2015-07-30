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
import yaml
import signal
from subprocess import check_output
from stixFromDb import StixFromDb
from fasguardStixRule import FASGuardStixRule
from properties.envProperties import EnvProperties

def getSuricataConfFile():
    paths=["/etc/suricata/suricata.yaml","/usr/local/etc/suricata/suricata.yaml"]
    for path in paths:
        if os.path.isfile(path):
            return path
    return None

def getSuricataConf():
    path = getSuricataConfFile()
    if path is None:
        return None
    suriconf = None
    with open(path, 'r+') as stream:
        suriconf = yaml.load(stream)
    stream.close()
    return suriconf

def updateSuricataConf():
    path = getSuricataConfFile()
    if path is None:
        return None
    with open(path, 'r+') as stream:
        conf = stream.readlines()
        index = conf.index('rule-files:\n') + 1
        conf.insert(index, " - fasguard.rules\n")
        stream.seek(0);
        stream.writelines(conf)
        stream.close()

def fixupSuricataConf(conf):
    rulesFiles = conf["rule-files"]
    if "fasguard.rules" in rulesFiles:
        return
    updateSuricataConf()

def writeFASGuardRules(rules, rulesDir):
    path = rulesDir
    if not path.endswith("/"):
        path += "/"
    path += "fasguard.rules"
    with open(path, 'w') as stream:
        stream.write('\n'.join(rules) + '\n')
        stream.close()

def getSuricataPid(conf):
    pid = None
    pidfile = conf["pid-file"]
    if pidfile is not None and os.path.isfile(pidfile):
        with open(pidfile, 'r') as stream:
            pid = int(stream.read().strip())
            stream.close()
        return pid
    return int(check_output(["pidof","suricata"]).strip())

def updateRules(rules):
    if rules is not None and isinstance(rules, list) and len(rules) > 0:
        conf = getSuricataConf()
        if conf is None:
            return
        fixupSuricataConf(conf)
        rulesDir = conf["default-rule-path"]
        if rulesDir is not None:
            writeFASGuardRules(rules, rulesDir)
            pid = getSuricataPid(conf)
            if pid is not None:
                os.kill(pid, signal.SIGUSR2)

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
    while stx_frm_db.processStix(): # continuous loop -
        fsr = FASGuardStixRule()
        fh = open(stix_xml_filename,'r')
        xml = fh.read()
        fh.close()
        fsr.parseXML(xml)
        if fsr.ruleList is not None:
            updateRules(fsr.ruleList)

if __name__ == '__main__':
    setup()

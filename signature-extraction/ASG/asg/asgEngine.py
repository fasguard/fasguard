"""
SYNOPSIS

This is the high level object that takes in the STIX format detection report
and outputs the signatures.

DESCRIPTION

The processing steps are:

1) Convert detection report XML to DetectorEvent object.
2) Convert DetectorEvent (Python object) to DetectorReport (C++ Object)

The actual processing is done in a C++ object that we initialize and then
invoke the processing steps one at a time.
"""
import logging
import sys
import os
import re
import pcap
from stix.core import STIXPackage
from pprint import pprint
from pprint import pformat
import datetime
import base64
import math
import calendar
import time
import dpkt

from asg.CppAsgEngine.asg_engine_ext import AsgEngine;
from asg.DetectorReports.detectorEvent import DetectorEvent

class PyAsgEngine:
    """
    Goes through processing steps to convert detector report XML to signatures.
    """
    def __init__(self, xml_file, properties, debug):
        """
        Constructor which provides STIX file from which signatures will be
        produced.

        Arguments:
        xml_file - STIX compliant XML file.
        properties - An EnvProperties object which contains information coming
                from a properties file.
        debug -Boolean, true if debug is on.
        """
        self.properties = {}
        for property_name in properties.propertyNames():
            self.properties[property_name] = properties.getProperty(
                property_name)
        self.cppAsgEngine = AsgEngine(self.properties, debug)
        self.detectorEvent = DetectorEvent(xml_file)
        self.debug = debug
    def loadDetectorEvent(self):
        """
        Method to transfer data from Python DectectorEvent to a
        DetectorReport in the C++ code.
        """
        self.cppAsgEngine.setDetectorEventFlags(
            self.detectorEvent.multiAttackFlag,
            self.detectorEvent.attackBoundaryFlag)
        for attack in self.detectorEvent.attackInstanceList:
            self.cppAsgEngine.appendAttack()
            for attack_packet in attack.packetList:
                self.cppAsgEngine.appendPacket(attack_packet.timeStamp,
                                               attack_packet.protocol,
                                               attack_packet.Sport,
                                               attack_packet.Dport,
                                               attack_packet.payload,
                                               attack_packet.probAttack)
    def makeCandidateSignatureStringSet(self):
        """
        Method to create a set of candidate signature strings which are then
        filtered using benign traffic. The method used for creating the
        candidate signatures depends on multi-attack metadata. The three
        possible methods are:
        1) If the multiAttackFlag is false, we produce tries that store all
           n-grams within the range of lengths and all are signature candidates.
        2) If the multiAttackFlag is true but the attackBoundaryFlag is false,
           we use a general local-alignment based clustering to find similar
           large strings within clustered packets assumed to be corresponding
           packets across attacks.
        3) If the multiAttackFlag is true and the attackBoundaryFlag is true,
           we create clusters such that each cluster is constrained to contain
           at most one packet from each attack instance.
        """
        logger = logging.getLogger('simple_example')
        self.cppAsgEngine.makeCandidateSignatureStringSet()
    def makeTries(self):
        """
        Takes each packet in each attack and converts it to a Trie.
        """
        logger = logging.getLogger('simple_example')
        logger.debug('In Python makeTries')
        self.cppAsgEngine.makeTries()

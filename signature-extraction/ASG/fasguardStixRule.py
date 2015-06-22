#!/usr/bin/env python2.7
import logging
import sys
import os
import re
import StringIO
from stix.core import STIXPackage
from stix.indicator import Indicator
from stix.ttp import TTP
from stix.ttp import ExploitTargets
from stix.exploit_target import ExploitTarget, Vulnerability
from stix.extensions.test_mechanism.snort_test_mechanism import SnortTestMechanism
from stix.common import Confidence, InformationSource, Identity


class FASGuardStixRule:
    """
    This class takes a list of Snort rules from the ASG and produces a
    FASGuard/STIX format file for transmission via TAXII.
    """
    def __init__(self, rule_list=[]):
        """
        Constructor.

        rule_list - List of Snort format rules.
        """
        self.ruleList = rule_list
    def toStixXml(self, confidence, efficacy):
        """
        This method converts a list of FASGuard generated Snort rules  into a STIX
        compliant XML string ready for output. It first converts the object
        into a hash of the right format and then converts it into XML using
        STIXPackage.from_dict and to_xml on the resulting object.

        Arguments:

        confidence - High, Medium or Low. High means low false alarm rate.
        efficacy - High, Medium or Low. High means a low missed detection rate.

        Returns:

        Reference to string containing STIX/CybOX XML file.
        """
        logger = logging.getLogger('simple_example')
        self.logger = logger
        self.logger.debug('In fasguardStixRule')
        stix_package = STIXPackage()

        # Build the Exploit Target
        vuln = Vulnerability()
        vuln.cve_id = "Unknown"

        et = ExploitTarget(title="From FASGuard")
        et.add_vulnerability(vuln)

        stix_package.add_exploit_target(et)

        # Build the TTP
        ttp = TTP(title="FASGuard Produced Signatures")
        ttp.exploit_targets.append(ExploitTarget(idref=et.id_))

        stix_package.add_ttp(ttp)

        # Build the indicator
        indicator = Indicator(title = "Snort Signature from FASGuard")
        indicator.confidence = Confidence(confidence)

        tm = SnortTestMechanism()
        tm.rules = self.ruleList
        tm.efficacy = efficacy
        tm.producer = InformationSource(identity=Identity(name="FASGuard"))
        tm.producer.references = ["http://fasguard.github.io/"]
        indicator.test_mechanisms = [tm]
        indicator.add_indicated_ttp(TTP(idref=ttp.id_))

        stix_package.add_indicator(indicator)

        return stix_package.to_xml()

        # stixDict = {'campaigns': [{}],
        #             'courses_of_action': [{}],
        #             'exploit_targets': [{}],
        #             'id': 'INSERT_PACKAGE_ID_HERE'}
        # stixDict['indicators'] = [{'indicator':
        #                            {'title':
        #                             'Automatically Generated FASGuard Signatures',
        #                             'test_mechanisms':
        #                             {'test_mechanism':
        #                              {'efficacy':'Low',
        #                               'producer':
        #                               {'Identity':'FASGuard'},
        #                               'rule':'xyz'}}}}
        # ]
        stix_package = STIXPackage.from_dict(stixDict)
        stix_xml = stix_package.to_xml()
        return stix_xml
    def parseXML(self,xml_string):
        """
        This method takes a STIX/CybOX XML string and extracts the list of
        rules which it stores in ruleList

        Arguments:

        xml_string - XML string in STIX/CybOX format containing rules.

        Returns:

        Rule list
        """
        sio = StringIO.StringIO(xml_string)
        stix_package = STIXPackage.from_xml(sio)
        stix_dict = stix_package.to_dict()
        rules = []
        print stix_dict['indicators'][0]['test_mechanisms'][0]['rules']
        for rule in stix_dict['indicators'][0]['test_mechanisms'][0]['rules']:
            rules.append(rule['value'])
        self.ruleList = rules
        return rules
if __name__ == '__main__':
    FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    logging_level  = logging.DEBUG
    logger = logging.getLogger('simple_example')
    logger.setLevel(logging_level)
    #formatter = logging.Formatter(FORMAT)
    ch = logging.StreamHandler()
    ch.setLevel(logging_level)
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    ch.setFormatter(formatter)
    logger.addHandler(ch)
    rule_list = [
        'alert tcp any any -> any any (msg: "bogus1"; content:"|16 03|"; )',
        'alert tcp any any -> any any (msg: "bogus2"; content:"|ab cd|"; )'
        ]
    fsr = FASGuardStixRule(rule_list)
    xml = fsr.toStixXml("High","Low")
    print 'xml',xml
    fsr = FASGuardStixRule()
    rule_list = fsr.parseXML(xml)
    cnt = 0
    for rule in rule_list:
        print 'Rule ',cnt,rule
        cnt += 1

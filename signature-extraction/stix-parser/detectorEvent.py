"""
SYNOPSIS

This class contains the data for a detector event which can consist of multiple
instances of the same attack.

DESCRIPTION

A detector event is stored in an object of the DetectorEven type. Fields can
be entered directly or can be input either as a homegrown file or a STIX file.
The data can also be output in either of those formats.
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

class AttackPacket:
    """
    This class contains both metadata and payload data for a single packet.

    Arguments:
    prob_of_attack - A double representing the probability that this packet is
        an attack
    time_stamp - The pcap time stamp of the packet
    payload - Packet payload.
    """

    def __init__(self, prob_of_attack, time_stamp, payload):
        self.probAttack = prob_of_attack
        self.timeStamp = time_stamp
        self.payload = payload


class AttackInstance:
    """
    This class contains the data for a single attack within a larger event.

    Arguments:
    packet_list - a list of AttackPacket objects
    """

    def __init__(self, packet_list = []):
        self.packetList = packet_list


class DetectorEvent:
    """
    This class contains the data for a detector event which can consist of
    multiple instances of the same attack.
    """

    def __init__(self, input_file = None):
        """
        Constructor.

        Arguments:
        input_file - Optional. If present and filename suffix is .fst, it is
        of the homegrown variety. If the suffix is .xml, it's a STIX file.
        """
        self.logger = logging.getLogger('simple_example')
        self.attackInstanceList = []
        if input_file:
            if re.match(r'.*\.fst', input_file):
                self.logger.debug('FST file: %s', input_file)
                self.parseFST(input_file)
            elif re.match(r'.*\.xml', input_file):
                self.logger.debug('STIX file: %s', input_file)
                self.parseXML(input_file)
            else:
                self.logger.error('Bad file name: %s', input_file)
                sys.exit(-1)

    def parseFST(self, fst_file):
        """
        This method parses a file in the BBN FST format which encodes an event.
        The format is in the form:
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

        Arguments:

        fst_file - The name of the file in the FST format.

        """
        instance_num = -1
        prob_attack = 0.0
        pcap_file = ''
        payloads = []
        time_stamps = []
        prob_of_attack_list = []
        f = open(fst_file, 'r')
        for line in f:
            self.logger.debug('Line: %s', line)
            if re.search(r'____', line):
                if instance_num == -1:
                    self.logger.debug('First instance of ____')
                else:
                    packet_list = []
                    for i in range(len(prob_of_attack_list)):
                        ap = AttackPacket(prob_of_attack_list[i],
                                          time_stamps[i], payloads[i])
                        packet_list.append(ap)

                    attack_instance = AttackInstance(packet_list)
                    self.logger.debug('Adding AttackInstance %d', instance_num)
                    self.attackInstanceList.append(attack_instance)
                    prob_of_attack_list = []
            elif re.search(r'ATTACK_INSTANCE_NUM\s*=\s*(\d+)', line):
                m = re.search(r'ATTACK_INSTANCE_NUM\s*=\s*(\d+)', line)
                instance_num = int(m.group(1))
                self.logger.debug('Instance Number: %d",instance_num',
                                  instance_num)
            elif re.search(r'PROB_OF_ATTACK\s*=\s*(\d+)', line):
                m = re.search(r'PROB_OF_ATTACK\s*=\s*([0-9.]+)', line)
                prob_attack = float(m.group(1))
                prob_of_attack_list.append(prob_attack)
            elif re.search(r'\*\*\*\*', line):
                pass
            elif re.search(r'PKT_NUM\s*(\d+)', line):
                pass
            elif re.search(r'PCAP_FILE_NAME\s*=\s*(\S+)', line):
                m = re.search(r'PCAP_FILE_NAME\s*=\s*(\S+)', line)
                pcap_file = m.group(1)
                pc = pcap.pcap(pcap_file)
                payloads = []
                time_stamps = []
                for ts, pkt in pc:
                    dtime = datetime.datetime.fromtimestamp(
                        int(ts)).strftime('%Y-%m-%d %H:%M:%S')
                    self.logger.debug('Time:', dtime)
                    time_stamps.append(ts)
                    payloads.append(pkt)

        f.close()

    def toStixXml(self):
        """
        This method converts a DetectorEvent object into a STIX compliant XML
        string ready for output. It first converts the object into a hash of the
        right format and then converts it into XML using STIXPackage.from_dict
        and to_xml on the resulting object.

        Returns:

        Reference to string containing STIX/CybOX XML file.
        """
        self.logger.debug('In toStixXml')
        stixDict = {'campaigns': [{}],
         'courses_of_action': [{}],
         'exploit_targets': [{}],
         'id': 'INSERT_PACKAGE_ID_HERE'}
        stixDict['incidents'] = []
        stixDict['indicators'] = [{}]
        stixDict['observables'] = {'major_version': 2,
                                   'minor_version': 1,
                                   'observables': [{}],
                                   'update_version': 0}
        stixDict['stix_header'] =  {'description': 'DESCRIPTION',
                                    'handling':
                                    [{'controlled_structure':
                                      '//node()',
                                      'marking_structures':
                                      [{'color': 'WHITE',
                                        'xsi:type':
                                        'tlpMarking:TLPMarkingStructureType'}]},
                                     {'controlled_structure':
                                      '//node()',
                                      'marking_structures':
                                      [{'xsi:type':
                                        'simpleMarking:SimpleMarkingStructureType'}]},
                                     {'controlled_structure': '//node()',
                                      'marking_structures':
                                      [{'xsi:type':
                                        'TOUMarking:TermsOfUseMarkingStructureType'}]}],
                                    'information_source': {'identity': {},
                                                           'time':
                                                           {'produced_time':
                                                            '2014-12-31T08:00:00+00:00'},
                                                           'tools': [{}]},
                                    'package_intents': [{'value': 'Incident',
                                                         'xsi:type':
                                                         'stixVocabs:PackageIntentVocab-1.0'}],
                                    'title': 'TITLE'}
        stixDict['threat_actors'] = [{}]
        stixDict['ttps'] = {'kill_chains':
                            {'kill_chains': [{'kill_chain_phases': [{}]}]},
                            'ttps': [{}]}
        stixDict['version'] = '1.1.1'
        for attack_instance in self.attackInstanceList:
            related_observables_hash = {'related_observables':
                                        {'observables': [],
                                         'scope':'exclusive'}}
            observables_list = (related_observables_hash['related_observables']
                                ['observables'])
            stixDict['incidents'].append(related_observables_hash)
            for packet in attack_instance.packetList:
                f_sec,sec = math.modf(packet.timeStamp)
                self.logger.debug('%f %f',sec,f_sec)
                dtime = datetime.datetime.fromtimestamp(
                    int(sec)).strftime('%Y-%m-%dT%H:%M:%S')+'.'+(
                        str(int(f_sec*1000000)))
                #dtime = '2014-10-13T14:08:00.002000+00:00'
                self.logger.debug('dtime = '+dtime)
                observable_dict = {}
                data_dict = {}
                properties_dict = {}
                packet_dict = {}
                observable_dict['observable'] = data_dict
                data_dict['keywords'] = [u'ProbAttack=' +
                                         str(packet.probAttack)]
                data_dict['object'] = properties_dict
                properties_dict['properties'] = packet_dict
                packet_dict['packaging'] = [{'algorithm': 'Base64',
                  'packaging_type': 'encoding'}]
                packet_dict['raw_artifact'] = base64.b64encode(packet.payload)
                packet_dict['type'] = 'Network Traffic'
                packet_dict['xsi:type'] = 'ArtifactObjectType'
                data_dict['observable_source'] = [
                    {'time':{'received_time':dtime}
                        }
                    ]
                observables_list.append(observable_dict)

        ofh = open('stix_dict.out', 'w')
        ofh.write(pformat(stixDict))
        self.logger.debug('Wrote stix dictionary to stix_dict.out')
        stix_package = STIXPackage.from_dict(stixDict)
        self.logger.debug('After constructor')
        stix_xml = stix_package.to_xml()
        return stix_xml
    def parseXML(self, xml_file):
        """
        This method takes a STIX/CybOX XML file and stores the content as a
        DetectorEvent object.

        Arguments:

        xml_file - Name of XML file in STIX/CybOX format to use as input to
                create the DetectorEvent objet.

        Returns:

        None
        """
        self.logger.debug('In toStixXml')
        stix_package = STIXPackage.from_xml(xml_file)
        stix_dict = stix_package.to_dict()

        # Extract attack instances
        related_observables_list = stix_dict['incidents']
        self.logger.debug('Number of Attacks: %d',len(related_observables_list))

        for r_obs in related_observables_list:
            observable_list = r_obs['related_observables']['observables']
            packet_list = []
            for obs in observable_list:
                ap = self.makeAttackPacket(obs)
                packet_list.append(ap)
            ai = AttackInstance(packet_list)
            self.attackInstanceList.append(ai)
    def makeAttackPacket(self, observable):
        """
        Takes 'observable' dictionary and extracts the necessary information to
        return an AttackInstance object

        Arguments:
        observable - An observable dictionary extracted from a STIX dictionary.

        Returns:
        An AttackInstance object.
        """
        m = re.search(r'ProbAttack=([0-9.]+)',
                      observable['observable']['keywords'][0])
        prob_attack = 0.0
        if m:
            prob_attack = float(m.group(1))
        else:
            self.logger.error('Unabale to find ProbAttack keyworkd')
            sys.exit(-1)
        if (observable['observable']['object']['properties']['packaging']
            [0]['algorithm'] != 'Base64'):
            self.logger.error('Packet encoding not Base64')
            sys.exit(-1)
        base64_packet = (observable['observable']['object']['properties']
                         ['raw_artifact'])
        binary_packet = base64.b64decode(base64_packet)
        received_time = (observable['observable']['observable_source'][0]
                         ['time']['received_time'])
        self.logger.debug('Received time: %s',received_time)
        m = re.search(r'(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.(\d+))?',
                      received_time)
        if m.group(7):
            self.logger.debug('usec = %s',m.group(7))
        if not m:
            self.logger.debug('Date match failed')
            sys.exit(-1)

        time_tuple = (int(m.group(1)),int(m.group(2)),int(m.group(3)),
                      int(m.group(4)),int(m.group(5)),int(m.group(6)),
                      0,0,True)


        usec = (float(m.group(7))/1000000.0) if m.group(7) else 0.0
        #usec = 0.0
        epoch_time = calendar.timegm(time_tuple) + usec
        epoch_time_from_local = time.mktime(time_tuple) + usec
        self.logger.debug('Epoch time from local: %f',epoch_time_from_local)
        self.logger.debug('Epoch Time: %f',epoch_time)
        return AttackPacket(prob_attack, epoch_time_from_local, binary_packet)

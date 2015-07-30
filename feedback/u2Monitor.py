#!/usr/bin/env python2.7
import shutil
class u2FileMonitor:

    """
    SYNOPSIS

    Feed back packets that match FASGuard rules to the Distribution point via STIX/TAXII.

    Set up a thread to monitor the fasguard.rules file from the Suricata Rules Directory and, if it changes,
    update the 'interesting SID List' by loading the fasguard rules in and extracting their SIDs.

    Monitor the Unified2 log file for Events (with packet records)  that have a SID that matches one of the
    FASGuard Rule SIDs.

    When an Event matches, push it on to the send queue.

    Periodically pull all queued Events, reformat them into Attack Records, and send them to the Distribution Point.

    """

    import logging
    import os
    import yaml
    import sys
    import re
    import lock
    import threading
    import tempfile
    import shutil
    import pickle

    """
    Locate the Suricata Configuration YAML file
    """
    def _getSuricataConfFile():
        paths=["/etc/suricata/suricata.yaml","usr/local/etc/suricata/suricata.yaml"]
        for path in paths:
            if os.path.isfile(path):
                return path
        logger.critical("Could not locate Suricata Configuration File")
        sys.exit(1)

    """
    Load the Suricata Configuration YAML file and extract the following:
        self.rulesDirectory: default rules directory
        self.fasguardRulesPath: absolute path of fasguard rules file
        self.logDir: Directory containing output unified 2 files
        self.unified2file: base name of unified2 output file
    """
    def _getSuricataConf():
        path = _getSuricataConfFile()
        if path is None:
            return None
        suriconf = None
        with open(path, 'r+') as stream:
            suriconf = yaml.load(stream)
        stream.close()
        if suriconf is None:
            logger.critical("Could not load Suricata Configuration File")
            sys.exit(1)
        self.rulesDirectory = conf["default-rule-path"]
        if self.rulesDirectory is None:
            logger.critical("Could not identify Suricata rules directory")
            sys.exit(1)
        path = self.rulesDirectory
        if not path.endswith("/"):
            path += "/"
        self.fasguardRulesPath = path + "fasguard.rules"
        if not os.path.exists(self.fasguardRulesPath):
            logger.critical("Could not locate Suricata fasguard rules file - "+self.fasguardRulesPath)
        outputs = conf["outputs"]
        if outputs is None:
            logger.critical("Could not locate outputs section in Suricata configuration file")
            sys.exit(1)
        unified2alert = outputs["unified2-alert"]
        if unified2alert is None:
            logger.critical("No unified2-alert section found in Suricata configuration file")
            sys.exit(1)
        self.unified2file = unified2alert["filename"]
        if self.unified2file is None:
            logger.critical("No filename value found for unified2-alert in Suricata configuration file")
            sys.exit(1)
        self.logDir = conf["default-log-dir"]
        if self.logDir is None:
            logger.critical("No default-log-dir value found in Suricata configuration file")
            sys.exit(1)

    """
    Load the variables that identify where to get rule sids and the unified2 logs from
    create the queue for queuing the events to the distribution system
    set the exit flag to false
    start the rule file monitoring thread
    start the unified2 spooling directory monitoring thread
    start the queue forwarding thread
    """
    def __init__(self):
        conf = _getSuricataConf()
        self.rulesmtime = 0  # catches writes to the file
        self.rulesctime = 0  # catches renames
        if not os.path.isfile(path):
            logger.info("u2Monitor ready, monitoring "+self.unified2path+" (doesn't exist yet)")
        else:
            logger.info("u2Monitor ready, monitoring "+self.unified2path)
        self.lock = Lock()
        self.outQueue = Queue.Queue()
        self.exit = False
        self.rulesThread = threading.Thread(target=self._monitorRulesFile())
        self.rulesThread.start()
        self.u2MonitorThread = threading.Thread(target=self._monitorUnified2File())
        self.u2MonitorThread.start()
        self.workdirpath = tempfile.mkdtemp()
        if not os.path.exists(self.workdirpath):
            os.makedirs(self.workdirpath)
        if not self.workdirpath.endswith(os.sep):
            self.workdirpath += os.sep

    def _loadSIDs(self):
        newSids = [] # empty list
        rulesFile = open(self.fasguardRulesPath)
        for rule in rulesFile:
            m = re.search('sid:(\d+);')
            if bool(m):
                rev = None
                sid = m.group(0)
                newSids.append(sid)
        with self.lock:
            self.sids = newSids

    def _monitorRulesFile(self):
        self.rfMonitorRunning = True
        while (not self.exit):
            # has the file changed?
            if self.rulesctime != os.path.getctime(self.fasguardRulesPath) or self.rulesmtime != os.path.getmtime(self.fasguardRulesPath):
                logger.debug("Rules change. Reloading SIDs")
                _loadSids(self)
                self.rulesctime = os.path.getctime(self.fasguardRulesPath)
                self.rulesmtime = os.path.getmtime(self.fasguardRulesPath)
            sleep(30)
        self.rfMonitorRunning = False

    def _monitorUnified2File(self):
        self.u2MonitorRunning = True
        reader = unified2.SpoolEventReader(self.logDir, self.unified2file, follow=True, delete=False, bookmark=True )
        while (not self.exit):
            # will block until an event is available
            for event in reader:
                logger.debug("Unified2 log change")
                if event.signature-id in self.sids:
                    with open(self.workdirpath + event.signature-id, "a") as outfile:
                        pickle.dump(event, outfile)
        self.u2MonitorRunning = False

    """
    This method converts an Event object into a STIX compliant XML
    string ready for output. It first converts the object into a hash of the
    right format and then converts it into XML using STIXPackage.from_dict
    and to_xml on the resulting object.

    Returns:

    Reference to string containing STIX/CybOX XML file.
    """
    def _createStixHeader(self, event):
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
        stixDict['version'] = '1.1.1'


    """
    Reads in each of the active SID packet files from the working directory, converts them to STIX XML Observables,
    then writes them to an output file for processing by the TAXII Transmitter
    """
    def _processSavedEvents(self):
        self.logger.debug("Process Saved Events")
        self.processSavedEventsRunning = True
        filelist = [ file for file in os.listdir(self.workdirpath) if isfile(join(self.workdirpath, file)) and file[0].isdigit()]
        for leaf in filelist:
            current = os.path.join(self.workdirpath, leaf)
            if (os.path.isfile(current)) and os.path:
                self.logger.debug("processing events for sid "+leaf)
                pcurrent = "p"+current
                if os.path.isfile(pcurrent):
                    ctime = os.path.getctime(pcurrent)
                    if ctime < time.time() - 86400:
                        logger.warning("Removing old temporary file for sid "+leaf)
                        os.remove(pcurrent)
                    else:
                        continue # on to next input file
                    os.rename(current, pcurrent)
                    with open("o"+current, "a") as outfile:
                        with open(pcurrent, "r") as infile:
                            self.multiAttackFlag = False
                            self.attackBoundaryFlag = False
                            event = None
                            count = 0
                            try:
                                # first packet
                                event = pickle.load(infile)
                                count++
                                # second packet
                                event = pickle.load(infile)
                                # multiple packets, set multiAttackFlag
                                self.multiAttackFlag = True
                            except(EOFError, UnpicklingError):
                                if count == 0:
                                    #empty file - delete it and continue to next sid file
                                    os.remove(pcurrent)
                                    continue
                            infile.seek(0,0)
                            description_string = '\n\t\t\t\tMultipleAttack = '
                            description_string += 'TRUE' if self.multiAttackFlag else 'FALSE'
                            description_string += '\n\t\t\t\tAttackBoundaries = '
                            description_string += 'TRUE' if self.attackBoundaryFlag else 'FALSE'
                            description_string += '\n\t\t\t'

        try:
            while(1):
                event = self.outQueue.get_nowait()
                xml = _toStixXml(event)

        except Queue.Empty:
            pass
        if not self.exit:
            # do it again in a minute
            threading.Timer(60,_processQueue).start()
        else:
            self.processSavedEventsRunning = False

if __name__ == "__main__":
    logging_level  = logging.DEBUG
    logger = logging.getLogger('u2Monitor')
    logger.setLevel(logging_level)

    ch = logging.StreamHandler()
    ch.setLevel(logging_level)
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    ch.setFormatter(formatter)
    logger.addHandler(ch)

    logger.info('Starting u2Monitor')

    suricataConf = getSuricataConf()
    if suricataConf is None:
        logger.critical("Could not load Suricata Configuration File")
        sys.exit(1)


    moi = MsgOnInsert(sys.argv[2],p_fh,'taxii_services_inboxmessage',5)
    moi.moiThread()

    sys.exit(0)

#!/usr/bin/env python2.7
"""
SYNOPSIS
This object hierarchy defines a top-level object that
defines general operations one might want to perform on an IDS instance.
DESCRIPTION
Certain functions are common regardless of the exact IDS a system is running.
This file contains the IDS class, which defines this set of operations.
Implementations for the Snort and the Suricata IDS applications are provided
to support these operations so that either IDS can be supported by the TAXII
rule update service.
"""
import logging
import sys
import os
import os.path
import stat
import argparse
import yaml
import signal
import psutil
import re
from subprocess import check_output
"""
A general class representing an IDS or IPS application.
"""
class IPS:
    def __init__(self):
        self.rulesFile = None
        self.cmd = None
        self.pid = None
        self.configFile = None
    """
    Return the path to the configuration file for the IDS/IPS instance
    Must be implemented in subclasses!
    """
    def _getConfigFile(self, pid):
        raise NotImplementedError("Method not implemented for " + self.__class__.__name__)
    def _getPid(self, name):
        ret = None
        try:
            ret = check_output(["pidof", "-s", name]).rstrip()
        except:
             pass
        return ret
    def isValid(self):
        return self.rulesFile is not None and self.rulesFile and os.access(self.rulesFile, os.F_OK|os.R_OK|os.W_OK)
    def _checkConfigFile(self, path):
                if not os.path.exists(path):
                    return
                if not os.access(path, os.F_OK):
                    raise OSError("The path " + path + " exists, but is not a file")
                if not os.access(path, os.R_OK):
                    raise OSError("No read access to " + path)
                if not os.access(path, os.W_OK):
                    raise OSError("No write access to " + path)
    """
    Add the provided list of rules to the rules file.
    """
    def updateRules(self, rules):
        if not self.isValid(self):
            raise ValueError("This IPS instance is not valid")
        if rules is not None and isinstance(rules, list) and len(rules) > 0:
            # APPEND the new rules to the file
            with open(path, 'a+') as stream:
                stream.write('\n'.join(rules) + '\n')
            self.signalReload(self)
    def _signalReload(self):
        raise NotImplementedError("Method not implemented for " + self.__class__.__name__)
class Suricata(IPS):
    """
    Constructor.
    pid is the process id of a running instance
    configFile is the path to the suricata.yaml file
    The primary goal of the constructor is to obtain the path to the FASGuard rules
    file, creating it if necessary.
    """
    def __init__(self, pid=None, configFile=None):
        self.cmd = "suricata"
        self.pid = pid
        self.configFile = configFile
        self.rulesFile = None
        if not self.configFile and not self.pid:
            # Look for a running instance
            self.pid = IPS._getPid(self, "suricata")
        if not self.configFile and not self.pid:
            # No running instance. Find a config file using default paths
            self._getSuricataConfFile()
        else:
            # Found a running process. see if the config file is specified
            # in the command line.
            try:
                cmdline = check_output(["ps","-p", self.pid, "-o","cmd", "-h"])
            except:
                pass
            if cmdline:
                match = re.search('\s*-c\s+(\S+)\s', cmdline)
                if match and match.group(1):
                    configFile = match.group(1)
                    IPS._checkConfigFile(self, configFile)
                    self.configFile = configFile
            if not self.configFile:
                # command line didn't specify an config file. Go for defaults.
                self._getSuricataConfFile()
        # OK, at this point we SHOULD have a configuration file
        if not self.configFile:
            raise ValueError("Cannot identify a Suricata Configuration File to use")
        # we DO have a configuration file
        # get current FASGuard rules file path, if it exists
        self._getRulesFileFromConf()
        # add rules file to conf if it does not
        if not self.rulesFile:
            self._addRulesFileToConf()
        # OK, we have a path to a rules file, which was the goal of this whole mess
        # The path is now included in the configuration file, if it was not already
        # We should create it as an empty file if it does not exist
        if not os.path.exists(self.rulesFile):
            os.mknod(self.rulesFile, 0664|stat.S_IFREG)
    """
    Set the configuration file by looking for a path in a predefined order.
    """
    def _getSuricataConfFile(self):
        paths = ["/etc/suricata/suricata.yaml","/usr/local/etc/suricata/suricata.yaml"]
        for path in paths:
            if os.path.isfile(path):
                try:
                    IPS.checkConfigFile(self, path)
                    self.configFile = path
                except OSError:
                    pass
    def _getRulesFileFromConf(self):
        with open(self.configFile, 'r+') as stream:
            print "configFile: " + self.configFile
            suriconf = yaml.load(stream)
            stream.close()
            if suriconf:
                rulesFiles = suriconf["rule-files"]
                print "rulesFiles: " + ', '.join(rulesFiles)
                if "FASGuard.rules" in rulesFiles:
                    print "FASGuard.rules is there"
                    self.rulesDir = suriconf["default-rule-path"]
                    if not self.rulesDir:
                        self.rulesDir = os.path.dirname(self.configFile) + "/rules"
                    if self.rulesDir.endswith('/'):
                        self.rulesFile = self.rulesDir + "FASGuard.rules"
                    else:
                        self.rulesFile = self.rulesDir + "/FASGuard.rules"
                    print "rulesFile: "+self.rulesFile
    def _addRulesFileToConf(self):
        with open(self.configFile, "rw+") as stream:
            suriconf = yaml.load(stream)
            if suriconf:
                rulesFiles = suriconf["rule-files"]
                if not "FASGuard.rules" in rulesFiles:
                    rulesFiles.append("FASGuard.rules")
                    stream.seek(0)
                    stream.write(yaml.dump(suriconf, default_flow_style=False ))
                    self.rulesDir = suriconf["default-rule-path"]
                    if not self.rulesDir:
                        self.rulesDir = os.path.dirname(self.configFile) + "/rules"
                    if self.rulesDir.endswith('/'):
                        self.rulesFile = self.rulesDir + "FASGuard.rules"
                    else:
                        self.rulesFile = self.rulesDir + "/FASGuard.rules"
    def _signalReload(self):
        if self.pid is not None and self.pid:
            # process was running - send USR2
            os.kill(self.pid, signal.SIGUSR2)
class Snort(IPS):
    """
    Constructor.
    pid is the process id of a running instance
    configFile is the path to the snort.conf file
    The primary goal of the constructor is to obtain the path to the FASGuard rules
    file, creating it if necessary.
    """
    def __init__(self, pid=None, configFile=None):
        self.cmd = "snort"
        self.pid = pid
        self.configFile = configFile
        self.rulesFile = None
        if not self.configFile and not self.pid:
            # Look for a running instance
            self.pid = IPS._getPid(self, "snort")
        if not self.configFile and not self.pid:
            # No running instance. Find a config file using default paths
            self._getSnortConfFile()
        else:
            # Found a running process. see if the config file is specified
            # in the command line.
            try:
                cmdline = check_output(["ps","-p", self.pid, "-o","cmd", "-h"])
            except:
                pass
            if cmdline:
                match = re.search('\W-c\W+(\S+)\W', cmdline)
                if match and match.group(1):
                    configFile = match.group(1)
                    IPS.checkConfigFile(self, configFile)
                    self.configFile = configFile
            if not self.configFile:
                # command line didn't specify an config file. Go for defaults.
                self._getSnortConfFile()
        # OK, at this point we SHOULD have a configuration file
        if not self.configFile:
            raise ValueError("Cannot identify a Snort Configuration File to use")
        # we DO have a configuration file
        # get current FASGuard rules file path, if it exists
        self._getRulesFileFromConf()
        # add rules file to conf if it does not
        if not self.rulesFile:
            self._addRulesFileToConf()
        # OK, we have a path to a rules file, which was the goal of this whole mess
        # The path is now included in the configuration file, if it was not already
        # We should create it as an empty file if it does not exist
        if not os.path.exists(self.rulesFile):
            os.mknod(self.rulesFile, 0664|stat.S_IFREG)
    """
    Set the configuration file by looking for a path in a predefined order.
    """
    def _getSnortConfFile(self):
        paths = ["/etc/snort/snort.conf","/usr/local/etc/snort.conf"]
        for path in paths:
            if os.path.isfile(path):
                try:
                    IPS._checkConfigFile(self, path)
                    self.configFile = path
                except OSError:
                    pass
    def _getRulesFileFromConf(self):
        with open(self.configFile, 'r+') as stream:
            for line in stream:
                match = re.search("\s*var\s+RULE_PATH\s+(\S+)", line)
                if match and match.group(1):
                    self.rulesDir = match.group(1)
                    if not self.rulesDir:
                        self.rulesDir = os.path.dirname(self.configFile) + "/rules"
                    if self.rulesDir.endswith('/'):
                        self.rulesFile = self.rulesDir + "FASGuard.rules"
                    else:
                        self.rulesFile = self.rulesDir + "/FASGuard.rules"
                    break
    def _addRulesFileToConf(self):
        # does nothing - conf file only identifies directory
        pass
    def _signalReload(self):
        if self.pid is not None and self.pid:
            # process was running - send USR2
            os.kill(self.pid, signal.SIGHUP)
def setup():
    ips = Snort()
    print ips.rulesFile
if __name__ == '__main__':
    setup()

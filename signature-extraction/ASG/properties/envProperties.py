#!/usr/bin/env python3.4
"""
SYNOPSIS

This is a wrapper for properties.Properties that provides expansion of
environmental variables embedded in property values.

DESCRIPTION

The property is looked up using the Config::Properties package.  The value
is then evaluated inside the expression `echo $val` where we are using
backquotes.  The string returned by the echo is then provided as the value
of the getProperty method.
"""

import logging
import sys
import os
import properties

class EnvProperties:
    """
    This class expands environmenta variables in properties before inserting
    the properties in the properties.Properties class.
    """
    def __init__(self, propertiesFile):
        """
        Constructor.

        Arguments:
        propertiesFile - Path to properties
        """
        self.propObj = properties.Properties()
        try:
            propFileObj = open(propertiesFile,"r")
        except IOError as e:
            logging.error("I/O error({0}): {1}".format(e.errno, e.strerror))
            sys.exit('Open of '+propertiesFile+' failed')
        self.propObj.load(propFileObj)
    def getProperty(self, key):
        """
        Passes parameters to properties.Properties and then uses os.popen with
        echo to expand environmental variables.
        """
        val = self.propObj.getProperty(key)

        if val is not None:
            expanded_val = os.popen('echo '+val).read().rstrip()
            return expanded_val
        else:
            return None

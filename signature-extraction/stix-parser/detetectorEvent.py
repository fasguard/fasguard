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
        self.logger = logging.getLogger('root')

        if input_file:
            if re.match(r'.*\.fst',input_file):
                self.logger.debug('FST file: %s',input_file)
            elif re.match(r'.*\.xml',input_file):
                self.logger.debug('STIX file: %s',input_file)
            else:
                self.logger.error('Bad file name: %s',input_file)
                sys.exit(-1)

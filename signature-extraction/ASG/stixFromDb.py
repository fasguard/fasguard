#!/usr/bin/env python2.7
import logging
import sys
import os
import sqlite3
import re
import xml.etree.ElementTree as ET

class StixFromDb:
    """
    SYNOPSIS

    Retrieve STIX attack files for ASG from database.

    DESCRIPTION

    Listen on named pipe for DB index of new STIX XML in the database and
    extract it for processing.
    """
    def __init__(self, properties):
        """
        Constructor which opens connection to sqlite3 DB and to named pipe.

        Arguments:
        properties - An EnvProperties object which contains information coming
                from a properties file.
        """
        self.logger = logging.getLogger('simple_example')
        db_file = properties.getProperty('StixFromDb.DbFile')
        self.logger.debug('db_file = %s',db_file)
        con = sqlite3.connect(db_file)
        cur = con.cursor()
        self.dbCursor = cur
        pipe_filename = properties.getProperty('StixFromDb.PipeFilename')
        self.pipeFh = open(pipe_filename,'r')
        stix_xml_filename = properties.getProperty('StixFromDb.StixXmlFilename')
        self.stixXmlFilename = stix_xml_filename
    def processStix(self):
        """
        This method blocks on a read from the named pipe. Once a value is read
        from the pipe, it is assumed to be an index into the database table
        entry containing the FASGuard/STIX data. The data is written to a file
        and the function returns true if successful, false otherwise.
        """
        while True:
            index = self.pipeFh.readline()[:-1]
            self.logger.debug('Received index: %s',index)
            if index.isdigit():
                break
        sql_stmt = 'select original_message from taxii_services_inboxmessage where id = %s' % (index)
        self.dbCursor.execute(sql_stmt)
        xml_content = self.dbCursor.fetchone()[0]
        #self.logger.debug('xml_content=%s',xml_content)
        m = re.search(r'<taxii_11:Content>(.*)</taxii_11:Content>',xml_content,
                      re.DOTALL)
        stix_xml = m.group(1)
        # tree = ET.fromstring(xml_content)
        # namespaces = {'taxii_11':
        #               "http://taxii.mitre.org/messages/taxii_xml_binding-1.1"}
        # subTree = tree.find('taxii_11:Content', namespaces)
        # stix_xml = ET.tostring(subTree)
        fh = open(self.stixXmlFilename,'w')
        fh.write(stix_xml)
        fh.close()
        return True

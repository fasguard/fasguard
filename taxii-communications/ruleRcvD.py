#!/usr/bin/env python2.7
"""
SYNOPSIS

Receive FASGuard/STIX rule files for remote Suricata using TAXII.

DESCRIPTION

We set up a django server to receive FASGuard/STIX rule XML files and place
them into a sqlite database. We also set up a trigger that sends a signal to
the module which adds the rules to Suricata when a new entry is placed into the
sqlite database.
"""

import logging
import sys
import os
import argparse
import thread
from properties.envProperties import EnvProperties
from django.core.management import execute_from_command_line
from msgOnInsert import MsgOnInsert

def watch4Insert(db, table, named_pipe):
    """
    Function for thread to watch for insertions into sqlite db.

    Arguments:
    db - Database handle for sqlite database
    table - Table to check for latest insert
    named_pipe - Pipe into which index for the latest insert is injected
    """
    pass
def setup():
    parser = argparse.ArgumentParser(
        description='Watches for FASGuard/STIX message from the ASG, '+
        'stores it in sqlite DB and sends signal to Suricata reloader')
    parser.add_argument('-d','--debug',required=False,action='store_true',
                        help='run with debug logging')
    parser.add_argument('-p','--properties',type=str,required=False,
                        default='rrd.properties',help='properties file')

    args = parser.parse_args()
    #print "In file: ",args.in_file
    FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    logging_level  = logging.DEBUG if args.debug else logging.INFO
    logger = logging.getLogger('simple_example')
    logger.setLevel(logging_level)

    ch = logging.StreamHandler()
    ch.setLevel(logging_level)
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    ch.setFormatter(formatter)
    print 'logging.DEBUG',logging.DEBUG
    logger.addHandler(ch)

    logger.debug('debug message')

    #sys.exit(-1)
    properties = EnvProperties(args.properties)

    # Retrieve the rule file directory where we'll watch for new files

    incoming_port = properties.getProperty('RuleRcvD.IncomingPort')
    sleep_sec = int(properties.getProperty('RuleRcvD.DBWatchSleepS'))
    named_pipe = properties.getProperty('RuleRcvD.NamedPipe')
    db_file = properties.getProperty('RuleRcvD.DbFile')
    p_fh = open(named_pipe,'w+')


    # Create MsgOnInsert object that will watch for new insertions into the
    # database by django
    moi = MsgOnInsert(os.environ['YETIPATH']+'/'+db_file,p_fh,
                      'taxii_services_inboxmessage',sleep_sec)
    # Start thread
    thread.start_new_thread(moi.moiThread,())

    sys.path.append(os.environ['YETIPATH'])
    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "yeti.settingsRules")

    exec_args = [os.environ['YETIPATH']+'/manage.py','runsslserver',
                 '--addrport','0.0.0.0:'+incoming_port]


    execute_from_command_line(exec_args)
    moi.loopFlag = False

if __name__ == '__main__':
    setup()

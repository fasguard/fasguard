#!/usr/bin/env python2.7
import logging
import os
import sys
import sqlite3
import time


class MsgOnInsert:
    """
    Sets up a thread which periodically checks for new insertion.
    """
    def __init__(self, db_filename, pipe_handle, table, sleep_sec):
        """
        Constructor stores connection information and then registers callback.

        Arguments:
        db_filename - Sqlite database filename.
        pipe_handle - Handle for pipe to which information about sqlite db
                information will be written.
        table - Name of table to check for new insertion.
        sleep_sec - Number of seconds to sleep
        """
        self.dBFilename = db_filename
        self.pipeHandle = pipe_handle
        self.Table = table
        self.sleepSec = sleep_sec
        self.maxIndex = 0
        self.loopFlag = 1
        self.logger = logging.getLogger('simple_example')
        self.logger.debug('In MsgOnInsert constructor')

    def moiThread(self):
        """
        This method is called in a thread and checks the database for new
        entries every few seconds.
        """
        con = sqlite3.connect(self.dBFilename)
        cur = con.cursor()
        sql_stmt = 'select max(id) from %s' % (self.Table)
        cur.execute(sql_stmt)
        cur_index = cur.fetchone()[0]
        # Set max at initial max
        self.maxIndex = cur_index
        while self.loopFlag:
            time.sleep(self.sleepSec)
            self.logger.debug('Query: %s',sql_stmt)
            cur.execute(sql_stmt)
            cur_index = cur.fetchone()[0]
            if cur_index > self.maxIndex:
                self.logger.debug('Writing %d to pipe',cur_index)
                self.pipeHandle.write('%d\n'%(cur_index))
                self.pipeHandle.flush()
                self.maxIndex = cur_index
            else:
                self.logger.debug('Pipe empty')
            self.logger.debug('Cur Index = %d',cur_index)

if __name__ == "__main__":
    # For testing only
    FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    logging_level  = logging.DEBUG
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

    #p_fh = os.open(sys.argv[1],os.O_WRONLY|os.O_NONBLOCK)
    p_fh = open(sys.argv[1],'w+')
    logger.debug('After pipe open')
    moi = MsgOnInsert(sys.argv[2],p_fh,'taxii_services_inboxmessage',5)
    moi.moiThread()

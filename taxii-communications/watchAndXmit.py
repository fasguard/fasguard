import pyinotify
import subprocess
import logging
import os
import sys

class EventHandler(pyinotify.ProcessEvent):
    def __init__(self, wax_obj):
        """
        Constructor which passes in the WatchAndXmit object that will be
        used to transmit the attack files as soon as they are detected.

        Arguments:
        wax_obj - WatchAndXmit object that will be invoked in the callbacks
                to transmit the attack
        """
        self.watchAndXmitObj = wax_obj
    def process_IN_CREATE(self, event):
        print "Creating:",event.pathname
        self.watchAndXmitObj.fileCreated(event.pathname)

    def process_IN_CLOSE_WRITE(self, event):
        print "Closing:",event.pathname
        self.watchAndXmitObj.fileClosed(event.pathname)

class WatchAndXmit:
    """
    An event handler is registered to watch a directory to see if a new attack
    file is created. If it is, we wait till it's closed and then transmit if
    via TAXII.
    """
    def __init__(self, watch_dir, properties):
        """
        Initialize class with name of directory to watch where attack file
        will be placed.

        Arguments:
        watch_dir - The directory to watch into which an attack file will be
                placed.
        properties - Properties file
        """
        self.logger = logging.getLogger('simple_example')
        self.watchDir = watch_dir
        self.properties = properties
        self.rcvUrl = properties.getProperty('WatchAndXmit.RcvUrl')
        self.xmitKey = properties.getProperty('WatchAndXmit.XmitKey')
        self.xmitCert = properties.getProperty('WatchAndXmit.XmitCert')
        self.attackFileDict = {}
    def startLoop(self):
        """
        Block waiting for file creation in the watched directory.
        """
        wm = pyinotify.WatchManager()
        mask = pyinotify.IN_CREATE | pyinotify.IN_CLOSE_WRITE
        handler = EventHandler(self)
        notifier = pyinotify.Notifier(wm, handler)
        wdd = wm.add_watch(self.watchDir, mask, rec=True)

        notifier.loop()
    def fileCreated(self, file):
        """
        Records a file that was just created in the watched directory in a
        dictionary. When fileClosed is called for that file, the file is
        transmitted via Yeti/TAXII.

        Arguments:
        file - The file that was created.
        """
        self.attackFileDict[file] = True
    def fileClosed(self, file):
        """
        Checks for the file in the attackFileDict dictionary. If found, it is
        transmitted via Yeti/TAXII. The file is then deleted locally and then
        removed from the dictionary.

        Arguments:
        file - The file that was closed.
        """
        if file in self.attackFileDict:
            #logger.debug('Call to %s, file %s',self.rcvUrl,file)
            arg_list = ['inbox_client','--url',self.rcvUrl,'--dcn','default',
                        '--content-file',file,'--key',self.xmitKey,'--cert',
                        self.xmitCert]
            if subprocess.call(arg_list) != 0:
                self.logger.error('Call to inbox_client failed')
                sys.exit(-1)
            else:
                os.remove(file)
                del self.attackFileDict[file]

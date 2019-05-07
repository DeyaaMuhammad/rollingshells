#!/usr/bin/env python3

# -- coding: UTF-8 --


'''
              .__  .__  .__                        .__           .__  .__          
_______  ____ |  | |  | |__| ____    ____     _____|  |__   ____ |  | |  |   ______
\_  __ \/  _ \|  | |  | |  |/    \  / ___\   /  ___/  |  \_/ __ \|  | |  |  /  ___/
 |  | \(  <_> )  |_|  |_|  |   |  \/ /_/  >  \___ \|   Y  \  ___/|  |_|  |__\___ \ 
 |__|   \____/|____/____/__|___|  /\___  /  /____  >___|  /\___  >____/____/____  >
                                \//_____/        \/     \/     \/               \/ 
'''


import os
import json
import shodan
import random
import socket
import argparse
import logging
from logging import config 

SHODAN_CONFIG = {
    "key": "",
    "query": "port:23 +root  +@ +# -login -name -Password -Session -user",
    "filename": "./results.json",
}

LOG_CONFIG = {
    'version':1,
    'formatters':{
        'error':{
            'format': "%(levelname)s at %(asctime)s in %(funcName)s in %(filename) at line %(lineno)d: %(message)s",
            'datefmt': '%Y-%m-%d %H:%M:%S'
        },
        'debug':{
            'format': "[%(asctime)s]: %(message)s",
            'datefmt': '%Y-%m-%d %H:%M:%S'
        },
        'info':{
            'format': "%(message)s",
            'datefmt': '%Y-%m-%d %H:%M:%S'
            }
    },
    'handlers':{
        'console':{
            'class':'logging.StreamHandler',
            'formatter':'info',
            'level':logging.INFO
        },
        # 'file':{
        #     'class':'logging.FileHandler',
        #     'filename':'.log',
        #     'formatter':'debug',
        #     'level':logging.INFO
        # }
    },
    'root':{
        # 'handlers':['console','file'],
        'handlers':['console'],
        'level':'INFO'
    }
}

class RS(object):

    """docstring for RS."""
    def __init__(self, args):


        self.key = SHODAN_CONFIG['key']
        self.query = SHODAN_CONFIG['query']
        self.filename = SHODAN_CONFIG['filename']

        self.results = None

        if args.key:
            self.key = args.key

        if args.update:
            self.saveResults(self.api())

        self.randConnect()


    def check(self, ip, port='23'):
        try:

            logging.info('Checking %s using port %s.' % (ip, port) )
            s = socket.socket()
            s.connect((ip, port))

            logging.error('Checking Success.')
            return True

        except:
            logging.error('Checking Failed.')
            return False

        finally:
            s.close()

        

    def connect(self, ip, port='23'):
        try:
            logging.info('Connecting to %s using port %s ...' % (ip, port) )
            os.system('telnet %s %s' %(ip, port))

        except:
            logging.error("There was a problem connecting to %s" %ip )
            return False


    def randConnect(self):
        try:

            logging.info('Reading Saved SHODAN Matches ...')
            results = self.readResults()

            while(True):

                result = self.randResult(results)

                ip = result['ip_str']
                port = result['port']
                location = result['location']

                logging.info("Choosing %s:%s located at %s" % (ip, port, location['country_name']) )

                if self.check(ip, port):
                    self.connect(ip, port)
                    break;

        except:
            logging.error("There was a problem choosing random target.")
            exit()


    def randResult(self, results):
        try:
            logging.info('Choosing a random target.')
            resultint = random.randint(0, len(results['matches']))
            result = results['matches'][resultint]

            return result

        except:
            logging.error("There was a problem choosing random target.")




    def readResults(self, filename=None):
        try:
            if filename is None:
                filename = self.filename

            logging.info('Trying to Open %s ...' %self.filename)
            with open(filename, 'r') as f:
                return json.load(f)

        except:
            logging.error("There was a problem reading shodan saved results.")
            exit()

    def saveResults(self, results, filename=None):
        try:
            if filename is None:
                filename = self.filename

            logging.info('Trying to Open %s ...' %self.filename)
            with open(filename, 'w') as f:
                return json.dump(results, f, sort_keys=True, indent=4)

        except:
            logging.error("There was a problem saving shodan results.")
            exit()


    def api(self, key=None , query=None):
        try:

            if key is None:
                key = self.key

            if query is None:
                query = self.query

            logging.info('Connecting to Shodan ...')
            api = shodan.Shodan(key)

            logging.info('Searching for targets.')
            return api.search(query)
        
        except:
            logging.error("There was a problem onnecting to shodan.")
            exit()


class CLI(object):
    """docstring for CLI."""
    def __init__(self):
        self.logging()
        self.main()

    def banner(self):
        print (__doc__)

    def logging(self):
        logging.config.dictConfig(LOG_CONFIG)

    def main(self):

        # Set formatter setting s to remove spaces
        os.environ['COLUMNS'] = "120"
        formatter = lambda prog: argparse.HelpFormatter(prog,max_help_position=52)
        parser = argparse.ArgumentParser(formatter_class=formatter)

        # Set args with Default values.
        parser.add_argument("-k","--key",action="store",dest="key",default=SHODAN_CONFIG['key'],help="SHODAN API KEY.")
        parser.add_argument("-u","--update",action="store_true",dest="update",default=False,help="Update Results.")
        # parser.add_argument("-l","--log",action="store",dest="log",help="Logging to file")

        args = parser.parse_args()


        # Print Banner
        self.banner()

        # Call RS
        if args.key:
            e = RS(args = args)
        else:
            parser.error("shodan key is required.") 


if __name__ == "__main__":
    CLI()

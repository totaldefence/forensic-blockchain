#!/usr/bin/env python3

''' Synchronizes blockchain across all machines

When executed, this program synchronizes the blockchain across all
participating machines. It contains two functions:

getbc(): retrieves the blockchain from each agent
putbc(): distributes (copies) the latest blockchain to each agent

This program is invoked by each machine's cronjob.

'''

import os
import shutil
import argparse
from subprocess import run, CalledProcessError
from time import time, ctime, localtime, strftime

LOGFILE = 'log_m0'
MACHINES = ['m1', 'm2', 'm4']
BLOCKCHAINFILE = 'blockchain_pickle'

class getbcError(Exception):
    pass
class putbcError(Exception):
    pass

def getbc(machine=None):
    ''' Retrieve blockchain pickle file from each machine
    '''
    if machine is None:
        raise getbcError(f'Need to specify a source machine')
    command = []
    command.append('scp')
    command.append('-q')
    command.append(f'{machine}:{machine}/{BLOCKCHAINFILE}')
    command.append(f'blockchain_pickle_{machine}')
    kwds = {}
    kwds['check'] = True
    kwds['capture_output'] = True
    kwds['text'] = True
    try:
        cp = run(command, **kwds)
        cmdoutput = cp.stdout
        returncode = cp.returncode
    except CalledProcessError:
        raise getbcError(f'Error getting blockchain pickle from {machine}')
    return None

def putbc(machine=None, filetosend=None):
    ''' Distribute latest blockchain pickle file to each machine
    '''
    if machine is None or filetosend is None:
        raise putbcError(f'Need to specify a file and machine')
    command = []
    command.append('scp')
    command.append('-q')
    command.append(f'{filetosend}')
    command.append(f'{machine}:{machine}/')
    kwds = {}
    kwds['check'] = True
    kwds['capture_output'] = True
    kwds['text'] = True
    try:
        cp = run(command, **kwds)
        cmdoutput = cp.stdout
        returncode = cp.returncode
    except CalledProcessError:
        raise putbcError(f'Error putting blockchain pickle to {machine}')
    return None

def echo(print_this):
    with open(LOGFILE, 'a') as f:
        unixtime = time()
        datetime = ctime(unixtime)
        tz = localtime(unixtime).tm_zone
        tzoffset = strftime('%z', localtime(unixtime))
        f.write(f'{unixtime:<16.4f}{datetime:<25}{print_this}')


def main():

    p = argparse.ArgumentParser(description='sync blockchain')
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument('--get', help='get blockchain files', action='store_true')
    g.add_argument('--put', help='distribute current blockchain', action='store_true')

    args = p.parse_args()

    if args.get:
        for machine in MACHINES:
            getbc(machine=machine)
            echo(f'\"retrieved blockchain from {machine} to blockchain_pickle_{machine}\"\n')


    elif args.put:
        for machine in MACHINES:
            putbc(machine=machine, filetosend=f'{BLOCKCHAINFILE}')
            echo(f'\"uploaded latest blockchain to {machine}\"\n')


if __name__ == "__main__":
    main()


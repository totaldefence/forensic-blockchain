#!/usr/bin/env python3

''' Makes pre-defined changes to assets for simulation purposes

This program is executed on each agent machine at pre-defined scheduled times.
It perturbs the state of digital assets monitored by the agent machine.
These changes propogate onto the blockchain thus simulating the monitoring
of assets whose state can change over time.

The execution of this program is logged by each agent during the simulation

'''

import os
import shutil
import argparse
from time import time, ctime, localtime, strftime


STATEFILE = 'simstate'
LOGFILE = 'log'


class m1_1_Error(Exception):
    pass
class m1_2_Error(Exception):
    pass
class m1_3_Error(Exception):
    pass
class m1_4_Error(Exception):
    pass
class m1_5_Error(Exception):
    pass
class m1_6_Error(Exception):
    pass
class m1_7_Error(Exception):
    pass
class m1_8_Error(Exception):
    pass
class m1_9_Error(Exception):
    pass


class m2_1_Error(Exception):
    pass
class m2_2_Error(Exception):
    pass
class m2_3_Error(Exception):
    pass
class m2_4_Error(Exception):
    pass
class m2_5_Error(Exception):
    pass
class m2_6_Error(Exception):
    pass
class m2_7_Error(Exception):
    pass
class m2_8_Error(Exception):
    pass
class m2_9_Error(Exception):
    pass
class m2_10_Error(Exception):
    pass
class m2_11_Error(Exception):
    pass


class m4_1_Error(Exception):
    pass


class m1_1r_Error(Exception):
    pass
class m1_2r_Error(Exception):
    pass
class m1_3r_Error(Exception):
    pass
class m1_4r_Error(Exception):
    pass
class m1_5r_Error(Exception):
    pass
class m1_6r_Error(Exception):
    pass
class m1_7r_Error(Exception):
    pass
class m1_8r_Error(Exception):
    pass


class m2_1r_Error(Exception):
    pass
class m2_2r_Error(Exception):
    pass
class m2_3r_Error(Exception):
    pass
class m2_4r_Error(Exception):
    pass
class m2_5r_Error(Exception):
    pass


class m4_1r_Error(Exception):
    pass


class modifypathError(Exception):
    pass
class revertpathError(Exception):
    pass
class funcError(Exception):
    pass


def skip():
    pass


# agent m1

def m1_1():
    try:
        shutil.copy2('trustme-certificate-authority.crt', '/usr/share/ca-certificates/mozilla/')
    except:
        raise m1_1_Error('Error copying trustme-certificate-authority.crt')

def m1_2():
    try:
        shutil.copy2('reactorspec.odt.bad', 'documents/reactorspec.odt')
    except:
        raise m1_2_Error('Error copying reactorspec.odt.bad')

def m1_3():
    try:
        shutil.copy2('awsiplist.bad', '/etc/cron.monthly/awsiplist')
    except:
        raise m1_3_Error('Error copying awsiplist.bad')

def m1_4():
    try:
        shutil.copy2('supplierdata.bad', 'documents/supplierdata')
    except:
        raise m1_4_Error('Error copying supplierdata.bad')

def m1_5():
    pass

def m1_6():
    try:
        os.rename('files/certlog', 'files/.temp')
    except:
        raise m1_6_Error('Error renaming certlog to .temp')

def m1_7():
    try:
        os.remove('files/ntfslog')
    except:
        raise m1_7_Error('Error removing ntfslog')

def m1_8():
    try:
        shutil.copy2('files/.temp', 'files/ntfslog')
    except:
        raise m1_8_Error('Error copying .temp to ntfslog')

def m1_9():
    try:
        os.chmod('files/secret', 493)
    except:
        raise m1_9_Error('Error chmod 493')



# agent m2

def m2_1():
    # asset 2000
    try:
        shutil.copy2('hanoi.py', '/usr/bin/')
    except:
        raise m2_1_Error('Error copying hanoi.py')

def m2_2():
    # asset 2001
    try:
        shutil.copy2('authorized_keys.bad', '../.ssh/authorized_keys')
    except:
        raise m2_2_Error('Error copying authorized_keys.bad')

def m2_3():
    # asset 2002
    try:
        shutil.copy2('sources.list.bad', '/etc/apt/sources.list')
    except:
        raise m2_3_Error('Error copying sources.list.bad')

def m2_4():
    # asset 2003
    try:
        shutil.copy2('trustme.gpg', '/etc/apt/trusted.gpg.d/')
    except:
        raise m2_4_Error('Error copying trustme.gpg')

def m2_5():
    # asset 2004
    try:
        shutil.copy2('samplefiles/userlog.2', 'syslogs/userlog')
    except:
        raise m2_5_Error('Error copying userlog.2')

def m2_6():
    # asset 2005
    try:
        shutil.copy2('samplefiles/commslog.2', 'syslogs/commslog')
    except:
        raise m2_6_Error('Error copying commslog.2')

def m2_7():
    # asset 2006
    try:
        shutil.copy2('samplefiles/invoicelog.2', 'syslogs/invoicelog')
    except:
        raise m2_7_Error('Error copying invoicelog.2')

def m2_8():
    # asset 2005
    try:
        shutil.copy2('samplefiles/commslog.3', 'syslogs/commslog')
    except:
        raise m2_8_Error('Error copying commslog.3')

def m2_9():
    # asset 2006
    try:
        shutil.copy2('samplefiles/invoicelog.3', 'syslogs/invoicelog')
    except:
        raise m2_9_Error('Error copying invoicelog.3')

def m2_10():
    # asset 2006
    try:
        shutil.copy2('samplefiles/invoicelog.4', 'syslogs/invoicelog')
    except:
        raise m2_10_Error('Error copying invoicelog.4')

def m2_11():
    # asset 2006
    try:
        shutil.copy2('samplefiles/invoicelog.5', 'syslogs/invoicelog')
    except:
        raise m2_11_Error('Error copying invoicelog.5')



# agent m4

def m4_1():
    try:
        shutil.copy2('hosts.bad', '/etc/hosts')
    except:
        raise m4_1_Error('Error copying hosts.bad')




# agent m1 revert

def m1_1r():
    try:
        os.remove('/usr/share/ca-certificates/mozilla/trustme-certificate-authority.crt')
    except:
        raise m1_1r_Error('Error removing /usr/share/ca-certificates/mozilla/trustme-certificate-authority.crt')

def m1_2r():
    try:
        shutil.copy2('reactorspec.odt.good', 'documents/reactorspec.odt')
    except:
        raise m1_2r_Error('Error copying reactorspec.odt.good')

def m1_3r():
    try:
        shutil.copy2('awsiplist.good', '/etc/cron.monthly/awsiplist')
    except:
        raise m1_3r_Error('Error copying awsiplist.good')

def m1_4r():
    try:
        shutil.copy2('supplierdata.good', 'documents/supplierdata')
    except:
        raise m1_4r_Error('Error copying supplierdata.good')

def m1_5r():
    pass

def m1_6r():
    try:
        os.rename('files/.temp', 'files/certlog')
    except:
        raise m1_6r_Error('Error renaming .temp to certlog')

def m1_7r():
    try:
        shutil.copy2('samplefiles/ntfslog', 'files/ntfslog')
    except:
        raise m1_7r_Error('Error reverting ntfslog')

def m1_8r():
    try:
        os.chmod('files/secret', 420)
    except:
        raise m1_8r_Error('Error reverting to chmod 420')




# agent m2 revert

def m2_1r():
    # asset 2000
    try:
        os.remove('/usr/bin/hanoi.py')
    except:
        raise m2_1r_Error('Error removing /usr/bin/hanoi.py')

def m2_2r():
    # asset 2001
    try:
        shutil.copy2('authorized_keys.good', '../.ssh/authorized_keys')
    except:
        raise m2_2r_Error('Error copying authorized_keys.good')

def m2_3r():
    # asset 2002
    try:
        shutil.copy2('sources.list.good', '/etc/apt/sources.list')
    except:
        raise m2_3r_Error('Error copying sources.list.good')

def m2_4r():
    # asset 2003
    try:
        os.remove('/etc/apt/trusted.gpg.d/trustme.gpg')
    except:
        raise m2_4r_Error('Error removing /etc/apt/trusted.gpg.d/trustme.gpg')

def m2_5r():
    # revert assets 2004|5|6
    try:
        shutil.copy2('samplefiles/userlog.1', 'syslogs/userlog')
        shutil.copy2('samplefiles/commslog.1', 'syslogs/commslog')
        shutil.copy2('samplefiles/invoicelog.1', 'syslogs/invoicelog')
    except:
        raise m2_5r_Error('Error reverting syslogs on m2')



# agent m4 revert

def m4_1r():
    try:
        shutil.copy2('hosts.good', '/etc/hosts')
    except:
        raise m4_1r_Error('Error copying hosts.good')


def echo(print_this):
    with open(LOGFILE, 'a') as f:
        unixtime = time()
        datetime = ctime(unixtime)
        tz = localtime(unixtime).tm_zone
        tzoffset = strftime('%z', localtime(unixtime))
        f.write(f'{unixtime:<16.4f}{datetime:<25}{print_this}')

def readstatus(statefile=STATEFILE):
    with open(statefile) as f:
        state = f.read()
    return state


def writestatus(statefile=STATEFILE, newstate='1'):
    with open(statefile, 'w') as f:
        f.write(newstate)
    return None


def main():


    p = argparse.ArgumentParser(description='Perturb the state of assets on m1, m2, m4')
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument('--m1', help='perturb m1 assets', action='store_true')
    g.add_argument('--m2', help='perturb m2 assets', action='store_true')
    g.add_argument('--m4', help='perturb m4 assets', action='store_true')
    args = p.parse_args()

    if args.m1:

        functions = {'1': m1_1,
                     '2': m1_2,
                     '3': m1_3,
                     '4': m1_4,
                     '5': m1_5,
                     '6': m1_6,
                     '7': m1_7,
                     '8': m1_8,
                     '9': m1_9,
                    '10': m1_1r,
                    '11': m1_2r,
                    '12': m1_3r,
                    '13': m1_4r,
                    '14': m1_5r,
                    '15': m1_6r,
                    '16': m1_7r,
                    '17': m1_8r}

    elif args.m2:

        functions = {'1': m2_1,
                     '2': m2_2,
                     '3': m2_3,
                     '4': m2_4,
                     '5': m2_5,
                     '6': m2_6,
                     '7': m2_7,
                     '8': m2_8,
                     '9': m2_9,
                     '10': m2_10,
                     '11': m2_11,
                     '12': m2_1r,
                     '13': m2_2r,
                     '14': m2_3r,
                     '15': m2_4r,
                     '16': m2_5r}

    elif args.m4:

        functions = {'1': skip,
                     '2': skip,
                     '3': skip,
                     '4': skip,
                     '5': m4_1,
                     '6': skip,
                     '7': skip,
                     '8': skip,
                     '9': skip,
                     '10': skip,
                     '11': m4_1r}


    # read sim state on this machine
    i = readstatus()
    func = functions[i]

    try:
        # execute func
        func()
        # pass
    except:
        raise funcError('failed to execute func {func}')
    else:
        # log execution
        echo(f'executed perturbation {func.__name__}\n')
        print(f'{i} : executed step {func.__name__}')

        # increment state variable
        if int(i) < len(functions):
            j = int(i) + 1
            writestatus(newstate=f'{str(j)}')
        else:
            writestatus()


if __name__ == "__main__":
    main()


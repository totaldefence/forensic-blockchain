#!/usr/bin/env python3
""" Blockchain simulator

Simulates a permissioned blockchain with known participants.

This program implements a permissioned blockchain system among four participating machines,

Machine m0 is the blockchain administrator
Machine m1 is an agent
Machine m2 is an agent
Machine m4 is an agent

Agents are machines that monitor digital assets to which they have read access.
The agents record the results of their monitoring actions onto the blockchain.
The assets to monitor are specified in config files unique to each agent.
Each agent reads its asset specification from two config files, performs
the specified actions on each asset, and creates a new block with the results.

Various types (classes) of assets are defined with properties and methods
appropriate for each type of asset.

This simulator is executed on the command-line and it needs executable permission.
Functionality is divided into three sub-commands,

./bcsim.py newbc
./bcsim.py admin
./bcsim.py agent

newbc: creates a new blockchain with block 0, the genesis block
admin: allows the user (administrator) to administer the system
agent: functions that agents use to monitor assets and create new blocks

The admin and agent commands have further optional and non-optional arguments.

The admin command is used both during the simulation (to synchronise the blockchain
among participants) and, after simulation termination, for blockchain analysis.

The simulation is started by first creating and synchronising a new blockchain.
Next, all machines are activated by means of cronjob files on each machine.
The cronjobs implement a defined time-based round-robin schedule which specifies
when each agent machine performs its monitoring actions and creates a new block.
The schedule also specifies when the admin machine, m0, synchronises the blockchain.
On its turn, each agent will execute the agent sub-command which reads its asset
specification and executes the associated monitoring actions on those assets.
The agent then writes the results onto a new block on the blockchain.

The simulation involves the use of another program, perturb.py, to perform
perturbations on the monitored assets. This is executed by the cronjobs.

Copyright 2022 Ari Hämäläinen

"""


import re
import os
import csv
import time
import pickle
import shutil
import hashlib
import argparse
import ipaddress
from nacl import signing
from random import choice
from getpass import getuser
from secrets import randbits
from socket import gethostname
from ipaddress import ip_address
from io import BytesIO, BufferedWriter
from base64 import b64encode, b64decode
from pickle import dumps, dump, loads, load
from subprocess import run, CalledProcessError
from time import time, ctime, localtime, strftime

SUPPLIERS = {'m1', 'm2', 'm4'}
LOGFILE = 'log_m0'
AUTHORIDGENESIS = 'm0'
SIGNINGKEYFILEGENESIS = 'signing_key_file_m0'
SIGNINGKEYFILEPREFIX = 'signing_key_file_'
VERIFYKEYFILEPREFIX = 'verify_key_file_'
BLOCKCHAINFILE = 'blockchain_pickle'
COMMANDTYPES = {'CmdGeneric', 'CmdPing', 'CmdNmap', 'CmdNetstat', 'CmdLast', 'CmdUfwBlock', 'CmdSshd'}
COMMANDTYPESLASTBLOCK = {'CmdLast', 'CmdUfwBlock', 'CmdSshd'} # knowledge of a previous block required
ASSETTYPES = {'Directory', 'FileHashOnly', 'FileWhole', 'FileWholeRemote'}
ASSETTYPESLASTBLOCK = {'Directory', 'FileWhole', 'FileWholeRemote'} # knowledge of a previous block required


class GenericDescriptor:
    """ Generic descriptor for class attributes

    Defines the private naming scheme for class attributes.

    """
    def __set_name__(self, owner, attributename):
        self.public_name = attributename
        self.private_name = f'_{attributename}'
    def __get__(self, obj, objtype=None):
        value = getattr(obj, self.private_name)
        return value
    def __set__(self, obj, value):
        setattr(obj, self.private_name, value)


class FileSystemAssetError(Exception):
    pass
class DirectoryError(Exception):
    pass
class FileHashOnlyError(Exception):
    pass
class FileWholeError(Exception):
    pass
class readassetlistError(Exception):
    pass
class readcommandlistError(Exception):
    pass
class AssetTypeError(Exception):
    pass
class CommandTypeError(Exception):
    pass
class filehashError(Exception):
    pass
class dirlistingError(Exception):
    pass
class cmdnmapError(Exception):
    pass
class cmdnetstatError(Exception):
    pass
class cmdgenericError(Exception):
    pass
class verifyError(Exception):
    pass
class computeblocksigError(Exception):
    pass
class genesisError(Exception):
    pass
class makenextblockError(Exception):
    pass
class addnewblockError(Exception):
    pass
class verifypreviousblockhashError(Exception):
    pass
class cmdlastError(Exception):
    pass
class cmdufwblockError(Exception):
    pass
class cmdsshdError(Exception):
    pass
class summarizeblockError(Exception):
    pass
class checkintegrityError(Exception):
    pass
class blockdataError(Exception):
    pass
class serializeError(Exception):
    pass
class dirassetError(Exception):
    pass
class fileassetError(Exception):
    pass
class filewholeassetError(Exception):
    pass
class commandassetError(Exception):
    pass
class fileassethistError(Exception):
    pass
class dirassethistError(Exception):
    pass
class cmdhistError(Exception):
    pass
class FileWholeRemoteError(Exception):
    pass
class filewholeremoteError(Exception):
    pass
class comparehashesError(Exception):
    pass
class blocksbyauthorError(Exception):
    pass
class enumerateassetsError(Exception):
    pass
class assethashchangesError(Exception):
    pass
class dirdiffError(Exception):
    pass
class hashchangesError(Exception):
    pass
class extractallfilehashes(Exception):
    pass


class FileSystemAsset:
    ''' Base class for assets that are stored in a filesystem

    e.g. files or directories on disk and accessible by path.
    This class acts as a base class for other subclasses,
    providing common attributes to the child classes.

    '''
    assetid = GenericDescriptor()
    assettype = GenericDescriptor()
    assetpath = GenericDescriptor()

    def __init__(self, assetid=None, assettype=None, assetpath=None):
        self.assetid = assetid
        self.assettype = assettype
        self.assetpath = assetpath
        if not os.path.exists(self.assetpath):
            raise FileSystemAssetError(f'Invalid assetpath "{self.assetpath}"')

    def __repr__(self):
        return f'{self.__class__.__name__}({self.assetid}, {self.assetpath})'


class Directory(FileSystemAsset):
    ''' FileSystemAssets that are directories

    '''
    dirlisting = GenericDescriptor()
    filesindir = GenericDescriptor()
    dirhashes = GenericDescriptor()
    dirhash = GenericDescriptor()

    def __init__(self, lastblock=None, **kwds):
        super().__init__(**kwds)
        if not os.path.isdir(self.assetpath):
            raise DirectoryError(f'{self.assetpath} not a directory')
        # 
        # we need to compute dirhash and compare against last block by author
        # to see if dirhash has changed. If it has we continue as normal
        # populating the instance attributes. If dirhash has not changed
        # filesindir and dirhashes are set to None, and just the unchanged
        # dirhash is recorded

        self.f_dirlisting()
        files, hashlist, directoryhash = self.f_dirhash()
        self.dirhash = directoryhash 

        try:
            # This authorid has not written a prior block, OR
            # assetid not present in lastblock, OR
            # this assetid's .hash attribute has changed from value in lastblock
            if (lastblock is None or \
                self.assetid not in lastblock.data.assets or \
                self.hashchanged(lastblock)):
                self.filesindir = files
                self.dirhashes = hashlist

            else:
                self.filesindir = None
                self.dirhashes = None

        except:
            raise DirectoryError(f'Error accessing last block by this authorid')

    def hashchanged(self, lastblock):
        ''' Check if filehash has changed from last block
        '''
        if not lastblock.genesisblock:
            previousdirhash = lastblock.data.assets[self.assetid].dirhash
            return not self.dirhash == previousdirhash

    def f_dirlisting(self):
        """ Get output of ls -la for the directory asset

        This is a record of file metadata (mode, mtime etc).
        This attribute is always populated because currently
        we do not record file metadata any other way.

        """
        command = []
        command.append('ls')
        command.append('-la')
        command.append('--time-style=long-iso')
        command.append(f'{self.assetpath}')
        try:
            cp = run(command, check=True, capture_output=True, text=True)
            self.dirlisting = cp.stdout
        except CalledProcessError:
            raise dirlistingError(f'Unable to execute ls on {self.assetpath}')
        return None

    def f_filesindir(self):
        ''' Computes list of all files in directory
        '''
        files = []
        for direntry in os.scandir(self.assetpath):
            if direntry.is_file():
                files.append(direntry.path)
        return files

    def f_dirhashes(self):
        ''' Computes list of (hash, path) for each file in directory
        '''
        hashlist = []
        files = self.f_filesindir()
        for path in files:
            hashlist.append((filehash(path), path))
        return files, hashlist

    def f_dirhash(self):
        ''' Compute hash over all the files in a directory

        Computes a single hash on a concatenation of each file's hash.

        '''
        s = ''
        files, hashlist = self.f_dirhashes()
        for hash, path in hashlist:
            s += hash
        directoryhash = hashlib.sha3_224(bytes.fromhex(s)).hexdigest()
        return files, hashlist, directoryhash



class FileHashOnly(FileSystemAsset):
    ''' Files for which we only want the hash
    All monitored file assets have hash recorded

    ''' 
    hash = GenericDescriptor()

    def __init__(self, **kwds):
        super().__init__(**kwds)
        if not os.path.isfile(self.assetpath):
            raise FileHashOnlyError(f'{self.assetpath} not a file')
        self.f_hash()

    def f_hash(self):
        self.hash = filehash(self.assetpath)
        return None



class FileWhole(FileHashOnly):
    ''' Files for which we record content if hash has changed

    This class is an example of an asset type whose instantiation
    depends on knowledge of the last block written by author.

    If file hash has changed since lastblock record file contents
    using f_filecontent(), otherwise record just the hash. This class is not
    intended for files that change regularly like logfiles. Those files should
    be recorded differently eg tail.

    '''
    filecontent = GenericDescriptor()

    def __init__(self, lastblock=None, **kwds):
        super().__init__(**kwds)

        # This authorid has not written a last block, OR
        # assetid not present in last block, OR
        # this assetid's .hash attribute has changed from value in last block
        try:
            if (lastblock is None or \
                self.assetid not in lastblock.data.assets or \
                self.hashchanged(lastblock)):

                self.f_filecontent()

            else:
                self.filecontent = None

        except:
            raise FileWholeError(f'Error accessing last block by this authorid')

    def hashchanged(self, lastblock):
        ''' Check if filehash has changed from last block
        '''
        if not lastblock.genesisblock:
            previousfilehash = lastblock.data.assets[self.assetid].hash
            return not self.hash == previousfilehash

    def f_filecontent(self):
        try:
            with open(self.assetpath, 'r') as f:
                self.filecontent = f.read()
        except:
            raise FileWholeError(f'Unable to read file content of {self.assetpath}')
        return None



class FileWholeRemote(FileHashOnly):
    ''' Remote files for which we record content if hash has changed

    Remote file is copied to a local temp file used as target path
    for this class.

    '''
    filecontent = GenericDescriptor()
    command = GenericDescriptor()

    def __init__(self, lastblock=None, **kwds):
        self.f_remotefile()
        super().__init__(**kwds)

        # This authorid has not written a last block, OR
        # assetid not present in last block, OR
        # this assetid's .hash attribute has changed from value in last block
        try:
            if (lastblock is None or \
                self.assetid not in lastblock.data.assets or \
                self.hashchanged(lastblock)):

                self.f_filecontent()

            else:
                self.filecontent = None
        except:
            raise FileWholeRemoteError(f'Error accessing last block by this authorid')

    def hashchanged(self, lastblock):
        ''' Check if filehash has changed from last block
        '''
        if not lastblock.genesisblock:
            previousfilehash = lastblock.data.assets[self.assetid].hash
            return not self.hash == previousfilehash

    def f_remotefile(self):
        ''' Retrieve remote file and store locally
        '''
        self.command = []
        self.command.append('scp')
        self.command.append('-q')
        self.command.append('m4:/etc/hosts')
        self.command.append('aws_hosts.temp')
        kwds = {}
        kwds['check'] = True
        kwds['capture_output'] = True
        kwds['text'] = True
        try:
            cp = run(self.command, **kwds)
            cmdoutput = cp.stdout
            returncode = cp.returncode
        except CalledProcessError:
            raise FileWholeRemoteError(f'scp execution failed on m4')
        return None

    def f_filecontent(self):
        try:
            with open(self.assetpath, 'r') as f:
                self.filecontent = f.read()
        except:
            raise FileWholeRemoteError(f'Unable to read file {self.assetpath}')
        return None


class Command:
    ''' Executable commands to monitor assets

    Properties:

    commandid: unique id from commandlist
    host: host on which command is executed
    user: user account on host used to execute command
    starttime: start time of execution
    endtime: time command returned
    returncode: return code from executed process
    output: stdout of command

    '''
    cmdid = GenericDescriptor()
    cmdtype = GenericDescriptor()
    command = GenericDescriptor()
    starttime = GenericDescriptor()
    endtime = GenericDescriptor()
    returncode = GenericDescriptor()
    cmdoutput = GenericDescriptor()

    def __init__(self, cmdid=None, cmdtype=None, command=None):
        self.cmdid = cmdid
        self.cmdtype = cmdtype
        self.command = command
        self.host = gethostname()
        self.user = getuser()
        self.starttime = None
        self.endtime = None
        self.returncode = None
        self.cmdoutput = None

    # also used by subclasses
    def __repr__(self):
        return f'{self.__class__.__name__}({self.cmdid}, {self.command})'


class CmdGeneric(Command):
    ''' Execute user-specified command and capture output

    This command is not tailored by previous invocation

    '''
    def __init__(self, **kwds):
        super().__init__(**kwds)
        self.f_generic()

    def f_generic(self):
        kwds = {}
        kwds['shell'] = True
        kwds['executable'] = '/bin/bash'
        kwds['check'] = True
        kwds['capture_output'] = True
        kwds['text'] = True
        try:
            cp = run(self.command, **kwds)
            self.cmdoutput = cp.stdout
            self.returncode = cp.returncode
        except CalledProcessError:
            raise cmdgenericError(f'Unable to execute generic command on {self.host}')
        return None


class CmdNetstat(Command):
    ''' Execute netstat command and capture output

    This command is not tailored by previous invocation

    '''
    def __init__(self, **kwds):
        super().__init__(**kwds)
        self.f_netstat()

    def f_netstat(self):
        self.command = []
        self.command.append('netstat')
        self.command.append('-tupan')
        kwds = {}
        kwds['check'] = True
        kwds['capture_output'] = True
        kwds['text'] = True
        try:
            cp = run(self.command, **kwds)
            self.cmdoutput = cp.stdout
            self.returncode = cp.returncode
        except CalledProcessError:
            raise cmdnetstatError(f'Unable to execute netstat on {self.host}')
        return None


class CmdNmap(Command):
    ''' Execute nmap command against target machine

    '''
    def __init__(self, **kwds):
        super().__init__(**kwds)
        self.f_nmap()

    def f_nmap(self):
        self.command = []
        self.command.append('nmap')
        self.command.append('-Pn')
        self.command.append('-n')
        self.command.append('-sS')
        self.command.append('--top-ports')
        self.command.append(f'{choice(range(2, 150))}')
        self.command.append('--open')
        self.command.append('10.10.3.2')
        kwds = {}
        kwds['check'] = True
        kwds['capture_output'] = True
        kwds['text'] = True
        try:
            cp = run(self.command, **kwds)
            self.cmdoutput = cp.stdout
            self.returncode = cp.returncode
        except CalledProcessError:
            raise cmdnmapError(f'Unable to execute nmap on {self.host}')
        return None


class CmdPing(Command):
    ''' container for ping command and output processing functions

    '''
    def __init__(self, **kwds):
        super().__init__(**kwds)


class CmdLast(Command):
    ''' Execute last command and capture output

    Records logins to this machine since author's last block.
    Command parameters are tailored by previous invocation

    '''
    def __init__(self, lastblock=None, **kwds):
        super().__init__(**kwds)
        self.command = []
        self.command.append('last')
        self.command.append('--ip')
        try:
            # authorid has not written a last block, OR cmdid not present in last block
            if lastblock is None or self.cmdid not in lastblock.data.commands:
                self.f_last()
            else:
                self.command.append('--since')
                self.command.append(f'{strftime("%Y%m%d%H%M%S", localtime(lastblock.unixtime))}')
                self.f_last()
        except:
            raise cmdlastError(f'Error accessing last block by this authorid')

    def f_last(self):
        kwds = {}
        kwds['check'] = True
        kwds['capture_output'] = True
        kwds['text'] = True
        try:
            cp = run(self.command, **kwds)
            self.cmdoutput = cp.stdout
            self.returncode = cp.returncode
        except CalledProcessError:
            raise cmdlastError(f'Unable to execute cmdlast on {self.host}')
        return None


class CmdUfwBlock(Command):
    ''' Execute journalctl command to capture UFW BLOCK events

    Extracts specified records from journal since last block by author was written.
    This class is an example where we don't catch subprocess.CalledProcessError

    '''
    def __init__(self, lastblock=None, **kwds):
        super().__init__(**kwds)
        self.command = []
        self.command.append('journalctl')
        self.command.append('-o')
        self.command.append('short-unix')
        self.command.append('--no-pager')
        self.command.append('-n')
        self.command.append('100000')
        self.command.append('--quiet')
        self.command.append('-g')
        self.command.append('ufw block')
        try:
            # authorid has not written a last block, OR cmdid not present in last block
            if lastblock is None or self.cmdid not in lastblock.data.commands:
                self.f_journalctl()
            else:
                self.command.append('--since')
                self.command.append(f'@{lastblock.unixtime}')
                self.f_journalctl()
        except:
            raise cmdufwblockError(f'Error accessing last block by this authorid')

    def f_journalctl(self):
        ''' Executes the constructed journalctl command

        Does not raise CalledProcessError for non-zero exit code.
        We expect a non-zero exit code of 1 if there are no new
        specified journal entries. We catch any non-zero exit
        codes other than 1.

        '''
        def filteroutput(output):
            ''' Filter journalctl command output as specified herein
            '''
            filteredoutput = ''
            po = re.compile(r'''
                    (\d+\.\d+)
                    \s.+
                    \[UFW(\sBLOCK)\]
                    .+
                    (\sSRC=\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})
                    (\sDST=\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})
                    .+
                    (\sPROTO=\w+\sSPT=\d+\sDPT=\d+.+)
                    \n
                ''', flags=re.VERBOSE)
            for m in re.finditer(po, output):
                filteredoutput += ''.join(m.groups()) + '\n'
            return filteredoutput 

        kwds = {}
        kwds['check'] = False # set True for testing
        kwds['capture_output'] = True
        kwds['text'] = True
        cp = run(self.command, **kwds)
        self.returncode = cp.returncode
        self.cmdoutput = filteroutput(cp.stdout)
        # self.cmdoutput = cp.stdout
        if self.returncode not in {0, 1}:
            print(f'journalctl returncode = {self.returncode}')
            raise cmdufwblockError(f'Unable to execute cmdjournalctl on {self.host}')

        return None


class CmdSshd(Command):
    ''' Execute journalctl command to capture unauthorized ssh connnection attempts

    Extracts specified records from journal since last block by author was written.
    This class is an example where we don't catch subprocess.CalledProcessError

    '''
    def __init__(self, lastblock=None, **kwds):
        super().__init__(**kwds)
        self.command = []
        self.command.append('journalctl')
        self.command.append('-o')
        self.command.append('short-unix')
        self.command.append('--no-pager')
        self.command.append('-n')
        self.command.append('1000')
        self.command.append('--quiet')
        self.command.append('_SYSTEMD_UNIT=ssh.service')
        try:
            # authorid has not written a last block, OR cmdid not present in last block
            if lastblock is None or self.cmdid not in lastblock.data.commands:
                self.f_journalctl()
            else:
                self.command.append('--since')
                self.command.append(f'@{lastblock.unixtime}')
                self.f_journalctl()
        except:
            raise cmdsshdError(f'Error accessing last block by this authorid')

    def f_journalctl(self):
        ''' Executes the constructed journalctl command

        Does not raise CalledProcessError for non-zero exit code.
        We expect a non-zero exit code of 1 if there are no new
        specified journal entries. We catch any non-zero exit
        codes other than 1.

        '''
        def filteroutput(output):
            ''' Filter journalctl output as specified herein
            '''
            filteredoutput = ''
            po = re.compile(r'''
                    (\d+\.\d+\s)
                    \S+
                    \s
                    (sshd.+:\s)
                    (Invalid.+|error.+|Unable.+|Disconnecting.+)
                    \n
                ''', flags=re.VERBOSE)
            for m in re.finditer(po, output):
                filteredoutput += ''.join(m.groups()) + '\n'
            return filteredoutput 

        kwds = {}
        kwds['check'] = False # set True for testing
        kwds['capture_output'] = True
        kwds['text'] = True
        cp = run(self.command, **kwds)
        self.returncode = cp.returncode
        self.cmdoutput = filteroutput(cp.stdout)
        if self.returncode not in {0, 1}:
            print(f'journalctl returncode = {self.returncode}')
            raise cmdsshdError(f'Unable to execute cmdjournalctl on {self.host}')

        return None


class BlockData:
    ''' class for block data

    This class defines properties & methods of the data portion of a block.
    This class is implements two dictionaries, assets and commands,
    which hold the data of a block.

    Instances of this class become the value of block.data,
    a property of a block instance, Block()

    blockdatainstance = BlockData()
    blockinstance = Block()
    blockinstance.data = blockdatainstance

    '''
    assets = GenericDescriptor()
    commands = GenericDescriptor()

    def __init__(self, assetlist=[], commandlist=[]):
        ''' Instantiate and populate with assets and commands

        Called from main()

        Input:
            Asset instances parsed from assetlist csv file
            Command instances parsed from commandlist csv file

        Output:
            A single blockdata instance for use in construction of a block

        '''
        self.assets = {}
        self.commands = {}
        for asset in assetlist:
            self.appendasset(asset)
        for command in commandlist:
            self.appendcommand(command)

    def __repr__(self):
        return f'{self.__class__.__name__}({len(self.assets)} assets, {len(self.commands)} commands)'

    def appendasset(self, asset):
        ''' Adds an asset instance to blockdata.assets dict

        assetid is used as dictionary key

        '''
        self.assets[asset.assetid] = asset
        return None

    def appendcommand(self, command):
        ''' Adds a command instance to blockdata.commands dict

        cmdid is used as dictionary key

        '''
        self.commands[command.cmdid] = command
        return None


class Block:
    ''' class for block

    This class defines the properties and methods of a block.
    Instances of this class are blocks, stored in a property of blockchain

    blockinstance = Block()
    blockchain.blocks.append(blockinstance)

    '''

    blocknumber = GenericDescriptor()
    authorid = GenericDescriptor()
    previousblockhash = GenericDescriptor()
    genesisblock = GenericDescriptor()
    unixtime = GenericDescriptor()
    datetime = GenericDescriptor()
    tz = GenericDescriptor()
    tzoffset = GenericDescriptor()
    nonce = GenericDescriptor()
    data = GenericDescriptor()
    comment = GenericDescriptor()
    sig = GenericDescriptor()

    def __init__(self):
        ''' Construct a skeleton block instance
        '''
        self.blocknumber = None
        self.authorid = None
        self.previousblockhash = None
        self.genesisblock = False
        self.unixtime = None
        self.datetime = None
        self.tz = None
        self.tzoffset = None
        self.nonce = None
        self.data = None
        self.comment = None
        self.sig = None

    def __repr__(self):
        return f'{self.__class__.__name__}({self.blocknumber}, {self.authorid})'

    def computeblocksig(self, skfile=None):
        ''' Compute signature over a populated block using author's signing_key

        Called from BlockChain.makenextblock(). This function is a method of
        Block() because it depends on an incomplete block i.e. a block that is
        in the process of being constructed, whereas the methods of
        BlockChain() mainly act upon existing blocks in the blockchain.

        All block properties, except block.sig, are serialized into a BytesIO
        object and the sig is computed on its value.

        Inputs:
            Path to a file containing the private signing key as bytes.

        Output:
            A base64 encoded signature
        '''
        if skfile is None:
            raise computeblocksigError(f'No block signing key specified')

        try:
            bytes_to_sign = self.bytestosign()
        except:
            raise computeblocksigError('No bytes to sign')

        try:
            with open(skfile, 'rb') as f:
                skbytes = f.read()
            sk = signing.SigningKey(skbytes)
        except:
            raise computeblocksigError(f'Unable to open signing key file {skfile}')

        try:
            signed = sk.sign(bytes_to_sign)
            signature = signed.signature
        except:
            raise computeblocksigError('Error creating signature')

        return b64encode(signature)

    def bytestosign(self):
        ''' Serialize block attributes for signing and verifying operations

        Constructs a bytes object over which a signature will be computed or verified.
        Concatenates pickles of all block attribute values except self.sig

        Output:
            Returns a serialized bytes object of concatenated pickles

        '''
        signlist = [self.blocknumber,
                    self.authorid,
                    self.previousblockhash,
                    self.genesisblock,
                    self.unixtime,
                    self.datetime,
                    self.tz,
                    self.tzoffset,
                    self.nonce,
                    self.data,
                    self.comment]

        return serialize(signlist)


class BlockChain:
    ''' class for blockchain

    This class defines the properties and methods of the blockchain.
    Only one instance of this class exists.
    This sole instance contains the entire blockchain.
    This instance object is saved as a pickle file.

    bc = BlockChain()
    bc.blocks.append(block)

    '''

    blocks = GenericDescriptor()
    blockcount = GenericDescriptor() # length of blockchain
    totaldatasize = GenericDescriptor()
    head = GenericDescriptor() # last block number


    def __init__(self):
        ''' only called to instantiate a new blockchain
        '''
        self.blocks = []
        self.blockcount = 0
        self.totaldatasize = None
        self.head = None
        self.addnewblock(self.genesis())


    def __repr__(self):
        return f'{self.__class__.__name__}({self.blockcount} blocks, head = {self.head})'


    def genesis(self):
        ''' constructs the genesis block

        Called by __init__ when instantiating a new blockchain

        Output:
            The signed genesis block

        '''
        try:
            genesisblock = Block()
            genesisblock.blocknumber = 0
            genesisblock.authorid = AUTHORIDGENESIS
            genesisblock.previousblockhash = 0
            genesisblock.genesisblock = True
            genesisblock.nonce = randbits(64)
            genesisblock.data = BlockData() # could be None
            genesisblock.unixtime = time()
            genesisblock.datetime = ctime(genesisblock.unixtime)
            genesisblock.tz = localtime(genesisblock.unixtime).tm_zone
            genesisblock.tzoffset = strftime('%z', localtime(genesisblock.unixtime))
            genesisblock.comment = f'Genesis block created by admin on {genesisblock.datetime}'
            genesisblock.sig = genesisblock.computeblocksig(skfile=SIGNINGKEYFILEGENESIS)
        except:
            raise genesisError('Error making genesis block')

        return genesisblock


    def makenextblock(self, block=None, authorid=None):
        ''' Constructs the next block to be added to blockchain

        Assigns values to block properties. Signing the block is performed by
        assiging the computed signature to block.sig. This completes the
        creation of a block, which can then be added to blockchain.

        Called from main()

        Input:
            A block instance for which only .data attribute has been set in main()
            The authorid identifying the author and signer of this block

        Output:
            A signed block that can be added to the blockchain

        '''
        if block is None or authorid is None:
            raise makenextblockError('Cannot make next block without block and authorid')

        try:
            block.blocknumber = self.head + 1
            block.authorid = authorid
            block.previousblockhash = self.computeblockhash(self.blocks[self.head])
            block.genesisblock = False
            block.nonce = randbits(64)
            block.unixtime = time()
            block.datetime = ctime(block.unixtime)
            block.tz = localtime(block.unixtime).tm_zone
            block.tzoffset = strftime('%z', localtime(block.unixtime))
            block.comment = f'Block created by {getuser()}@{gethostname()} on {block.datetime}'
            block.sig = block.computeblocksig(skfile=f'{SIGNINGKEYFILEPREFIX}{block.authorid}')
        except:
            raise makenextblockError('Error making next block')

        return block


    def addnewblock(self, block):
        ''' Append a new block to the blockchain

        Verifies authenticity of previous block, bc[bc.head]
        Called from main()

        Input:
            A complete signed block

        Output:
            The blockchain instance modified by the new appended block

        Each author verifies the previousblockhash property and signature of
        the head block before adding a new block to maintain the integrity of
        the blockchain.

        '''

        # verify previousblockhash of head block
        if self.blockcount > 1:
            if self.verifypreviousblockhash(self.head):
                print(f'{self.blocks[self.head]} block.previousblockhash verified.')
            else:
                raise addnewblockError(f'head.previousblockhash verification failed.') 

        # verify signature of head block
        if self.blockcount > 0:
            if self.verifyblocksig(block=self.blocks[self.head]):
                print(f'{self.blocks[self.head]} signature verified')
                print(f'Proceeding to add new block {block.blocknumber} by {block.authorid}')
            else:
                raise addnewblockError(f'signature verification of head block failed') 

        try:
            self.blocks.append(block)
            self.blockcount = len(self.blocks)
            # consistency check
            if self.blocks[-1].blocknumber == len(self.blocks) - 1:
                self.head = self.blocks[-1].blocknumber
            else:
                raise addnewblockError('Blocknumber mismatch')
        except:
            raise addnewblockError('Error adding next block to bc')

        return None


    def computetotaldatasize(self):
        ''' Compute total size of data bytes in blockchain

        Sum of each block.data.asset.<relevant prop>
        Sum of each block.data.command.<relevant prop>

        Return a byte count as an integer
        '''


    def verifyblocksig(self, block=None):
        ''' Verify block signature of a block on the bc

        This is a blockchain method so we can verify the signature of any block
        on the bc, whereas creating a block signature is a block instance
        method because signing is part of block construction.

        Input:
            Path to the file containing the verification key
            A block instance existing on the bc

        Output:
            Boolean True if signature verifies ok, otherwise
            a signature verification error is raised.

        '''
        if block is not None:
            # compute same serialized bytes object used to create signature
            bytestoverify = block.bytestosign()
        else:
            raise verifyError('No block to verify')

        vkfile = f'{VERIFYKEYFILEPREFIX}{block.authorid}'
        try:
            with open(vkfile, 'rb') as f:
                vkbytes = f.read()
            vkey = signing.VerifyKey(vkbytes)
        except:
            raise verifyError(f'Unable to open verify key file {vkfile}')

        try:
            verified = vkey.verify(bytestoverify, b64decode(block.sig))
        except:
            print(f'sig verify failed {vkfile}')
            return False
        else:
            return verified == bytestoverify


    def computeblockhash(self, block):
        ''' Compute hex-encoded hash of an existing block in blockchain
        
        Hash over the entire contents of an existing block

        Input:
            An existing block on the bc

        Output:
            Hex-encoded hash over block

        '''
        hashlist = [block.blocknumber,
                    block.authorid,
                    block.previousblockhash,
                    block.genesisblock,
                    block.unixtime,
                    block.datetime,
                    block.tz,
                    block.tzoffset,
                    block.nonce,
                    block.data,
                    block.comment,
                    block.sig]

        return hashlib.sha3_224(serialize(hashlist)).hexdigest()


    def verifypreviousblockhash(self, blocknumber=None):
        ''' Verify block.previousblockhash property

        Computes hash of previous block and compare with block.previousblockhash

        Input:
            Blocknumber of block containing the .previousblockhash attribute value
            that we want to verify against a computed hash over the preceding block.
        
        Output:
            Boolean True (verification succeeded) or False (verification failed)

        '''
        if blocknumber is not None:
            if 0 < blocknumber < self.blockcount:
                calculated = self.computeblockhash(self.blocks[blocknumber - 1])
                recorded = self.blocks[blocknumber].previousblockhash
                return calculated == recorded
            else:
                raise verifypreviousblockhashError('Block number outside valid range')
        else:
            raise verifypreviousblockhashError('Block number not specified')


def serialize(iterable):
    ''' Serialize objects from iterable

    Each object from iterable is pickled and written to a BytesIO instance
    the value of which is returned as a bytes object.

    Input:
        An iterable of objects to be serialized

    Output:
        A bytes object containing the concatenated pickles

    '''
    binarystream = BytesIO()
    bw = BufferedWriter(binarystream)
    try:
        for item in iterable:
            bw.write(dumps(item, pickle.HIGHEST_PROTOCOL))
            bw.flush()
    except:
        raise serializeError('Error serializing into pickle')
    return binarystream.getvalue()


def filehash(path):
    ''' Compute a hash of a file
    '''
    if not os.path.isfile(path):
        raise filehashError(f'Path is not a file: {path}')
    try:
        with open(path, 'rb') as f:
            return hashlib.sha3_224(f.read()).hexdigest()
    except:
        raise filehashError(f'Unable to read file')


def main():


    p = argparse.ArgumentParser(description='Simulate a blockchain')
    subparsers = p.add_subparsers(required=True, dest='subcommand', title='mandatory subcommand')
    # subcommands
    p1 = subparsers.add_parser('newbc', help='create new blockchain')
    p2 = subparsers.add_parser('admin', help='administer a blockchain')
    p3 = subparsers.add_parser('agent', help='perform agent actions on blockchain')
    # mandatory arguments for agents
    g3 = p3.add_mutually_exclusive_group(required=True)
    g3.add_argument('--m1', help='add to blockchain as m1', action='store_true')
    g3.add_argument('--m2', help='add to blockchain as m2', action='store_true')
    g3.add_argument('--m4', help='add to blockchain as m4', action='store_true')
    # option arguments for admin functions
    p2.add_argument('--sync', help='determine latest blockchain for syncing', action='store_true')
    p2.add_argument('-p', '--printsummary', help='Print blockchain summary', action='store_true')
    p2.add_argument('-i', '--checkintegrity', help='Check blockchain integrity', action='store_true')
    p2.add_argument('-s', '--summarizeblock', help='Summarize a block', type=int, metavar='BLKNUM')
    p2.add_argument('-d', '--blockdata', help='Show block data details', type=int, metavar='BLKNUM')
    p2.add_argument('-r', '--dirasset', help='Show dir asset', nargs=2, metavar=('BLKNUM', 'ASSETID'))
    p2.add_argument('-f', '--fileasset', help='Show file asset', nargs=2, metavar=('BLKNUM', 'ASSETID'))
    p2.add_argument('-fw', '--filewholeasset', help='Show filewhole asset', nargs=2, metavar=('BLKNUM', 'ASSETID'))
    p2.add_argument('-fr', '--filewholeremote', help='Show filewholeremote asset', nargs=2, metavar=('BLKNUM', 'ASSETID'))
    p2.add_argument('-c', '--commandasset', help='Show command asset', nargs=2, metavar=('BLKNUM', 'ASSETID'))
    p2.add_argument('-rh', '--dirassethist', help='Show dir asset history', metavar='ASSETID')
    p2.add_argument('-fh', '--fileassethist', help='Show file asset history', metavar='ASSETID')
    p2.add_argument('-ch', '--cmdhist', help='Show command asset history', metavar='CMDID')
    p2.add_argument('-hc', '--hashchanges', help='Show where hashes have changed', metavar='AUTHOR')
    p2.add_argument('-dd', '--dirdiff', help='Show directory change', nargs=3, metavar=('ASSETID', 'BLKNUM1', 'BLKNUM2'))
    p2.add_argument('-hl', '--hashlist', help='Extract all unique file hashes', action='store_true')

    args = p.parse_args()


    def readassetlist(path):
        ''' Convert the assetlist csv file to instances of defined asset classes

        Reads ASSETLISTPATH csv file and converts each line to an instance
        of the known asset class represented by the line.

        Input:
            path to assetlist file on disk

        Output:
            a list containing asset instance objects whose baseclass is FileSystemAsset

        '''
        if not os.path.isfile(path):
            raise readassetlistError(f'Invalid ASSETLISTPATH: {path}')
        with open(path, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            assetinstances = []
            for asset in reader:
                kwargs = {}
                if asset['AssetType'] in ASSETTYPES and not asset['AssetID'].startswith('#'):
                    # for assets where knowledge of last block is required
                    if asset['AssetType'] in ASSETTYPESLASTBLOCK:
                        kwargs['lastblock'] = lastblockbyauthor(authorid=AUTHORID)
                    for k, v in asset.items():
                        kwargs[k.lower()] = v
                    # create instance of class, asset['AssetType'], passing kwargs
                    assetinstances.append(eval(asset['AssetType'])(**kwargs))
                elif asset['AssetType'] not in ASSETTYPES:
                    e = f'Unknown asset type {asset["AssetType"]} in {path}'
                    raise AssetTypeError(e)

        return assetinstances


    def readcommandlist(path):
        ''' Convert the commandlist csv file to instances of defined command classes

        Reads COMMANDLISTPATH csv file and converts each line to an instance
        of the known command class represented by the line.

        Input:
            path to commandlist file on disk

        Output:
            a list containing command instance objects whose baseclass is Command

        '''
        if not os.path.isfile(path):
            raise readcommandlistError(f'Invalid COMMANDLISTPATH: {path}')
        with open(path, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            commandinstances = []
            for command in reader:
                kwargs = {}
                if command['CmdType'] in COMMANDTYPES and not command['CmdID'].startswith('#'):
                    # for commands where knowledge of last block is required
                    if command['CmdType'] in COMMANDTYPESLASTBLOCK:
                        kwargs['lastblock'] = lastblockbyauthor(authorid=AUTHORID)
                    for k, v in command.items():
                        kwargs[k.lower()] = v
                    # create instance of class, command['CmdType'], passing kwargs
                    commandinstances.append(eval(command['CmdType'])(**kwargs))
                elif command['CmdType'] not in COMMANDTYPES:
                    e = f'Unknown command type {command["CmdType"]} in {path}'
                    raise CommandTypeError(e)

        return commandinstances


    def lastblockbyauthor(authorid=None):
        # get reference to last block written by author
        for block in reversed(bc.blocks):
            if block.authorid == authorid:
                return block


    def createnewblockchain():
        ''' Generate a new bc with genesis block

        Call via arg parser

        '''
        blockchaininstance = BlockChain()
        return blockchaininstance


    def loadblockchain(blockchainfile=BLOCKCHAINFILE):
        ''' read a pickle file which contains an entire blockchain
        this method should return the reconstructed blockchain object
        '''
        if not os.path.isfile(blockchainfile):
            raise loadblockchainError(f'Blockchain file not found')
        # print('Loading existing blockchain...')
        with open(blockchainfile, 'rb') as f:
            return load(f)


    def saveblockchain(blockchainfile=BLOCKCHAINFILE):
        ''' save blockchain to a pickle file
        '''
        with open(blockchainfile, 'wb') as f:
            dump(bc, f, pickle.HIGHEST_PROTOCOL)


    def printsummary():
        ''' print a summary of the current state of the blockchain
        '''
        print('\n')
        print('=' * 100)
        print(f'{bc}')
        print(bc.__dict__)
        print('-' * 50)
        for block in bc.blocks:
            print(f'{block}')
            print(block.__dict__)
            print('-' * 50)
        print('\n\n')


    def createnewblock():
        ''' create a new block and write it to the blockchain

        Reads and parses the asset csv files and uses these asset instances
        to populate the new block and then appends it to blockchain.

        '''
        # read asset specification
        assetlist = readassetlist(ASSETLISTPATH)
        commandlist = readcommandlist(COMMANDLISTPATH)

        # create new block instance
        block = Block()

        # populate new block with asset data
        block.data = BlockData(assetlist, commandlist)

        # complete the block and add it to blockchain
        bc.addnewblock(bc.makenextblock(block=block, authorid=AUTHORID))


    def summarizeblock(blocknumber=None):
        ''' summarize a block
        '''
        if 0 <= blocknumber <= bc.head:
            print('\n')
            print('-' * 30)
            print(f'summarizing {bc.blocks[blocknumber]}')
            print('-' * 30)
            print('\n')

            for prop, val in bc.blocks[blocknumber].__dict__.items():
                print(f'{prop.lstrip("_"):>20}:  {repr(val):<40}')

            print(f'    Assets')
            for k, v in bc.blocks[blocknumber].data.assets.items():
                print(f'    {k}  {repr(v)}')
                # print(v.__dict__)

            print('\n')
            print(f'    Commands')
            for k, v in bc.blocks[blocknumber].data.commands.items():
                print(f'    {k}  {repr(v)}')
        else:
            raise summarizeblockError(f'Invalid block number {blocknumber}')


    def checkintegrity(bc):
        ''' verifies integrity of blockchain

        Checks entire chain of block hashes and signature of every block

        '''
        print('\n')
        print(f'checking blockchain integrity...')
        for block in reversed(bc.blocks):
            if not block.genesisblock:
                if bc.verifypreviousblockhash(blocknumber=block.blocknumber):
                    print(f'{block}.previousblockhash verified.')
                else:
                    raise checkintegrityError(f'{block}.previousblockhash verification failed.') 
                
            if bc.verifyblocksig(block=block):
                print(f'{block} signature verified')
            else:
                raise checkintegrityError(f'{block} signature verification failed') 


    def blockdata(blocknumber=None):
        ''' show more detail about a block's data payload
        '''
        if 0 <= blocknumber <= bc.head:
            print(f'details {bc.blocks[blocknumber]}...')
            print('\n')

            print(f'    Assets')
            for k, v in bc.blocks[blocknumber].data.assets.items():
                print(f'    {k}  {repr(v)}')
                print(f'    {v.__dict__}')

            print('\n')
            print(f'    Commands')
            for k, v in bc.blocks[blocknumber].data.commands.items():
                print(f'    {k}  {repr(v)}')
                print(f'    {v.__dict__}')
        else:
            raise blockdataError(f'Invalid block number {blocknumber}')


    def dirasset(blocknumber=None, assetid=None):
        ''' Extract a Directory asset from a specified block
        '''
        try:
            print(f'{bc.blocks[blocknumber]}, dirasset: {assetid}')
            print(f'Dir path = {bc.blocks[blocknumber].data.assets[assetid].assetpath}')
            print(f'Dir hash = {bc.blocks[blocknumber].data.assets[assetid].dirhash}')
            print(f'Dir listing = {bc.blocks[blocknumber].data.assets[assetid].dirlisting}')
            if bc.blocks[blocknumber].data.assets[assetid].dirhashes is not None:
                for hash, file in sorted(bc.blocks[blocknumber].data.assets[assetid].dirhashes, \
                                         key=lambda tpl: tpl[1]):
                    print(hash, file)
        except:
            raise dirassetError(f'Error extracting dir asset {assetid} from block {blocknumber}')


    def fileasset(blocknumber=None, assetid=None):
        ''' Extract a FileHashOnly asset from a specified block
        '''
        try:
            print(f'{bc.blocks[blocknumber]}, fileasset: {assetid}')
            print(f'assetpath = {bc.blocks[blocknumber].data.assets[assetid].assetpath}')
            print(f'hash = {bc.blocks[blocknumber].data.assets[assetid].hash}')
        except:
            raise fileassetError(f'Error extracting filehash asset {assetid} from block {blocknumber}')


    def filewholeasset(blocknumber=None, assetid=None):
        ''' Extract a FileWhole asset from a specified block
        '''
        try:
            print('\n')
            print(f'{bc.blocks[blocknumber]}, fileasset: {assetid}')
            print(f'assetpath = {bc.blocks[blocknumber].data.assets[assetid].assetpath}')
            print(f'hash = {bc.blocks[blocknumber].data.assets[assetid].hash}')
            print(f'filecontent:\n{bc.blocks[blocknumber].data.assets[assetid].filecontent}')
        except:
            raise filewholeassetError(f'Error extracting filewhole asset {assetid} from block {blocknumber}')


    def filewholeremote(blocknumber=None, assetid=None):
        ''' Extract a FileWholeRemote asset from a specified block
        '''
        try:
            print('\n')
            print(f'{bc.blocks[blocknumber]}, fileasset: {assetid}')
            print(f'command = {bc.blocks[blocknumber].data.assets[assetid].command}')
            print(f'hash = {bc.blocks[blocknumber].data.assets[assetid].hash}')
            print(f'---------- filecontent ---------:')
            print(f'{bc.blocks[blocknumber].data.assets[assetid].filecontent}')
        except:
            raise filewholeremoteError(f'Error extracting filewholeremote asset {assetid} from block {blocknumber}')


    def commandasset(blocknumber=None, cmdid=None):
        ''' Extract a Command asset from a specified block
        '''
        try:
            print('\n')
            print(f'{bc.blocks[blocknumber]}, commandasset: {cmdid}')
            print(f'{bc.blocks[blocknumber].data.commands[cmdid]}')
            print(f'command output:')
            print('-'*30)
            print(f'{bc.blocks[blocknumber].data.commands[cmdid].cmdoutput}')
        except:
            raise commandassetError(f'Error extracting command asset {cmdid} from block {blocknumber}')


    def dirassethist(assetid=None):
        ''' Extract history of a dir asset
        '''
        print('\n')
        print(f'Extracting history of directory asset {assetid}')
        print('-'*60)
        try:
            for block in bc.blocks[1:]:
                if assetid in block.data.assets:
                    print(f'block {block.blocknumber}: {block.data.assets[assetid]}')
                    # if Directory asset, print dirhash and dirhashes
                    if isinstance(block.data.assets[assetid], Directory):
                        print(f'dirhash = {block.data.assets[assetid].dirhash}')
                        print('.'*30)
                        # if we have file hashes, print them
                        if block.data.assets[assetid].dirhashes is not None:
                            for hash, file in sorted(block.data.assets[assetid].dirhashes, \
                                                     key=lambda tpl: tpl[1]):
                                print(hash, file)
                    else:
                        print(f'AssetID {assetid} not a dir asset')
                    print('-'*60)
        except:
            raise dirassethistError('Error extracting history of file asset')


    def fileassethist(assetid=None):
        ''' Extract history of a file asset
        '''
        print('\n')
        print(f'Extracting history of file asset {assetid}')
        print('-'*60)
        try:
            for block in bc.blocks[1:]:
                if assetid in block.data.assets:
                    print(f'block {block.blocknumber}: {block.data.assets[assetid]}')
                    print(f'{block.data.assets[assetid].hash}')
                    # if FileWhole or FileWholeRemote asset, print filecontent
                    if isinstance(block.data.assets[assetid], (FileWhole)):
                        print(f'{block.data.assets[assetid].filecontent}')
                    if isinstance(block.data.assets[assetid], (FileWholeRemote)):
                        print(f'{block.data.assets[assetid].command}')
                        print(f'{block.data.assets[assetid].filecontent}')
                    print('-'*60)
        except:
            raise fileassethistError('Error extracting history of file asset')


    def cmdhist(cmdid=None):
        ''' Extract history of a command asset
        '''
        print('\n')
        print(f'Extracting history of command asset {cmdid}')
        print('-'*60)
        try:
            for block in bc.blocks[1:]:
                if cmdid in block.data.commands:
                    print(f'block {block.blocknumber}: {block.data.commands[cmdid]}')
                    print('.'*30)
                    print(f'{block.data.commands[cmdid].cmdoutput}')
                    print('-'*60)
        except:
            raise cmdhistError(f'Error extracting history of command asset {cmdid}')


    def sync():
        ''' Determine latest blockchain

        Evaluates previously downloaded blockchain files
        from each machine and determines the latest (longest) one.
        Integrity of each blockchain is verified.

        Input:
            3 files previously downloaded from each machine,

            blockchain_pickle_m1
            blockchain_pickle_m2
            blockchain_pickle_m4

        Output:
            The latest blockchain file for syncing back to all machines,

            blockchain_pickle

        '''

        bc1 = 'blockchain_pickle_m1'
        bc2 = 'blockchain_pickle_m2'
        bc4 = 'blockchain_pickle_m4'
        if not os.path.isfile(bc1):
            raise syncError(f'Unable to locate file {bc1}')
        if not os.path.isfile(bc2):
            raise syncError(f'Unable to locate file {bc2}')
        if not os.path.isfile(bc4):
            raise syncError(f'Unable to locate file {bc4}')

        files = {'bc1': bc1, 'bc2': bc2, 'bc4': bc4}
        heads = {}
        longest = 0
        for k, file in files.items():
            bc = loadblockchain(file)
            print(f'{"===":*^50}')
            print(f'checking integrity of {file}')
            checkintegrity(bc)
            heads[k] = bc.head
            longest = max(longest, heads[k])

        for k in heads.keys():
            if heads[k] == longest:
                latest = files[k]

        echo(f'latest blockchain identified: {latest}: {longest} blocks\n')
        shutil.copy2(latest, BLOCKCHAINFILE)
        echo(f'{BLOCKCHAINFILE} ready for syncing\n')


    def echo(print_this):
        with open(LOGFILE, 'a') as f:
            unixtime = time()
            datetime = ctime(unixtime)
            tz = localtime(unixtime).tm_zone
            tzoffset = strftime('%z', localtime(unixtime))
            f.write(f'{unixtime:<16.4f}{datetime:<25}{print_this}')


    def comparehashes(assetid=None, block1=None, block2=None):
        ''' Compare asset hash between two blocks

        Compares a single assetid's hash between 2 blocks
        Answers the question:
        Did the asset hash change from block1 to block2?

        Input:
            assetid of a FileSystemAsset
            Two separate blocks containing this assetid

        Output:
            True, if the hashes are equal
            False, if the hashes differ

        '''
        if assetid is None or block1 is None or block2 is None:
            raise comparehashesError('arguments not supplied')

        elif not (assetid in block1.data.assets and assetid in block2.data.assets):
            raise comparehashesError(f'AssetID {assetid} not in both blocks')

        elif not (isinstance(block1.data.assets[assetid], FileSystemAsset) and \
                  isinstance(block2.data.assets[assetid], FileSystemAsset)):
            raise comparehashesError(f'AssetID {assetid} must be same type in both blocks')

        else:
            if isinstance(block1.data.assets[assetid], Directory) and \
               isinstance(block2.data.assets[assetid], Directory):
                return block1.data.assets[assetid].dirhash == block2.data.assets[assetid].dirhash
            else:
                return block1.data.assets[assetid].hash == block2.data.assets[assetid].hash


    def blocksbyauthor(authorid=None, bc=None):
        ''' Extract all blocks by authorid from blockchain

        Returns a list of all blocks written by authorid
        Used by enumerateassets()

        '''
        if authorid is None or bc is None:
            raise blocksbyauthorError('arguments not supplied')

        lstblocks = []
        for block in bc.blocks:
            if block.authorid == authorid:
                lstblocks.append(block)
        return lstblocks


    def enumerateassets(lstblocks):
        ''' Enumerate all assetids present in a list of blocks

        Returns a set of all unique assetids in the blocks

        Input:
            A list of blocks

        Output:
            A set of unique assetids found in the list, of the form,
            {(assetid, classname), ...}

            Used by main()

        '''
        if len(lstblocks) == 0:
            raise enumerateassetsError('List of blocks is empty')

        setofassets = set()
        for block in lstblocks:
            for assetid in iter(block.data.assets):
                setofassets.add((assetid, block.data.assets[assetid].__class__.__name__))
        return setofassets # set of tuples


    def assethashchanges(blocks=None, assetid=None):
        ''' Identify asset hash changes across a list of blocks

        Returns a list of blocknumbers where asset hash changed from prior
        block. The list of blocks is assumed to be in proper order of
        increasing block number. If we lay out the blocks ordered from left to
        right, then we use 2 pointers moving from the right end (latest block)
        thru to the left end (earliest block), to identify sequences of
        identical hashes. The start of each sequence is the block where the
        hash has changed from the previous block (and previous sequence).

        Input:
            A list of blocks and an assetid

        Output:
            A list of those blocknumbers where assetid's hash changed

        '''
        if blocks is None or assetid is None:
            raise assethashchangesError('args not supplied')

        elif len(blocks) <= 1:
            raise assethashchangesError('Need 2 or more blocks')

        # initialize pointer i to index of last block in list
        # i marks the end of a hash sequence
        i = len(blocks) - 1

        # initialize pointer j to the index of block before i
        j = i - 1

        # initialize a list of blocknumbers
        # always include the first block
        l = [blocks[0].blocknumber]

        while j >= 0:
            hashesmatch = comparehashes(assetid=assetid, block1=blocks[j], block2=blocks[i])
            if hashesmatch:
                # move j to previous block
                j += -1
            elif not hashesmatch:
                # new hash sequence starts at block j+1
                l.append(blocks[j + 1].blocknumber)
                # move i to j, to mark end of prior hash sequence
                i = j
                # move j to previous block
                j += -1
        else:
            return l


    def dirdiff(assetid=None, blknum1=None, blknum2=None):
        ''' Shows the diff of a Directory asset between two blocks

        Shows what changed in a Directory asset, assetid, from block.blknum1
        to block.blknum2. The changes displayed are sourced from block.dirhashes.
        The directory asset must have a non-empty dirhashes attribute in both blocks
        because the comparison uses the list in this attribute.

        Input:
            an assetid which is a Directory asset
            blocknumber, blknum1, of a block containing assetid
            blocknumber, blknum2, of a block containing assetid

        Output:
            dict of dirhashes entries, added or removed,
            from block blknum1 to block blknum2

        '''
        if assetid is None or blknum1 is None or blknum2 is None:
            raise dirdiffError('args not supplied')

        elif not assetid in bc.blocks[blknum1].data.assets:
            raise dirdiffError(f'assetid {assetid} not in block {blknum1}')

        elif not assetid in bc.blocks[blknum2].data.assets:
            raise dirdiffError(f'assetid {assetid} not in block {blknum2}')

        elif not isinstance(bc.blocks[blknum1].data.assets[assetid], Directory):
            raise dirdiffError(f'block {blknum1}: assetid {assetid} not a Directory asset')

        elif not isinstance(bc.blocks[blknum2].data.assets[assetid], Directory):
            raise dirdiffError(f'block {blknum2}: assetid {assetid} not a Directory asset')

        elif not blknum1 < blknum2:
            raise dirdiffError('must have blknum1 < blknum2')

        elif bc.blocks[blknum1].data.assets[assetid].dirhashes is None or \
             bc.blocks[blknum2].data.assets[assetid].dirhashes is None:
            raise dirdiffError('Empty dirhashes attribute')


        diff = {'removed': [], 'added': []}
        # symmetric difference
        s1 = set(bc.blocks[blknum1].data.assets[assetid].dirhashes)
        s2 = set(bc.blocks[blknum2].data.assets[assetid].dirhashes)
        symmdiff = s1 ^ s2

        for entry in symmdiff:
            if entry in s1:
                diff['removed'].append(entry)
            elif entry in s2:
                diff['added'].append(entry)

        return diff


    def extractallfilehashes():
        ''' Extract all unique file hashes per supplier

        The output files can be used for checking against known hashes
        Called from main()

        Input:
            Uses the currently loaded blockchain
        Output:
            Writes one text file per supplier containing unique file hashes
            from the set of assets monitored by the supplier.

        '''
        supplierfilehashes = {}
        for supplier in SUPPLIERS:
            supplierfilehashes[f'{supplier}'] = set()
        for block in bc.blocks[1:]:
            for assetid, asset in block.data.assets.items():
                if isinstance(asset, FileHashOnly):
                    for supplier, hashset in supplierfilehashes.items():
                        if block.authorid == supplier:
                            hashset.add((asset.hash, asset.assetpath))
                if isinstance(asset, Directory):
                    if asset.dirhashes is not None and len(asset.dirhashes) > 0:
                        for hash, path in asset.dirhashes:
                            for supplier, hashset in supplierfilehashes.items():
                                if block.authorid == supplier:
                                    hashset.add((hash, path))

        for supplier in iter(supplierfilehashes):
            print('\n')
            print('-'*60)
            print(f'{len(supplierfilehashes[supplier])} file hashes from supplier {supplier}:')
            print('-'*60)
            with open(f'{supplier}_hashes', 'a') as f:
                i = 0
                for hash, path in sorted(supplierfilehashes[supplier], key=lambda tpl: tpl[1]):
                    f.write(f'{hash} {path}\n')
                    i += 1
            print(f'{i} unique hashes written to {supplier}_hashes')
            print('\n')




    # ########################################################################
    #                 process command-line arguments
    # ########################################################################


    if args.subcommand == 'newbc':
        print('Creating new blockchain...')
        bc = createnewblockchain()
        saveblockchain()
        printsummary()

    elif args.subcommand == 'agent':
        if args.m1:
            AUTHORID = 'm1'
            ASSETLISTPATH = 'assetlist_m1'
            COMMANDLISTPATH = 'commandlist_m1'
            bc = loadblockchain()
            createnewblock()
            saveblockchain()
            printsummary()

        elif args.m2:
            AUTHORID = 'm2'
            ASSETLISTPATH = 'assetlist_m2'
            COMMANDLISTPATH = 'commandlist_m2'
            bc = loadblockchain()
            createnewblock()
            saveblockchain()
            printsummary()

        elif args.m4:
            AUTHORID = 'm4'
            ASSETLISTPATH = 'assetlist_m4'
            COMMANDLISTPATH = 'commandlist_m4'
            bc = loadblockchain()
            createnewblock()
            saveblockchain()
            printsummary()

    elif args.subcommand == 'admin':
        AUTHORID = 'm0'

        if args.sync:
            sync()

        if args.printsummary:
            bc = loadblockchain()
            printsummary()

        if args.checkintegrity:
            bc = loadblockchain()
            checkintegrity(bc)

        if args.summarizeblock is not None:
            bc = loadblockchain()
            summarizeblock(blocknumber=args.summarizeblock)

        if args.blockdata:
            bc = loadblockchain()
            blockdata(blocknumber=args.blockdata)

        if args.dirasset:
            bc = loadblockchain()
            dirasset(blocknumber=int(args.dirasset[0]), assetid=args.dirasset[1])

        if args.fileasset:
            bc = loadblockchain()
            fileasset(blocknumber=int(args.fileasset[0]), assetid=args.fileasset[1])

        if args.filewholeasset:
            bc = loadblockchain()
            filewholeasset(blocknumber=int(args.filewholeasset[0]), assetid=args.filewholeasset[1])

        if args.filewholeremote:
            bc = loadblockchain()
            filewholeremote(blocknumber=int(args.filewholeremote[0]), assetid=args.filewholeremote[1])

        if args.commandasset:
            bc = loadblockchain()
            commandasset(blocknumber=int(args.commandasset[0]), cmdid=args.commandasset[1])

        if args.dirassethist:
            bc = loadblockchain()
            dirassethist(assetid=args.dirassethist)

        if args.fileassethist:
            bc = loadblockchain()
            fileassethist(assetid=args.fileassethist)

        if args.cmdhist:
            bc = loadblockchain()
            cmdhist(cmdid=args.cmdhist)

        if args.hashchanges:
            bc = loadblockchain()
            authorid = args.hashchanges
            if authorid not in SUPPLIERS:
                raise hashchangesError(f'Unknown authorid {authorid}')

            authorblocks = blocksbyauthor(authorid=authorid, bc=bc)
            setoftuples = enumerateassets(authorblocks)
            assets = sorted(list(setoftuples), key=lambda tpl: tpl[0])
            print('\n')
            print('-'*60)
            print(f'    Blocks by supplier {authorid}:')
            print([block.blocknumber for block in authorblocks])
            print('-'*60)
            print(f'    Assets by supplier {authorid}:')
            for asset in assets:
                print(asset)
            print('-'*60)
            print('\n')
            print(f'    Supplier {authorid} asset hash changes:')
            print('_'*50)
            for asset in assets:
                blknums = assethashchanges(blocks=authorblocks, assetid=asset[0])
                print(f'asset {asset} changed in blocks:')
                print(f'    {sorted(list(blknums))}')
                print('_'*50)
            print('\n')

        if args.dirdiff:
            bc = loadblockchain()
            assetid=args.dirdiff[0]
            blknum1=int(args.dirdiff[1])
            blknum2=int(args.dirdiff[2])
            diff = dirdiff(assetid=assetid, blknum1=blknum1, blknum2=blknum2)
            print('\n')
            print('-'*60)
            print(f'Directory asset {assetid} changed from block {blknum1} to block {blknum2}')
            print('-'*60)
            for entry in diff['removed']:
                print(f'- {entry}')
            for entry in diff['added']:
                print(f'+ {entry}')
            print('-'*60)
            print('\n')

        if args.hashlist:
            bc = loadblockchain()
            extractallfilehashes()


if __name__ == "__main__":
    main()


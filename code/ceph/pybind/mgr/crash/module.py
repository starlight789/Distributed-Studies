"""crash"""
from mgr_module import MgrModule
import datetime
import errno
import json


DATEFMT = '%Y-%m-%d %H:%M:%S.%f'


class Module(MgrModule):
    """crash"""
    def __init__(self, *args, **kwargs):
        super(Module, self).__init__(*args, **kwargs)

    def handle_command(self, inbuf, command):
        """crash"""
        for cmd in self.COMMANDS:
            if cmd['cmd'].startswith(command['prefix']):
                handler = cmd['handler']
                break
        if handler is None:
            return errno.EINVAL, '', 'unknown command %s' % command['prefix']

        return handler(self, command, inbuf)

    @staticmethod
    def validate_crash_metadata(inbuf):
        """crash"""
        # raise any exceptions to caller
        metadata = json.loads(inbuf)
        if 'crash_id' not in metadata:
            raise AttributeError("missing 'crash_id' field")
        return metadata

    @staticmethod
    def time_from_string(timestr):
        """crash"""
        # drop the 'Z' timezone indication, it's always UTC
        timestr = timestr.rstrip('Z')
        return datetime.datetime.strptime(timestr, DATEFMT)

    # command handlers

    def do_info(self, cmd, inbuf):
        """crash"""
        crashid = cmd['id']
        key = 'crash/%s' % crashid
        val = self.get_store(key)
        if not val:
            return errno.EINVAL, '', 'crash info: %s not found' % crashid
        return 0, val, ''

    def do_post(self, cmd, inbuf):
        """crash"""
        try:
            metadata = self.validate_crash_metadata(inbuf)
        except Exception as e:
            return errno.EINVAL, '', 'malformed crash metadata: %s' % e

        crashid = metadata['crash_id']
        key = 'crash/%s' % crashid
        # repeated stores of same item are ignored silently
        if not self.get_store(key):
            self.set_store(key, inbuf)
        return 0, '', ''

    def do_ls(self, cmd, inbuf):
        """crash"""
        keys = []
        for key in self.get_store_prefix('crash/').iterkeys():
            keys.append(key.replace('crash/', ''))
        return 0, '\n'.join(keys), ''

    def do_rm(self, cmd, inbuf):
        """crash"""
        crashid = cmd['id']
        key = 'crash/%s' % crashid
        self.set_store(key, None)       # removes key
        return 0, '', ''

    def do_prune(self, cmd, inbuf):
        """crash"""
        now = datetime.datetime.utcnow()

        keep = cmd['keep']
        try:
            keep = int(keep)
        except ValueError:
            return errno.EINVAL, '', 'keep argument must be integer'

        keeptime = datetime.timedelta(days=keep)

        for key, meta in self.get_store_prefix('crash/').iteritems():
            meta = json.loads(meta)
            stamp = self.time_from_string(meta['timestamp'])
            if stamp <= now - keeptime:
                self.set_store(key, None)

        return 0, '', ''

    def do_stat(self, cmd, inbuf):
        """crash"""
        # age in days for reporting, ordered smallest first
        bins = [1, 3, 7]
        retlines = list()

        def binstr(bindict):
            """crash"""
            binlines = list()
            count = len(bindict['idlist'])
            if count:
                binlines.append(
                    '%d older than %s days old:' % (count, bindict['age'])
                )
                for crashid in bindict['idlist']:
                    binlines.append(crashid)
            return '\n'.join(binlines)

        total = 0
        now = datetime.datetime.utcnow()
        for i, age in enumerate(bins):
            agelimit = now - datetime.timedelta(days=age)
            bins[i] = {
                'age': age,
                'agelimit': agelimit,
                'idlist': list()
            }

        for key, meta in self.get_store_prefix('crash/').iteritems():
            total += 1
            meta = json.loads(meta)
            stamp = self.time_from_string(meta['timestamp'])
            crashid = meta['crash_id']
            for i, bindict in enumerate(bins):
                if stamp <= bindict['agelimit']:
                    bindict['idlist'].append(crashid)
                    # don't count this one again
                    continue

        retlines.append('%d crashes recorded' % total)

        for bindict in bins:
            retlines.append(binstr(bindict))
        return 0, '\n'.join(retlines), ''

    def do_self_test(self, cmd, inbuf):
        """crash"""
        # test time conversion
        timestr = '2018-06-22 20:35:38.058818Z'
        dt = self.time_from_string(timestr)
        if dt != datetime.datetime(2018, 6, 22, 20, 35, 38, 58818):
            return errno.EINVAL, '', 'time_from_string() failed'

        return 0, '', 'self-test succeeded'

    COMMANDS = [
        {
            'cmd': 'crash info name=id,type=CephString',
            'desc': 'show crash dump metadata',
            'perm': 'r',
            'handler': do_info,
        },
        {
            'cmd': 'crash ls',
            'desc': 'Show saved crash dumps',
            'perm': 'r',
            'handler': do_ls,
        },
        {
            'cmd': 'crash post',
            'desc': 'Add a crash dump (use -i <jsonfile>)',
            'perm': 'rw',
            'handler': do_post,
        },
        {
            'cmd': 'crash prune name=keep,type=CephString',
            'desc': 'Remove crashes older than <keep> days',
            'perm': 'rw',
            'handler': do_prune,
        },
        {
            'cmd': 'crash rm name=id,type=CephString',
            'desc': 'Remove a saved crash <id>',
            'perm': 'rw',
            'handler': do_rm,
        },
        {
            'cmd': 'crash self-test',
            'desc': 'Run a self test of the crash module',
            'perm': 'r',
            'handler': do_self_test,
        },
        {
            'cmd': 'crash stat',
            'desc': 'Summarize recorded crashes',
            'perm': 'r',
            'handler': do_stat,
        },
    ]

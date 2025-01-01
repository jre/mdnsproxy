#!/usr/bin/env python3

# Copyright (c) 2022 Joshua R. Elsasser <josh@elsasser.org>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

import argparse
import fcntl
import grp
import os
import pwd
import socket
import sys

import daemon
import dnslib.proxy
import dnslib.server


class DispatchingResolver(dnslib.proxy.BaseResolver):
    mdns_zones = (b'local.', b'254.169.in-addr.arpa.', b'8.e.f.ip6.arpa.',
                  b'9.e.f.ip6.arpa.', b'a.e.f.ip6.arpa.', b'b.e.f.ip6.arpa.')

    def __init__(self, ucast_addr):
        self.ucast_resv = None
        if ucast_addr is not None:
            self.ucast_resv = dnslib.proxy.ProxyResolver(ucast_addr, 53, 5)
        self.mcast_resv = dnslib.proxy.ProxyResolver('224.0.0.251', 5353, 2)

    def resolve(self, request, handler):
        for zone in self.mdns_zones:
            if request.q.qname.matchSuffix(zone):
                resp = self.mcast_resv.resolve(request, handler)
                if request.header.rd:
                    resp.header.rd = True
                    resp.header.ra = True
                return resp
        if self.ucast_resv is not None:
            return self.ucast_resv.resolve(request, handler)
        error = request.reply(aa=0)
        error.header.rcode = dnslib.RCODE.SERVFAIL
        return error


class Daemonize(daemon.DaemonContext):
    def __init__(self, uid, gid, pidfile=None, files_preserve=()):
        fdlist = list(files_preserve)
        nullfh = open('/dev/null', 'r+b')
        fdlist.append(nullfh.fileno())

        pidfh = None
        if pidfile is not None:
            pidfh = open(pidfile, 'a')
            try:
                fcntl.flock(pidfh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                myname = sys.argv[0].rsplit('/', 1)[-1]
                print('Failed to lock pidfile %s, is %s already running?' % (
                    pidfile, myname), file=sys.stderr)
                sys.exit(1)
            pidfh.seek(0)
            pidfh.truncate(0)
            fdlist.append(pidfh.fileno())
        self.__pidfh = pidfh

        super().__init__(files_preserve=fdlist,
                         chroot_directory='/var/empty',
                         working_directory='/',
                         umask=0o022,
                         detach_process=True,
                         uid=uid,
                         gid=gid,
                         initgroups=True,
                         stdin=nullfh,
                         stdout=nullfh,
                         stderr=nullfh)

    def __enter__(self):
        res = super().__enter__()
        if self.__pidfh is not None:
            print(os.getpid(), file=self.__pidfh, flush=True)
        return res


def IPv4Address(arg):
    try:
        if arg == '' or socket.inet_pton(socket.AF_INET, arg):
            return arg
    except Exception as exc:
        raise ValueError(exc.args)
    raise ValueError()


def UserName(arg):
    try:
        return int(arg)
    except ValueError:
        pass
    try:
        return pwd.getpwnam(arg).pw_uid
    except Exception as exc:
        raise ValueError(exc.args)


def GroupName(arg):
    try:
        return int(arg)
    except ValueError:
        pass
    try:
        return grp.getgrnam(arg).gr_gid
    except Exception as exc:
        raise ValueError(exc.args)


def main():
    parser = argparse.ArgumentParser(
        description='Proxy DNS requests to a recursive DNS server or to mDNS')
    parser.add_argument('server', type=IPv4Address, nargs='?',
                        help='Recursive DNS server IPv4 address')
    parser.add_argument('-a', dest='bindaddr', type=IPv4Address, default='',
                        help='IPv4 address to listen for requests on')
    parser.add_argument('-P', dest='bindport', type=int, default=53,
                        help='port number to listen for requests on')
    parser.add_argument('-p', dest='pidfile',
                        help='Write server PID to this file')
    parser.add_argument('-u', dest='user', type=UserName, default='nobody',
                        help='User name or ID to change to')
    parser.add_argument('-g', dest='group', type=GroupName, default='nogroup',
                        help='User name or ID to change to')
    parser.add_argument('-d', dest='debug', action='store_true',
                        help='Run in the foreground and output debug messages')
    args = parser.parse_args()

    resolver = DispatchingResolver(args.server)
    server = dnslib.server.DNSServer(resolver,
                                     address=args.bindaddr,
                                     port=args.bindport)

    if args.debug:
        server.start()
    else:
        with Daemonize(args.user, args.group,
                       files_preserve=[server.server.socket.fileno()],
                       pidfile=args.pidfile):
            server.start()


if __name__ == '__main__':
    main()

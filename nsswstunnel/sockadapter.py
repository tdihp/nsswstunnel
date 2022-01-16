"""
Incomplete adapting from nss to python socket
"""
import os
import sys
import socket
import errno
from functools import wraps
import traceback

from twisted.logger import Logger

from nss.error import NSPRError, get_nspr_error_string
import nss.io as io
import nss.ssl as ssl

import prerr

# logger = logging.getLogger('sockadapter')
log = Logger()


OPT_NSPR2SOCKET = {
    io.PR_SockOpt_NoDelay: (socket.IPPROTO_TCP, socket.TCP_NODELAY),
    io.PR_SockOpt_Keepalive: (socket.SOL_SOCKET, socket.SO_KEEPALIVE),
    io.PR_SockOpt_Reuseaddr: (socket.SOL_SOCKET, socket.SO_REUSEADDR),
}
OPT_SOCKET2NSPR = dict((v, k) for k, v in OPT_NSPR2SOCKET.items())

ERRNO_NSPR2SOCKET = {
    prerr.PR_INVALID_ARGUMENT_ERROR: errno.EINVAL,
    prerr.PR_WOULD_BLOCK_ERROR: errno.EWOULDBLOCK,
    prerr.PR_IN_PROGRESS_ERROR: errno.EINPROGRESS,
    prerr.PR_ALREADY_INITIATED_ERROR: errno.EALREADY,
    prerr.PR_IS_CONNECTED_ERROR: errno.EISCONN,
    prerr.PR_OUT_OF_MEMORY_ERROR: errno.ENOMEM,
    prerr.PR_CONNECT_ABORTED_ERROR: errno.ECONNABORTED,
    prerr.PR_CONNECT_REFUSED_ERROR: errno.ECONNREFUSED,
    prerr.PR_NOT_CONNECTED_ERROR: errno.ENOTCONN,
}


def addr_nspr2socket(addr):
    """convert nspr io style addr to python socket style"""
    args = (addr.address, addr.port)
    if addr.family == io.PR_AF_INET6:
        args += (0, 0)

    return args


def addr_socket2nspr(addr):
    """convert python socket style addr to nspr io stile"""
    if len(addr) == 4:
        assert addr[2] == 0 and addr[3] == 0

    addr, port = addr[:2]
    addr_info = io.AddrInfo(addr, flags=io.PR_AI_ADDRCONFIG|io.PR_AI_NOCANONNAME)
    assert len(addr_info) == 1
    net_addr = addr_info[0]
    net_addr.port = port
    return net_addr

def nspr2oserror(f):
    @wraps(f)
    def wrapper(*args, **kwds):
        try:
            return f(*args, **kwds)
        except NSPRError as e:
            if e.errno in ERRNO_NSPR2SOCKET:
                err = ERRNO_NSPR2SOCKET[e.errno]
                exc = OSError(err, os.strerror(err))
                log.debug('got exc %s' % exc)
                raise exc
            else:
                # we have no idea what this is, raise as-is
                raise

    return wrapper


# NOTE: subclassing SSLSocket doesn't work due to the implementation logic's use of Py_TYPE(self)->tp_base
class SocketAdapter(object):
    """
    Adapts a SSLSocket into Regular socket
    """
    def __init__(self, skt):
        self.skt = skt

    def __getattr__(self, name):
        attr = getattr(self.skt, name)
        return attr

    def setblocking(self, flag):
        nonblocking = not(flag)
        self.skt.set_socket_option(io.PR_SockOpt_Nonblocking, nonblocking)

    def getsockopt(self, level, optname, buflen=None):
        if optname == socket.SO_ERROR:
            log.debug('SO_ERROR is always zero!')
            # nss doesn't implement this
            return 0

        return self.skt.get_socket_option(OPT_SOCKET2NSPR[(level, optname)])
    
    def setsockopt(self, level, optname, value):
        return self.skt.get_socket_option(OPT_SOCKET2NSPR[(level, optname)])

    def getpeername(self):
        return addr_nspr2socket(self.skt.get_peer_name())

    def getsockname(self):
        return addr_nspr2socket(self.skt.get_sock_name())

    @nspr2oserror
    def connect(self, address):
        addr = addr_socket2nspr(address)
        self.skt.connect(addr)

    def connect_ex(self, address):
        try:
            self.connect(address)
            return 0
        except OSError as e:
            return e.errno

    def bind(self):
        raise NotImplementedError()

    # def shutdown(self, how):
    #     return self.skt.shutdown(how)

    @nspr2oserror
    def send(self, buf, flags=0):
        assert flags == 0
        return self.skt.send(bytes(buf))

    @nspr2oserror
    def recv(self, bufsize, flags=0):
        assert flags == 0
        return self.skt.recv(bufsize)

    @nspr2oserror
    def shutdown(self, flags):
        return self.skt.shutdown(flags)


"""
asyncio event loop implementation
"""

import socket
import asyncio
import logging
import functools
# hack for copying _ensure_resolved, as 3.6 doesn't include _ensure_resolved as a private method
from asyncio.base_events import _ipaddr_info

import nss.nss as nss
import nss.ssl as ssl
import nss.io as io

from .sockadapter import SocketAdapter

logger = logging.getLogger(__name__)


async def _ensure_resolved(loop, address,  *,
                           family=0, type=socket.SOCK_STREAM,
                           proto=0, flags=0):
        host, port = address[:2]
        info = _ipaddr_info(host, port, family, type, proto, *address[2:])
        if info is not None:
            # "host" is already a resolved IP.
            return [info]
        else:
            return await loop.getaddrinfo(host, port, family=family, type=type,
                                          proto=proto, flags=flags)


def _sock_connect_cb(fut, sock, address):
    if fut.done():
        return
    # nspr offers no way to verify if a socket is in error,
    # try to run connect again, it should raise error if not connected or not done.
    try:
        sock.connect(address)
    except (BlockingIOError, InterruptedError):
        pass
    except (SystemExit, KeyboardInterrupt):
        raise
    except BaseException as exc:
        fut.set_exception(exc)
    else:
        fut.set_result(None)


def sock_connect(loop, sock, address):
    fut = loop.create_future()
    fd = sock.fileno()
    try:
        sock.connect(address)
    except (BlockingIOError, InterruptedError):
        loop.add_writer(fd, _sock_connect_cb, fut, sock, address)

    fut.add_done_callback(lambda _: loop.remove_writer(fd))
    return fut


def _sock_ssl_handshake_cb(fut, sock):
    if fut.done():
        return

    try:
        sock.force_handshake()
    except BlockingIOError:
        pass
    except (SystemExit, KeyboardInterrupt):
        raise
    except BaseException as exc:
        fut.set_exception(exc)


def _ssl_handshake_done(sock, fut):
    logger.info('handshake done for sock %s', sock.get_peer_name())
    logger.debug('negotiated host: %s', sock.get_negotiated_host())
    logger.debug('connection_info_str: %s', sock.connection_info_str())
    fut.set_result(None)


def _ssl_cert_verify(sock, check_sig, is_server, certdb):
    log = logger.getChild('_ssl_cert_verify')
    log.debug("check_sig=%s is_server=%s", check_sig, is_server)
    assert not is_server

    cert = sock.get_peer_certificate()
    pin_args = sock.get_pkcs11_pin_arg()
    if pin_args is None:
        pin_args = ()

    log.debug("peer cert:\n%s", cert)
    intended_usage = nss.certificateUsageSSLServer

    try:
        approved_usage = cert.verify_now(certdb, check_sig, intended_usage, *pin_args)
    except Exception as e:
        log.exception('failed during verify')
        return False

    log.debug("approved_usage = %s", ', '.join(nss.cert_usage_flags(approved_usage)))

    # Is the intended usage a proper subset of the approved usage
    if not (approved_usage & intended_usage):
        return False

    hostname = sock.get_hostname()
    log.debug("verifying socket hostname %s matches cert subject %s", hostname, cert.subject)
    try:
        # If the cert fails validation it will raise an exception
        cert_is_valid = cert.verify_hostname(hostname)
    except Exception as e:
        log.exception("Failed validating hostname")
        return False

    log.debug('cert_is_valid: %s', cert_is_valid)
    return cert_is_valid


def _sock_ssl_handshake(loop, sock):
    """ enforcing handshake
    """
    fut = loop.create_future()
    # sock = SocketAdapter(sock)
    fd = sock.fileno()
    sock.set_handshake_callback(_ssl_handshake_done, fut)
    try:
        sock.force_handshake()
    except BlockingIOError:
        loop.add_writer(fd, _sock_ssl_handshake_cb, fut, sock)

    fut.add_done_callback(lambda _: loop.remove_writer(fd))
    return fut


async def _connect_sock(loop, exceptions, addrinfo, ssl_context, server_hostname,
        ssl_handshake_timeout, certdb):
    """Initializes socket and try connect as a (SSL) client"""
    my_exceptions = []
    exceptions.append(my_exceptions)
    family, _, proto, _, address = addrinfo
    assert proto == socket.IPPROTO_TCP
    assert family in (socket.AF_INET, socket.AF_INET6)
    sock = None
    if ssl_context:
        sock = SocketAdapter(ssl.SSLSocket(family))
        sock.set_ssl_option(ssl.SSL_SECURITY, True)
        sock.set_ssl_option(ssl.SSL_HANDSHAKE_AS_CLIENT, True)
        sock.set_hostname(server_hostname)
        sock.set_auth_certificate_callback(_ssl_cert_verify, certdb)
    else:
        sock = SocketAdapter(io.Socket(family))
    sock.setblocking(False)
    try:
        await sock_connect(loop, sock, address)
        if ssl:
            await _sock_ssl_handshake(loop, sock)
    except OSError as exc:
        my_exceptions.append(exc)
        if sock is not None:
            sock.close()
        raise
    except:
        if sock is not None:
            sock.close()
        raise
    return sock


async def create_nss_connection(
        loop, protocol_factory, host, port, *, ssl=None,
        server_hostname=None, ssl_handshake_timeout=None,
        certdb=None):
    """builds the SSLSocket"""
    if server_hostname is not None and not ssl:
        raise ValueError('server_hostname is only meaningful with ssl')

    if server_hostname is None and ssl:
        server_hostname = host

    if ssl_handshake_timeout is not None and not ssl:
        raise ValueError(
            'ssl_handshake_timeout is only meaningful with ssl')

    if ssl and not certdb:
        certdb = nss.get_default_certdb()

    # HACK: use internal function of loop
    infos = await _ensure_resolved(loop,
        (host, port), family=socket.AF_INET, type=socket.SOCK_STREAM,
        proto=socket.IPPROTO_TCP, flags=0)

    if not infos:
        raise OSError('getaddrinfo() returned empty list')

    exceptions = []
    for addrinfo in infos:
        try:
            sock = await _connect_sock(loop, exceptions, addrinfo,
                ssl, server_hostname, ssl_handshake_timeout, certdb)
            break
        except OSError:
            continue

    if sock is None:
        exceptions = [exc for sub in exceptions for exc in sub]
        if len(exceptions) == 1:
            raise exceptions[0]
        else:
            raise OSError('Multiple exceptions: {}'.format(
                ', '.join(str(exc) for exc in exceptions)))
    logger.debug('got sock %r', sock)
    return await loop.create_connection(protocol_factory, sock=sock)

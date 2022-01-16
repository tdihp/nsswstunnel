import sys

from twisted.internet.epollreactor import EPollReactor
from twisted.internet import tcp, fdesc
from twisted.internet.endpoints import HostnameEndpoint
from twisted.python.compat import nativeString
from twisted.logger import Logger

import nss.nss as nss
import nss.ssl as ssl

logger = Logger()

from .sockadapter import SocketAdapter


class NSSClient(tcp.Client):
    """
    NSS based SSL client
    """
    def createInternetSocket(self):
        import socket
        s = SocketAdapter(ssl.SSLSocket(self.addressFamily))
        s.set_ssl_option(ssl.SSL_SECURITY, False)
        s.set_ssl_option(ssl.SSL_HANDSHAKE_AS_CLIENT, True)
        s.set_ssl_option(ssl.SSL_HANDSHAKE_AS_SERVER, False)
        s.setblocking(0)
        fdesc._setCloseOnExec(s.fileno())
        return s

    def enableSSL(self, hostname, client_nickname=None, password=None):
        """Start SSL configuration"""
        s = self.socket
        s.set_ssl_option(ssl.SSL_SECURITY, True)
        s.set_hostname(hostname)

        # Provide a callback which notifies us when the SSL handshake is complete
        s.set_handshake_callback(self.handshake_callback)

        # Provide a callback to supply our client certificate info
        # s.set_client_auth_data_callback(self.client_auth_data_callback, client_nickname,
        #                                 password, nss.get_default_certdb())

        # Provide a callback to verify the servers certificate
        s.set_auth_certificate_callback(self.auth_certificate_callback,
                                        nss.get_default_certdb())

    @staticmethod
    def handshake_callback(s):
        logger.info("-- handshake complete --")
        logger.info("peer: {peer}", peer=s.get_peer_name())
        logger.info("negotiated host: {negotiated_host}", negotiated_host=s.get_negotiated_host())
        logger.info("{connection_info}", connection_info=s.connection_info_str())
        logger.info("-- handshake complete --")

    @staticmethod
    def auth_certificate_callback(s, check_sig, is_server, certdb):
        logger.info("auth_certificate_callback: check_sig={check_sig} is_server={is_server}",
            check_sig=check_sig, is_server=is_server)

        cert = s.get_peer_certificate()
        pin_args = s.get_pkcs11_pin_arg()
        if pin_args is None:
            pin_args = ()

        logger.info("peer cert:\n{cert}", cert=cert)

        intended_usage = nss.certificateUsageSSLServer

        try:
            # If the cert fails validation it will raise an exception, the errno attribute
            # will be set to the error code matching the reason why the validation failed
            # and the strerror attribute will contain a string describing the reason.
            approved_usage = cert.verify_now(certdb, check_sig, intended_usage, *pin_args)
        except Exception as e:
            logger.failure('failed during verify: {exc}', exc=e)
            return False

        logger.info("approved_usage = {approved_usage}", approved_usage=', '.join(nss.cert_usage_flags(approved_usage)))

        # Is the intended usage a proper subset of the approved usage
        if not (approved_usage & intended_usage):
            return False

        # Certificate is OK.  Since this is the client side of an SSL
        # connection, we need to verify that the name field in the cert
        # matches the desired hostname.  This is our defense against
        # man-in-the-middle attacks.

        hostname = s.get_hostname()
        logger.info("verifying socket hostname {hostname} matches cert subject {subject}", hostname=hostname, subject=cert.subject)
        try:
            # If the cert fails validation it will raise an exception
            cert_is_valid = cert.verify_hostname(hostname)
        except Exception as e:
            logger.failure("Failed validating hostname: {exc}", exc=e)
            return False

        logger.info('cert_is_valid: {cert_is_valid}', cert_is_valid=cert_is_valid)
        return cert_is_valid


class NSSConnector(tcp.Connector):
    enable_ssl = False

    def __init__(self, host, port, factory, timeout, bindAddress, reactor=None):
        super().__init__(host, port, factory, timeout, bindAddress, reactor)


    def _makeTransport(self):
        client = NSSClient(self.host, self.port, self.bindAddress, self, self.reactor)
        if self.enable_ssl:
            client.enableSSL(self.host)

        return client


class NSSReactor(EPollReactor):
    """
    NSS based reactor that opens client connections with NSS Sockets.

    Note: It is based on a socket adapter that converts SSLSocket to regular socket.
    However SSLSocket behaves differently on polling due to NSPR / NSS's poll logic override.
    This however doesn't affect transport per testing,
    only that results several non-bocking errors when calling send/recv.
    """
    def connectTCP(self, host, port, factory, timeout=30, bindAddress=None):
        c = NSSConnector(host, port, factory, timeout, bindAddress, self)
        c.connect()
        return c

    def connectSSL(
        self, host, port, factory, contextFactory, timeout=30, bindAddress=None
    ):
        # basically we ignore contextFactory
        c = NSSConnector(host, port, factory, timeout, bindAddress, self)
        c.enable_ssl=True
        c.connect()
        return c

    # For now we use the builtin listen features
    # def listenTCP(self, port, factory, backlog=50, interface=""):
    #     raise NotImplementedError('nss TCP listen not yet implemented')

    # def listenSSL(self, port, factory, contextFactory, backlog=50, interface=""):
    #     raise NotImplementedError('nss SSL listen not yet implemented')


def install():
    """
    Configure the twisted mainloop to be run inside the glib mainloop.
    """
    reactor = NSSReactor()
    from twisted.internet.main import installReactor

    installReactor(reactor)


def test_http():
    """a simplistic test by building http client and run a GET query"""
    
    install()
    import os
    from twisted.web.client import HTTPClientFactory
    from twisted.internet import reactor
    nss.nss_init('sql:' + os.path.expanduser('~/.pki/nssdb'))
    ssl.set_domestic_policy()
    # nss.set_password_callback(password_callback)

    factory = HTTPClientFactory(b'https://baidu.com/')
    # factory = HTTPClientFactory(b'http://baidu.com/')
    def cb_response(*args, **kwargs):
        print('response: %r, %r' % (args, kwargs))

    def cb_err(*args, **kwargs):
        print('err: %r, %r' % (args, kwargs))

    def cb_close(ignored):
        reactor.stop()

    factory.deferred.addCallbacks(cb_response, cb_err)
    factory.deferred.addBoth(cb_close)
    # reactor.connectTCP('baidu.com', 80, factory)
    reactor.connectSSL('baidu.com', 443, factory, contextFactory=None)
    reactor.run()


if __name__ == '__main__':
    from twisted.python import log
    log.startLogging(sys.stdout)
    test_http()

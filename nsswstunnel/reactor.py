import sys
import logging

from twisted.internet.epollreactor import EPollReactor
from twisted.internet import tcp, fdesc
from twisted.internet.endpoints import HostnameEndpoint
from twisted.python.compat import nativeString
# from twisted.logger import Logger

import nss.nss as nss
import nss.ssl as ssl

from .sockadapter import SocketAdapter

# logger = Logger()
logger = logging.getLogger(__name__)


class NSSClient(tcp.Client):
    """
    NSS based SSL client
    """
    def createInternetSocket(self):
        s = SocketAdapter(ssl.SSLSocket(self.addressFamily))
        s.set_ssl_option(ssl.SSL_SECURITY, False)
        s.set_ssl_option(ssl.SSL_HANDSHAKE_AS_CLIENT, True)
        s.set_ssl_option(ssl.SSL_HANDSHAKE_AS_SERVER, False)
        s.setblocking(0)
        fdesc._setCloseOnExec(s.fileno())
        return s

    def enableSSL(self, hostname, verify_ssl=True):
        """Start SSL configuration"""
        s = self.socket
        s.set_ssl_option(ssl.SSL_SECURITY, True)
        s.set_hostname(hostname)

        # Provide a callback which notifies us when the SSL handshake is complete
        s.set_handshake_callback(self.handshake_callback)

        # Provide a callback to verify the servers certificate
        if verify_ssl:
            s.set_auth_certificate_callback(
                self.auth_certificate_callback,
                nss.get_default_certdb()
            )

    @staticmethod
    def handshake_callback(s):
        logger.info("-- handshake complete --")
        logger.debug("peer: %s", s.get_peer_name())
        logger.debug("negotiated host: %s", s.get_negotiated_host())
        logger.debug("%s", s.connection_info_str())
        logger.debug("-- handshake complete --")

    @staticmethod
    def auth_certificate_callback(s, check_sig, is_server, certdb):
        logger.info("auth_certificate_callback: check_sig=%s is_server=%s",
            check_sig, is_server)

        cert = s.get_peer_certificate()
        pin_args = s.get_pkcs11_pin_arg()
        if pin_args is None:
            pin_args = ()

        logger.info("peer cert:\n%s", cert)

        intended_usage = nss.certificateUsageSSLServer

        try:
            # If the cert fails validation it will raise an exception, the errno attribute
            # will be set to the error code matching the reason why the validation failed
            # and the strerror attribute will contain a string describing the reason.
            approved_usage = cert.verify_now(certdb, check_sig, intended_usage, *pin_args)
        except Exception as e:
            logger.exception('failed during verify')
            return False

        logger.info("approved_usage = %s", ', '.join(nss.cert_usage_flags(approved_usage)))

        # Is the intended usage a proper subset of the approved usage
        if not (approved_usage & intended_usage):
            return False

        # Certificate is OK.  Since this is the client side of an SSL
        # connection, we need to verify that the name field in the cert
        # matches the desired hostname.  This is our defense against
        # man-in-the-middle attacks.

        hostname = s.get_hostname()
        logger.info("verifying socket hostname %s matches cert subject %s", hostname, cert.subject)
        try:
            # If the cert fails validation it will raise an exception
            cert_is_valid = cert.verify_hostname(hostname)
        except Exception as e:
            logger.exception("Failed validating hostname")
            return False

        logger.info('cert_is_valid: %s', cert_is_valid)
        return cert_is_valid


class NSSConnector(tcp.Connector):
    enable_ssl = False

    def __init__(self,
            host, port, factory, timeout, bindAddress, reactor=None,
            enable_ssl=False, verify_ssl=True):
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


def install():
    """
    Configure the twisted mainloop to be run inside the glib mainloop.
    """
    reactor = NSSReactor()
    from twisted.internet.main import installReactor

    installReactor(reactor)





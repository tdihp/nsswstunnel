import unittest
from nsswstunnel.reactor import *

class NSSReactorTests(unittest.TestCase):
    def test_http(self):
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
            self.fail()

        def cb_err(*args, **kwargs):
            print('err: %r, %r' % (args, kwargs))
            self.fail()

        def cb_close(ignored):
            reactor.stop()

        factory.deferred.addCallbacks(cb_response, cb_err)
        factory.deferred.addBoth(cb_close)
        # reactor.connectTCP('baidu.com', 80, factory)
        reactor.connectSSL('baidu.com', 443, factory, contextFactory=None)
        reactor.run()


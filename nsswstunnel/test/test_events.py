

import pytest
import asyncio
from functools import partial
import ssl as openssl
from nsswstunnel.events import *


class EchoServerProtocol(asyncio.Protocol):
    def connection_made(self, transport):
        peername = transport.get_extra_info('peername')
        print('Connection from {}'.format(peername))
        self.transport = transport

    def data_received(self, data):
        message = data.decode()
        print('Data received: {!r}'.format(message))
        self.transport.write(data)
        print('Close the client socket')
        self.transport.close()


@pytest.mark.asyncio
async def test_create_nss_connection_e2e(certdb, server_cert, server_name):
    loop = asyncio.get_event_loop()
    TESTPORT=8443
    certfile, keyfile = server_cert
    ssl_context = openssl.create_default_context(openssl.Purpose.CLIENT_AUTH)
    ssl_context.check_hostname = False
    ssl_context.load_cert_chain(certfile, keyfile)
    server = await loop.create_server(EchoServerProtocol, '127.0.0.1', TESTPORT, ssl=ssl_context)
    # loop.run_until_complete()s

    class EchoClientProtocol(asyncio.Protocol):
        def __init__(self, on_con_lost):
            self.got = None
            self.on_con_lost = on_con_lost

        def connection_made(self, transport):
            self.transport = transport
            transport.write('El Psy Kangaroo'.encode('ascii'))

        def data_received(self, data):
            assert data.decode('ascii') == 'El Psy Kangaroo'
            assert self.got is None
            self.got = data
            self.transport.close()

        def connection_lost(self, exc):
            assert exc is None
            assert self.got
            self.on_con_lost.set_result(True)

    await server.start_serving()
    async with server:
        await server.start_serving()
        on_con_lost = loop.create_future()
        conn = await create_nss_connection(
            loop, partial(EchoClientProtocol, on_con_lost),
            '127.0.0.1', TESTPORT, ssl=True,
            server_hostname=server_name, ssl_handshake_timeout=5,
            certdb=nss.get_default_certdb())
        # print('got conn %r'% conn)
        # client_ssl_context = openssl.create_default_context()
        # client_ssl_context.load_verify_locations(certfile)
        # conn = await loop.create_connection(
        #     partial(EchoClientProtocol, on_con_lost),
        #     host='127.0.0.1', port=TESTPORT,
        #     ssl=client_ssl_context, server_hostname=server_name,
        #     ssl_handshake_timeout=5)
        await asyncio.wait_for(on_con_lost, timeout=1)



"""main components of server logic"""

from autobahn.twisted.websocket import WebSocketClientProtocol, \
    WebSocketClientFactory


class TunnelProtocol(WebSocketClientProtocol):
    def onConnect(self)

class MyClientProtocol(WebSocketClientProtocol):

    def onConnect(self, response):
        print("Server connected: {0}".format(response.peer))

    def onConnecting(self, transport_details):
        print("Connecting; transport details: {}".format(transport_details))
        return None  # ask for defaults

    def onOpen(self):
        print("WebSocket connection open.")

        def hello():
            self.sendMessage("Hello, world!".encode('utf8'))
            self.sendMessage(b"\x00\x01\x03\x04", isBinary=True)
            self.factory.reactor.callLater(1, hello)

        # start sending messages every second ..
        hello()

    def onMessage(self, payload, isBinary):
        if isBinary:
            print("Binary message received: {0} bytes".format(len(payload)))
        else:
            print("Text message received: {0}".format(payload.decode('utf8')))

    def onClose(self, wasClean, code, reason):
        print("WebSocket connection closed: {0}".format(reason))


class MyClientFactory():
    pass

if __name__ == '__main__':

    import sys

    from twisted.python import log
    from nssreactor import NSSReactor
    reactor = NSSReactor()

    log.startLogging(sys.stdout)

    factory = WebSocketClientFactory("ws://127.0.0.1:9000", reactor=reactor)
    factory.protocol = MyClientProtocol

    reactor.connectTCP("127.0.0.1", 9000, factory)
    reactor.run()


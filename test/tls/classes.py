# -*- coding: utf-8 -*-

import datetime

import abc
import unittest
try:
    from unittest import mock
except ImportError:
    import mock

from test.common.classes import TestThreadedServer

import attr
import six

from cryptoparser.tls.ciphersuite import TlsCipherSuite
from cryptoparser.tls.extension import TlsExtensionsClient
from cryptoparser.tls.record import TlsRecord
from cryptoparser.tls.subprotocol import (
    TlsAlertDescription,
    TlsAlertLevel,
    TlsAlertMessage,
    TlsContentType,
    TlsHandshakeHelloRandom,
    TlsHandshakeServerHello,
)
from cryptoparser.tls.version import TlsProtocolVersionFinal, TlsVersion

from cryptolyzer.common.exception import NetworkError, NetworkErrorType, SecurityError, SecurityErrorType
from cryptolyzer.tls.client import L7ClientTlsBase
from cryptolyzer.tls.exception import TlsAlert
from cryptolyzer.tls.server import L7ServerTls, TlsServerHandshake


class TestTlsCases:
    class TestTlsBase(unittest.TestCase):
        @staticmethod
        @abc.abstractmethod
        def get_result(host, port, protocol_version=None, timeout=None, ip=None):
            raise NotImplementedError()

        @mock.patch.object(
            L7ClientTlsBase, 'do_tls_handshake',
            side_effect=SecurityError(SecurityErrorType.UNPARSABLE_MESSAGE)
        )
        def test_error_security_error_unparsable_message(self, _):
            self.get_result('badssl.com', 443)

        @mock.patch.object(
            L7ClientTlsBase, 'do_tls_handshake',
            side_effect=NetworkError(NetworkErrorType.NO_CONNECTION)
        )
        def test_error_network_error_no_connection(self, _):
            with self.assertRaises(NetworkError) as context_manager:
                self.get_result('badssl.com', 443)
            self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_CONNECTION)

        @mock.patch.object(
            L7ClientTlsBase, 'do_tls_handshake',
            side_effect=NetworkError(NetworkErrorType.NO_RESPONSE)
        )
        def test_error_network_error_no_response(self, _):
            self.get_result('badssl.com', 443)

        @mock.patch.object(
            L7ClientTlsBase, 'do_tls_handshake',
            side_effect=TlsAlert(TlsAlertDescription.UNEXPECTED_MESSAGE)
        )
        def test_error_tls_alert(self, _):
            with self.assertRaises(TlsAlert) as context_manager:
                self.get_result('badssl.com', 443)
            self.assertEqual(context_manager.exception.description, TlsAlertDescription.UNEXPECTED_MESSAGE)


class L7ServerTlsTest(TestThreadedServer):
    def __init__(self, l7_server):
        self.l7_server = l7_server
        super(L7ServerTlsTest, self).__init__(self.l7_server)

    def run(self):
        self.l7_server.do_handshake()


@attr.s
class TlsServerMockResponse(TlsServerHandshake):
    _message_count = attr.ib(init=False, default=0)

    def _get_mock_responses(self):
        raise NotImplementedError()

    def _init_connection(self, last_handshake_message_type):
        mock_responses = self._get_mock_responses()
        self.l4_transfer.send(b''.join(mock_responses))

    def _process_invalid_message(self):
        pass


class L7ServerTlsMockResponse(L7ServerTls):
    @staticmethod
    def _get_handshake_class(l4_transfer):
        return TlsServerMockResponse


class TlsServerPlainTextResponse(TlsServerHandshake):
    def _process_handshake_message(self, message, last_handshake_message_type):
        self.l4_transfer.send(
            b'<!DOCTYPE html><html><body>Typical plain text response to TLS client hello message</body></html>'
        )


class L7ServerTlsPlainTextResponse(L7ServerTls):
    @staticmethod
    def _get_handshake_class(l4_transfer):
        return TlsServerPlainTextResponse


class TlsServerCloseDuringHandshake(TlsServerHandshake):
    def _process_handshake_message(self, message, last_handshake_message_type):
        self.l4_transfer.send(
            TlsRecord(
                TlsAlertMessage(TlsAlertLevel.WARNING, TlsAlertDescription.USER_CANCELED).compose(),
                content_type=TlsContentType.ALERT,
            ).compose()[:TlsRecord.HEADER_SIZE],
        )


class L7ServerTlsCloseDuringHandshake(L7ServerTls):
    @staticmethod
    def _get_handshake_class(l4_transfer):
        return TlsServerCloseDuringHandshake


class TlsServerOneMessageInMultipleRecords(TlsServerHandshake):
    SERVER_HELLO_MESSAGE = TlsHandshakeServerHello(
        protocol_version=TlsProtocolVersionFinal(TlsVersion.TLS1_2),
        random=TlsHandshakeHelloRandom(datetime.datetime.fromtimestamp(0)),
        cipher_suite=TlsCipherSuite.TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        extensions=TlsExtensionsClient([]),
    )

    def _process_handshake_message(self, message, last_handshake_message_type):
        for hello_message_byte in self.SERVER_HELLO_MESSAGE.compose():
            self.l4_transfer.send(TlsRecord(fragment=six.int2byte(hello_message_byte)).compose())


class L7ServerTlsOneMessageInMultipleRecords(L7ServerTls):
    @staticmethod
    def _get_handshake_class(l4_transfer):
        return TlsServerOneMessageInMultipleRecords


class TlsServerAlert(TlsServerHandshake):
    def _get_alert_message(self):
        raise NotImplementedError()

    def _process_handshake_message(self, message, last_handshake_message_type):
        handshake_message_bytes = self._get_alert_message().compose()
        self.l4_transfer.send(TlsRecord(handshake_message_bytes + handshake_message_bytes).compose())


class L7ServerTlsAlert(L7ServerTls):
    @staticmethod
    def _get_handshake_class(l4_transfer):
        return TlsServerAlert

# -*- coding: utf-8 -*-

import ftplib
import imaplib
import poplib
import smtplib
import socket
import unittest
try:
    from unittest import mock
except ImportError:
    import mock

from cryptoparser.common.exception import NotEnoughData
from cryptoparser.tls.ciphersuite import SslCipherKind
from cryptoparser.tls.record import TlsRecord, SslRecord
from cryptoparser.tls.subprotocol import (
    SslErrorMessage,
    SslErrorType,
    SslHandshakeClientHello,
    SslHandshakeServerHello,
    SslMessageType,
    TlsAlertDescription,
    TlsAlertLevel,
    TlsAlertMessage,
    TlsContentType,
)
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal

from cryptolyzer.tls.client import (
    ClientIMAP,
    L7ClientTls,
    L7ClientTlsBase,
    SslError,
    SslHandshakeClientHelloAnyAlgorithm,
    TlsAlert,
    TlsHandshakeClientHelloAnyAlgorithm
)
from cryptolyzer.common.exception import (
    NetworkError,
    NetworkErrorType,
    SecurityError,
    SecurityErrorType
)
from cryptolyzer.tls.server import L7ServerTlsBase, L7ServerTls, TlsServerHandshake, SslServerHandshake
from cryptolyzer.common.transfer import L4ClientTCP
from cryptolyzer.tls.versions import AnalyzerVersions

from .classes import L7ServerTlsTest


class L7ServerTlsFatalResponse(TlsServerHandshake):
    def _process_handshake_message(self, record, last_handshake_message_type):
        self._send_alert(TlsAlertLevel.WARNING, TlsAlertDescription.USER_CANCELED)
        raise StopIteration()


class L7ServerSslPlainTextResponse(SslServerHandshake):
    def _process_handshake_message(self, record, last_handshake_message_type):
        self._l4_transfer.send(b'\x00\x01\x00\xff\x00')
        raise StopIteration()


class TestTlsAlert(unittest.TestCase):
    def test_repr_and_str(self):
        alert = TlsAlert(TlsAlertDescription.HANDSHAKE_FAILURE)
        self.assertEqual(str(alert), repr(alert))


class TestL7ClientBase(unittest.TestCase):
    @staticmethod
    def get_result(proto, host, port, timeout=None, ip=None):
        analyzer = AnalyzerVersions()
        l7_client = L7ClientTlsBase.from_scheme(proto, host, port, timeout, ip=ip)
        result = analyzer.analyze(l7_client, TlsProtocolVersionFinal(TlsVersion.TLS1_2))
        return result


class L7ClientTlsMock(L7ClientTls):
    pass


class TestL7ClientTlsBase(TestL7ClientBase):
    def test_error_unexisting_hostname(self):
        with self.assertRaises(NetworkError) as context_manager:
            self.get_result('tls', 'unexisting.hostname', 443)
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_ADDRESS)

    @mock.patch.object(socket, 'getaddrinfo', return_value=[])
    def test_error_hostname_with_no_address(self, _):
        with self.assertRaises(NetworkError) as context_manager:
            self.get_result('tls', 'hostname.with.no.address', 443)
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_ADDRESS)

    def test_error_invalid_address(self):
        with self.assertRaises(NetworkError) as context_manager:
            self.get_result('tls', 'badssl.com', 443, ip='not.an.ip.address')
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_ADDRESS)

    @mock.patch.object(L4ClientTCP, '_send', return_value=0)
    def test_error_send(self, _):
        with self.assertRaises(NetworkError) as context_manager:
            self.get_result('tls', 'badssl.com', 443)
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_CONNECTION)

    def test_error_unsupported_scheme(self):
        with self.assertRaises(ValueError):
            self.get_result('unsupported_scheme', 'badssl.com', 443)

    def test_error_connection_timeout_on_close(self):
        analyzer = AnalyzerVersions()
        l7_client = L7ClientTlsMock('badssl.com', 443)
        self.assertEqual(
            analyzer.analyze(l7_client, TlsProtocolVersionFinal(TlsVersion.TLS1_2)).versions,
            [
                TlsProtocolVersionFinal(TlsVersion.TLS1_0),
                TlsProtocolVersionFinal(TlsVersion.TLS1_1),
                TlsProtocolVersionFinal(TlsVersion.TLS1_2),
            ]
        )

    def test_tls_client(self):
        self.assertEqual(
            self.get_result('tls', 'badssl.com', 443).versions,
            [
                TlsProtocolVersionFinal(TlsVersion.TLS1_0),
                TlsProtocolVersionFinal(TlsVersion.TLS1_1),
                TlsProtocolVersionFinal(TlsVersion.TLS1_2),
            ]
        )

    def test_https_client(self):
        self.assertEqual(
            self.get_result('https', 'badssl.com', None).versions,
            [
                TlsProtocolVersionFinal(TlsVersion.TLS1_0),
                TlsProtocolVersionFinal(TlsVersion.TLS1_1),
                TlsProtocolVersionFinal(TlsVersion.TLS1_2),
            ]
        )


class TestClientPOP3(TestL7ClientBase):
    @mock.patch.object(poplib.POP3, '_shortcmd', return_value=b'-ERR')
    def test_error_unsupported_starttls(self, _):
        self.assertEqual(self.get_result('pop3', 'pop3.comcast.net', None, 10).versions, [])

    @mock.patch.object(poplib.POP3, '__init__', side_effect=poplib.error_proto)
    def test_error_pop3_error_on_connect(self, _):
        self.assertEqual(self.get_result('pop3', 'pop3.comcast.net', None, 10).versions, [])

    @mock.patch.object(poplib.POP3, 'quit', side_effect=poplib.error_proto)
    def test_error_pop3_error_on_quit(self, _):
        self.assertEqual(
            self.get_result('pop3', 'pop3.comcast.net', None, 10).versions,
            [TlsProtocolVersionFinal(version) for version in [TlsVersion.TLS1_0, TlsVersion.TLS1_1, TlsVersion.TLS1_2]]
        )

    def test_pop3_client(self):
        self.assertEqual(
            self.get_result('pop3', 'pop3.comcast.net', None, 10).versions,
            [TlsProtocolVersionFinal(version) for version in [TlsVersion.TLS1_0, TlsVersion.TLS1_1, TlsVersion.TLS1_2]]
        )

    def test_pop3s_client(self):
        self.assertEqual(
            self.get_result('pop3s', 'pop.gmail.com', None).versions,
            [TlsProtocolVersionFinal(version) for version in [TlsVersion.TLS1_0, TlsVersion.TLS1_1, TlsVersion.TLS1_2]]
        )


class TestClientIMAP(TestL7ClientBase):
    @mock.patch.object(
        ClientIMAP, '_capabilities',
        mock.PropertyMock(return_value=(
            'IMAP4REV1',
            'LITERAL+',
            'SASL-IR',
            'LOGIN-REFERRALS',
            'ID',
            'ENABLE',
            'IDLE',
            'LOGINDISABLED',
        )),
        create=True
    )
    def test_error_unsupported_starttls(self):
        self.assertEqual(self.get_result('imap', 'imap.comcast.net', None, 10).versions, [])

    @mock.patch.object(imaplib.IMAP4, '__init__', side_effect=imaplib.IMAP4.error)
    def test_error_imap_error(self, _):
        self.assertEqual(self.get_result('imap', 'imap.comcast.net', None, 10).versions, [])

    @mock.patch.object(
        imaplib.IMAP4, 'xatom',
        return_value=[('BAD', 'command unknown or arguments invalid'), mock.DEFAULT]
    )
    @mock.patch.object(imaplib.IMAP4, 'shutdown', side_effect=imaplib.IMAP4.error)
    def test_error_starttls_error(self, _, __):
        self.assertEqual(self.get_result('imap', 'imap.comcast.net', None, 10).versions, [])

    def test_imap_client(self):
        self.assertEqual(
            self.get_result('imap', 'imap.comcast.net', None, 10).versions,
            [TlsProtocolVersionFinal(version) for version in [TlsVersion.TLS1_0, TlsVersion.TLS1_1, TlsVersion.TLS1_2]]
        )

    def test_imaps_client(self):
        self.assertEqual(
            self.get_result('imaps', 'imap.gmail.com', None).versions,
            [TlsProtocolVersionFinal(version) for version in [TlsVersion.TLS1_0, TlsVersion.TLS1_1, TlsVersion.TLS1_2]]
        )


class TestClientSMTP(TestL7ClientBase):
    @mock.patch.object(smtplib.SMTP, 'has_extn', return_value=False)
    def test_error_unsupported_starttls(self, _):
        self.assertEqual(self.get_result('smtp', 'smtp.gmail.com', None).versions, [])

    @mock.patch.object(smtplib.SMTP, 'connect', side_effect=smtplib.SMTPException)
    def test_error_smtp_error_on_connect(self, _):
        self.assertEqual(self.get_result('smtp', 'smtp.gmail.com', None).versions, [])

    @mock.patch.object(smtplib.SMTP, 'quit', side_effect=smtplib.SMTPServerDisconnected)
    def test_error_smtp_error_on_quit(self, _):
        self.assertEqual(
            self.get_result('smtp', 'smtp.gmail.com', None).versions,
            [TlsProtocolVersionFinal(version) for version in [TlsVersion.TLS1_0, TlsVersion.TLS1_1, TlsVersion.TLS1_2]]
        )

    @mock.patch.object(smtplib.SMTP, 'docmd', return_value=(454, 'TLS not available due to temporary reason'))
    def test_error_starttls_error(self, _):
        self.assertEqual(self.get_result('smtp', 'smtp.gmail.com', None).versions, [])

    def test_smtp_client(self):
        self.assertEqual(
            self.get_result('smtp', 'smtp.gmail.com', None).versions,
            [TlsProtocolVersionFinal(version) for version in [TlsVersion.TLS1_0, TlsVersion.TLS1_1, TlsVersion.TLS1_2]]
        )

    def test_smtps_client(self):
        self.assertEqual(
            self.get_result('smtps', 'smtp.gmail.com', None).versions,
            [TlsProtocolVersionFinal(version) for version in [TlsVersion.TLS1_0, TlsVersion.TLS1_1, TlsVersion.TLS1_2]]
        )


class TestClientFTP(TestL7ClientBase):
    @mock.patch.object(ftplib.FTP, '__init__', side_effect=ftplib.error_reply)
    def test_error_ftplib_error(self, _):
        self.assertEqual(self.get_result('ftp', 'ftp.cert.dfn.de', None).versions, [])

    @mock.patch.object(ftplib.FTP, 'sendcmd', return_value='502 Command not implemented')
    def test_error_unsupported_starttls(self, _):
        self.assertEqual(self.get_result('ftp', 'ftp.cert.dfn.de', None).versions, [])

    @mock.patch.object(ftplib.FTP, 'connect', return_value='534 Could Not Connect to Server - Policy Requires SSL')
    @mock.patch.object(ftplib.FTP, 'quit', side_effect=ftplib.error_perm)
    def test_error_ftp_error_on_connect(self, _, __):
        self.assertEqual(self.get_result('ftp', 'ftp.cert.dfn.de', None).versions, [])

    @mock.patch.object(ftplib.FTP, 'quit', side_effect=ftplib.error_reply)
    def test_error_ftp_error_on_quit(self, _):
        self.assertEqual(
            self.get_result('ftp', 'ftp.cert.dfn.de', None).versions,
            [TlsProtocolVersionFinal(version) for version in [TlsVersion.TLS1_1, TlsVersion.TLS1_2]]
        )

    def test_ftp_client(self):
        self.assertEqual(
            self.get_result('ftp', 'ftp.cert.dfn.de', None).versions,
            [TlsProtocolVersionFinal(version) for version in [TlsVersion.TLS1_1, TlsVersion.TLS1_2]]
        )

    def test_ftps_client(self):
        self.assertEqual(
            self.get_result('ftps', 'ftp.mrxs.de', None).versions,
            [TlsProtocolVersionFinal(version) for version in [TlsVersion.TLS1_0, TlsVersion.TLS1_1, TlsVersion.TLS1_2]]
        )


class TestClientDoH(TestL7ClientBase):
    def test_doh_client(self):
        self.assertEqual(
            self.get_result('doh', 'dns.google', None).versions,
            [TlsProtocolVersionFinal(version) for version in [TlsVersion.TLS1_2]]
        )


class TestTlsClientHandshake(TestL7ClientBase):
    @mock.patch.object(
        TlsRecord, 'messages', mock.PropertyMock(
            return_value=[TlsAlertMessage(TlsAlertLevel.WARNING, TlsAlertDescription.CLOSE_NOTIFY)]
        )
    )
    @mock.patch.object(
        TlsRecord, 'content_type', mock.PropertyMock(return_value=TlsContentType.ALERT)
    )
    def test_error_always_alert_wargning(self):
        with self.assertRaises(TlsAlert) as context_manager:
            self.get_result('https', 'badssl.com', None)
        self.assertEqual(context_manager.exception.description, TlsAlertDescription.CLOSE_NOTIFY)

    @mock.patch.object(
        TlsRecord, 'content_type', mock.PropertyMock(return_value=TlsContentType.CHANGE_CIPHER_SPEC)
    )
    def test_error_non_handshake_message(self):
        with self.assertRaises(TlsAlert) as context_manager:
            self.assertEqual(self.get_result('https', 'badssl.com', None).versions, [])
        self.assertEqual(context_manager.exception.description, TlsAlertDescription.UNEXPECTED_MESSAGE)

    @mock.patch.object(L7ServerTlsBase, '_get_handshake_class', return_value=L7ServerTlsFatalResponse)
    def test_error_fatal_alert(self, _):
        threaded_server = L7ServerTlsTest(
            L7ServerTls('localhost', 0, timeout=1),
            fallback_to_ssl=False
        )
        threaded_server.wait_for_server_listen()
        l7_client = L7ClientTlsBase('localhost', threaded_server.l7_server.port)

        client_hello = TlsHandshakeClientHelloAnyAlgorithm(TlsProtocolVersionFinal(TlsVersion.TLS1_2), 'localhost')
        with self.assertRaises(NetworkError) as context_manager:
            l7_client.do_tls_handshake(client_hello)
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_RESPONSE)

    @mock.patch.object(L7ServerTlsBase, '_get_handshake_class', return_value=L7ServerSslPlainTextResponse)
    def test_error_plain_text_response(self, _):
        threaded_server = L7ServerTlsTest(
            L7ServerTls('localhost', 0, timeout=1),
            fallback_to_ssl=False
        )
        threaded_server.wait_for_server_listen()
        l7_client = L7ClientTlsBase('localhost', threaded_server.l7_server.port)

        client_hello = SslHandshakeClientHelloAnyAlgorithm()
        with self.assertRaises(SecurityError) as context_manager:
            l7_client.do_ssl_handshake(client_hello)
        self.assertEqual(context_manager.exception.error, SecurityErrorType.UNPARSABLE_MESSAGE)


class TestSslClientHandshake(unittest.TestCase):
    @mock.patch.object(
        SslRecord, 'parse_exact_size', return_value=SslRecord(SslErrorMessage(SslErrorType.NO_CIPHER_ERROR))
    )
    def test_error_ssl_error_replied(self, _):
        with self.assertRaises(SslError) as context_manager:
            L7ClientTlsBase('badssl.com', 443).do_ssl_handshake(SslHandshakeClientHello(SslCipherKind))
        self.assertEqual(context_manager.exception.error, SslErrorType.NO_CIPHER_ERROR)

    @mock.patch.object(L4ClientTCP, 'receive', side_effect=NotEnoughData(100))
    @mock.patch.object(
        L4ClientTCP, 'buffer',
        mock.PropertyMock(side_effect=[
            b'',
            True,
            b'some text content',
            b'some text content',
            b'some text content'
        ])
    )
    def test_error_unparsable_response(self, _):
        with self.assertRaises(SecurityError) as context_manager:
            L7ClientTlsBase('badssl.com', 443).do_ssl_handshake(SslHandshakeClientHello(SslCipherKind))
        self.assertEqual(context_manager.exception.error, SecurityErrorType.PLAIN_TEXT_MESSAGE)

    @mock.patch.object(L4ClientTCP, 'receive', side_effect=NotEnoughData(100))
    @mock.patch.object(
        L4ClientTCP, 'buffer',
        mock.PropertyMock(side_effect=[
            b'',
            True,
            TlsRecord([
                TlsAlertMessage(TlsAlertLevel.FATAL, TlsAlertDescription.CLOSE_NOTIFY)
            ]).compose()
        ])
    )
    def test_error_unacceptable_tls_error_replied(self, _):
        with self.assertRaises(NetworkError) as context_manager:
            L7ClientTlsBase('badssl.com', 443).do_ssl_handshake(SslHandshakeClientHello(SslCipherKind))
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_CONNECTION)

    @mock.patch.object(L4ClientTCP, 'receive', return_value=b'')
    @mock.patch.object(
        SslRecord, 'parse_exact_size', side_effect=[
            SslRecord(SslHandshakeServerHello(b'', SslCipherKind)),
            SslRecord(SslErrorMessage(SslErrorType.NO_CERTIFICATE_ERROR)),
        ]
    )
    def test_multiple_messages(self, _, __):
        with self.assertRaises(SslError) as context_manager:
            L7ClientTlsBase('badssl.com', 443).do_ssl_handshake(
                SslHandshakeClientHello(SslCipherKind),
                SslMessageType.ERROR
            )
        self.assertEqual(context_manager.exception.error, SslErrorType.NO_CERTIFICATE_ERROR)

# -*- coding: utf-8 -*-

try:
    from unittest import mock
except ImportError:
    import mock

from cryptoparser.tls.subprotocol import TlsAlertDescription, SslErrorType
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionDraft, TlsProtocolVersionFinal, SslProtocolVersion

from cryptolyzer.common.exception import SecurityError, SecurityErrorType

from cryptolyzer.tls.client import L7ClientTlsBase, SslError
from cryptolyzer.tls.exception import TlsAlert
from cryptolyzer.tls.server import L7ServerTls, TlsServerConfiguration
from cryptolyzer.tls.versions import AnalyzerVersions

from .classes import TestTlsCases, L7ServerTlsTest, L7ServerTlsPlainTextResponse


class TestSslVersions(TestTlsCases.TestTlsBase):
    @staticmethod
    def get_result(host, port, protocol_version=None, timeout=None, ip=None):
        analyzer = AnalyzerVersions()
        l7_client = L7ClientTlsBase.from_scheme('tls', host, port, timeout, ip)
        result = analyzer.analyze(l7_client, SslProtocolVersion())
        return result

    @staticmethod
    def create_server(configuration=None):
        threaded_server = L7ServerTlsTest(L7ServerTls('localhost', 0, timeout=0.2, configuration=configuration))
        threaded_server.wait_for_server_listen()
        return threaded_server

    @mock.patch.object(
        L7ClientTlsBase, 'do_ssl_handshake',
        side_effect=SslError(SslErrorType.NO_CERTIFICATE_ERROR)
    )
    def test_error_ssl_error(self, _):
        with self.assertRaises(SslError) as context_manager:
            self.get_result('badssl.com', 443)
        self.assertEqual(context_manager.exception.error, SslErrorType.NO_CERTIFICATE_ERROR)

    @mock.patch.object(
        L7ClientTlsBase, 'do_ssl_handshake',
        side_effect=SecurityError(SecurityErrorType.UNPARSABLE_MESSAGE)
    )
    def test_error_security_error(self, _):
        self.assertEqual(
            self.get_result('badssl.com', 443).versions,
            [
                TlsProtocolVersionFinal(TlsVersion.TLS1_0),
                TlsProtocolVersionFinal(TlsVersion.TLS1_1),
                TlsProtocolVersionFinal(TlsVersion.TLS1_2),
            ]
        )

    def test_ssl_2(self):
        threaded_server = self.create_server(TlsServerConfiguration(
            protocol_versions=[TlsProtocolVersionFinal(TlsVersion.SSL3), ],
            fallback_to_ssl=True
        ))
        self.assertEqual(
            self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port).versions,
            [SslProtocolVersion(), TlsProtocolVersionFinal(TlsVersion.SSL3), ]
        )

    def test_versions(self):
        threaded_server = L7ServerTlsTest(
            L7ServerTls('localhost', 0, timeout=0.5),
        )
        threaded_server.start()

        server_port = threaded_server.l7_server.l4_transfer.bind_port

        self.assertEqual(
            self.get_result('localhost', server_port).versions,
            [
                TlsProtocolVersionFinal(TlsVersion.SSL3),
                TlsProtocolVersionFinal(TlsVersion.TLS1_0),
                TlsProtocolVersionFinal(TlsVersion.TLS1_1),
                TlsProtocolVersionFinal(TlsVersion.TLS1_2),
            ]
        )

    def test_tls_alert_response_to_ssl_handshake(self):
        result = self.get_result('www.google.com', 443)
        self.assertEqual(
            result.versions,
            [
                TlsProtocolVersionFinal(version)
                for version in [TlsVersion.TLS1_0, TlsVersion.TLS1_1, TlsVersion.TLS1_2, TlsVersion.TLS1_3, ]
            ]
        )


class TestTlsVersions(TestTlsCases.TestTlsBase):
    @mock.patch.object(
        L7ClientTlsBase, 'do_tls_handshake',
        side_effect=TlsAlert(TlsAlertDescription.UNRECOGNIZED_NAME),
    )
    def test_error_tls_alert_unrecognized_name(self, _):
        self.assertEqual(self.get_result('badssl.com', 443).versions, [])

    @staticmethod
    def get_result(host, port, protocol_version=None, timeout=None, ip=None):
        analyzer = AnalyzerVersions()
        l7_client = L7ClientTlsBase.from_scheme('tls', host, port, timeout, ip)
        analyzer_result = analyzer.analyze(l7_client, protocol_version)

        return analyzer_result

    def test_tls_1_0_only(self):
        self.assertEqual(
            self.get_result('tls-v1-0.badssl.com', 1010).versions,
            [TlsProtocolVersionFinal(TlsVersion.TLS1_0)]
        )

    def test_tls_1_1_only(self):
        self.assertEqual(
            self.get_result('tls-v1-1.badssl.com', 1011).versions,
            [TlsProtocolVersionFinal(TlsVersion.TLS1_1)]
        )

    def test_tls_1_2_only(self):
        self.assertEqual(
            self.get_result('tls-v1-2.badssl.com', 1012).versions,
            [TlsProtocolVersionFinal(TlsVersion.TLS1_2)]
        )

    def test_tls_1_2_3(self):
        self.assertEqual(
            self.get_result('badssl.com', 443).versions,
            [TlsProtocolVersionFinal(version) for version in [TlsVersion.TLS1_0, TlsVersion.TLS1_1, TlsVersion.TLS1_2]]
        )

    def test_tls_1_3(self):
        self.assertEqual(
            self.get_result('www.cloudflare.com', 443).versions,
            [
                TlsProtocolVersionFinal(version)
                for version in [TlsVersion.TLS1_0, TlsVersion.TLS1_1, TlsVersion.TLS1_2, TlsVersion.TLS1_3, ]
            ]
        )

    def test_tls_1_3_draft(self):
        self.assertEqual(
            self.get_result('www.internet.org', 443).versions,
            [
                TlsProtocolVersionFinal(TlsVersion.TLS1_0),
                TlsProtocolVersionFinal(TlsVersion.TLS1_1),
                TlsProtocolVersionFinal(TlsVersion.TLS1_2),
                TlsProtocolVersionDraft(23),
                TlsProtocolVersionDraft(26),
                TlsProtocolVersionDraft(28),
                TlsProtocolVersionFinal(TlsVersion.TLS1_3),
            ]
        )

    def test_ecdsa_only(self):
        self.assertEqual(
            self.get_result('ecc256.badssl.com', 443).versions,
            [TlsProtocolVersionFinal(version) for version in [TlsVersion.TLS1_0, TlsVersion.TLS1_1, TlsVersion.TLS1_2]]
        )

    def test_with_client_auth(self):
        self.assertEqual(
            self.get_result('client.badssl.com', 443).versions,
            [TlsProtocolVersionFinal(version) for version in [TlsVersion.TLS1_0, TlsVersion.TLS1_1, TlsVersion.TLS1_2]]
        )

    def test_plain_text_response(self):
        threaded_server = L7ServerTlsTest(
            L7ServerTlsPlainTextResponse('localhost', 0, timeout=0.2),
        )
        threaded_server.start()
        self.assertEqual(self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port).versions, [])

#!/usr/bin/env python
# -*- coding: utf-8 -*-

from cryptoparser.tls.extension import TlsSignatureAndHashAlgorithm, TlsExtensionSignatureAlgorithms
from cryptoparser.tls.subprotocol import TlsAlertDescription

from cryptolyzer.common.analyzer import AnalyzerTlsBase
from cryptolyzer.common.exception import NetworkError
from cryptolyzer.common.result import AnalyzerResultTls, AnalyzerTargetTls
from cryptolyzer.tls.client import (
    TlsAlert,
    TlsHandshakeClientHelloAuthenticationECDSA,
    TlsHandshakeClientHelloAuthenticationDSS,
    TlsHandshakeClientHelloAuthenticationRSA,
)


class AnalyzerResultSigAlgos(AnalyzerResultTls):
    def __init__(self, target, sig_algos):
        super(AnalyzerResultSigAlgos, self).__init__(target)

        self.sig_algos = sig_algos


class AnalyzerSigAlgos(AnalyzerTlsBase):
    @classmethod
    def get_name(cls):
        return 'sigalgos'

    @classmethod
    def get_help(cls):
        return 'Check which signature and hash algorithm combinations supported by the server(s)'

    def analyze(self, l7_client, protocol_version):
        supported_algorithms = []
        client_hellos = [
            TlsHandshakeClientHelloAuthenticationDSS(l7_client.address),
            TlsHandshakeClientHelloAuthenticationECDSA(l7_client.address),
            TlsHandshakeClientHelloAuthenticationRSA(l7_client.address),
        ]
        for client_hello in client_hellos:
            authentication = client_hello.cipher_suites[0].value.authentication

            for algorithm in TlsSignatureAndHashAlgorithm:
                if algorithm.value.signature_algorithm != authentication:
                    continue

                for extension in client_hello.extensions:
                    if isinstance(extension, TlsExtensionSignatureAlgorithms):
                        extension = TlsExtensionSignatureAlgorithms([algorithm, ])

                try:
                    l7_client.do_tls_handshake(client_hello)
                except TlsAlert as e:
                    acceptable_alerts = [TlsAlertDescription.HANDSHAKE_FAILURE, TlsAlertDescription.ILLEGAL_PARAMETER]
                    if e.description not in acceptable_alerts:
                        raise e
                except NetworkError:
                    pass
                else:
                    supported_algorithms.append(algorithm)

        return AnalyzerResultSigAlgos(
            AnalyzerTargetTls.from_l7_client(l7_client, protocol_version),
            supported_algorithms
        )

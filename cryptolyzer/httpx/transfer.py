# -*- coding: utf-8 -*-

import abc
import attr
import urllib3
import six
import warnings

from cryptolyzer.common.exception import NetworkError, NetworkErrorType


@attr.s
class HttpHandshakeBase(object):
    response = attr.ib(init=False, validator=attr.validators.instance_of(urllib3.response.HTTPResponse))

    def _get_connection_extra_args(self):
        return {}

    def _ignore_warnings(self):
        pass

    @property
    def raw_headers(self):
        raw_headers = '\r\n'.join([
            '{}: {}'.format(name, value)
            for name, value in self.response.headers.items()
        ]) + '\r\n'

        if len(self.response.headers) == 1:
            raw_headers += '\r\n'

        return raw_headers.encode('ascii')

    def do_handshake(self, transfer):
        url = str(transfer.uri)
        try:
            extra_args = self._get_connection_extra_args()
            conn = urllib3.PoolManager().connection_from_url(url, extra_args)
            with warnings.catch_warnings():
                self._ignore_warnings()
                self.response = conn.request(
                    'HEAD', url,
                    timeout=transfer.timeout, redirect=False,
                )
        except urllib3.exceptions.NewConnectionError as e:
            six.raise_from(NetworkError(NetworkErrorType.NO_CONNECTION), e)
        except urllib3.exceptions.HTTPError as e:
            raise e
            six.raise_from(NetworkError(NetworkErrorType.NO_RESPONSE), e)

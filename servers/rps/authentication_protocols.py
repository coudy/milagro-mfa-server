from tornado.log import app_log as log
from mpin_utils import secrets
from mpin_utils.common import Time


class NotSupportedProtocolException(Exception):
    pass


class TwoPass(object):
    def __init__(self, storage, application):
        self.storage = storage
        self.application = application

    def pass1(self, receive_data, request_info, pass1_expires_time):

        try:
            mpin_id = receive_data['mpin_id'].decode("hex")
            ut_hex = receive_data['UT']
            u_hex = receive_data['U']
        except KeyError as ex:
            reason = "Invalid data received. %s argument missing" % ex.message
            log.error("%s %s" % (request_info, reason))
            return_data = {
                'message': reason,
                'status_code': 403
            }

            return True, return_data

        log.debug("%s %s" % (request_info, receive_data))

        # Server generates Random number Y and sends it to Client
        try:
            y_hex = self.application.server_secret.get_pass1_value()
        except secrets.SecretsError as e:
            return True, {'message': e.message, 'status_code': 500}

        # Store Pass1 values
        self.storage.add(
            expire_time=Time.syncedISO(seconds=pass1_expires_time),
            stage="pass1",
            mpinId=mpin_id.encode('hex'),
            ut=ut_hex,
            u=u_hex,
            y=y_hex,
        )

        log.info("%s Stored Pass1 values" % request_info)

        reason = "OK"
        return_data = {
            'y': y_hex,
            'pass': 1,
            'message': reason,
            'status_code': 200
        }
        log.debug("%s %s" % (request_info, return_data))

        return False, return_data

# Map the protocol name to class name
supportedProtocolsMapping = {
    '2pass': TwoPass
}


class AuthenticationProtocol(object):
    @staticmethod
    def factory(protocol, storage, application):
        try:
            return supportedProtocolsMapping[protocol](storage, application)
        except KeyError:
            raise NotSupportedProtocolException("The protocol '%s' is not supported" % (protocol,))

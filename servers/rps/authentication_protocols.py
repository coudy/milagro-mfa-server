import tornado
from tornado.log import app_log as log
from mpin_utils import secrets
from mpin_utils.common import Time, SIGNATURE_EXPIRES_OFFSET_SECONDS
from base_handlers import BaseHandler

from constants import VERSION, PASS1_EXPIRES_TIME


class NotSupportedProtocolException(Exception):
    pass

###
# Two Pass protocol ###
###


# AUTHENTICATION HANDLER
class Pass1Handler(BaseHandler):
    """
    ..  apiTextStart

    *Description*

      Implements the first pass of the M-Pin Protocol

    *URL structure*

      ``/pass1``

    *Version*

      0.3

    *HTTP Request Method*

      POST

    *Request Data*

      JSON request::

        {
          "mpin_id":  "7b22...227d",
          "U":    "0409...3d9c",
          "UT":   "0402...d1d1",
          "pass" : 1
        }

      mpin_id is the hex encoded M-Pin ID, U is x.hash(mpin_id) and UT is
      x.(hash(mpin_id) + hash(data||hash(mpin_id)))

    *Returns*

      JSON response::

        {
          "y" : "212a...8d08",
          "version" : "0.3",
          "message" : "OK",
          "pass" : 1
        }

      y  is a 256 bit random value.

    *Status-Codes and Response-Phrases*

      ::

        Status-Code          Response-Phrase

        200                  OK
        403                  Invalid data received. <argument> argument missing
        403                  Invalid data received. No JSON object could be decoded
        403                  Invalid data received. Non-hexadecimal digit found
        500                  Failed to generate y
        500                  Failed to add pass one to memory

    ..  apiTextEnd

    """
    def post(self):
        # Remote request information
        if 'User-Agent' in self.request.headers.keys():
            UA = self.request.headers['User-Agent']
        else:
            UA = 'unknown'
        request_info = '%s %s %s %s ' % (self.request.path, self.request.remote_ip, UA, Time.syncedISO())

        try:
            receive_data = tornado.escape.json_decode(self.request.body)
        except (ValueError, TypeError) as ex:
            reason = "Invalid data received. %s" % ex.message
            log.error("%s %s" % (request_info, reason))
            self.set_status(403, reason=reason)
            self.content_type = 'application/json'
            self.write({'version': VERSION, 'message': reason})
            self.finish()
            return

        error, return_data = self.pass1_logic(receive_data, request_info, PASS1_EXPIRES_TIME)
        return_data['version'] = VERSION

        self.content_type = 'application/json'
        self.set_status(return_data.pop('status_code'), reason=return_data['message'])
        self.write(return_data)
        self.finish()
        return

    def pass1_logic(self, receive_data, request_info, pass1_expires_time):

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


class Pass2Handler(BaseHandler):
    """
    ..  apiTextStart

    *Description*

      Implements the second pass of the M-Pin Protocol. The result will be the authOTP.
      At this point the authentication token has also been written to the RPS.
      An authOTT will always be returned even if authentication fails.

    *URL structure*

      ``/pass2``

    *Version*

      0.3

    *HTTP Request Method*

      POST

    *Request Data*

      JSON request::

        {
          "WID" : "123456"
          "V" : "0411...05f6a",
          "pass" : 2,
          "OTP" : <1||0>
        }

      WID is web identifier used for mobile authentication
      When OTP is set to one this indicates that the radius OTP should be
      generated.  V is a parameter used to perform the final step of the M-Pin
      algorithm.

    *Returns*

      JSON response::

        {
          "OTP": "155317",
          "authOTT": "31ba0ed5efb75d91ef69a2b7eb1d3a26",
          "pass": 2,
          "version": "0.3"
        }

      OTP is the radius one time password. authOTT is the password used to log into the
      Customer's website.

    *Status-Codes and Response-Phrases*

      ::

        Status-Code          Response-Phrase

        200                  OK
        403                  Invalid data received. <argument> argument missing
        403                  Invalid data received. No JSON object could be decoded
        403                  Invalid data received. Non-hexadecimal digit found
        500                  Pass one data is not in memory

    ..  apiTextEnd

    """
    @tornado.gen.coroutine
    def post(self):
        # Remote request information
        if 'User-Agent' in self.request.headers.keys():
            UA = self.request.headers['User-Agent']
        else:
            UA = 'unknown'
        request_info = '%s %s %s %s ' % (self.request.path, self.request.remote_ip, UA, Time.syncedISO())

        # START
        try:
            receive_data = tornado.escape.json_decode(self.request.body)
            mpin_id_hex = receive_data['mpin_id']
            mpin_id = mpin_id_hex.decode('hex')
            WID = receive_data['WID']
            OTPEn = receive_data['OTP']
            v_data = receive_data['V'].decode("hex")
        except KeyError as ex:
            reason = "Invalid data received. %s argument missing" % ex.message
            log.error("%s %s" % (request_info, reason))
            self.set_status(403, reason=reason)
            self.content_type = 'application/json'
            self.write({'version': VERSION, 'message': reason})
            self.finish()
            return
        except (ValueError, TypeError) as ex:
            reason = "Invalid data received. %s" % ex.message
            log.error("%s %s" % (request_info, reason))
            self.set_status(403, reason=reason)
            self.content_type = 'application/json'
            self.write({'version': VERSION, 'message': reason})
            self.finish()
            return
        log.debug("%s %s" % (request_info, receive_data))

        # Get pass one values
        pass1Value = self.storage.find(stage="pass1", mpinId=mpin_id_hex)

        if pass1Value:
            u = pass1Value.u.decode("hex")
            ut = pass1Value.ut.decode("hex")
            y = pass1Value.y.decode("hex")
        else:
            reason = "Invalid pass one data"
            log.error("%s %s" % (request_info, reason))
            self.set_status(500, reason=reason)
            self.content_type = 'application/json'
            self.write({'version': VERSION, 'message': reason})
            self.finish()
            return
        log.info("%s loaded Pass1 values" % request_info)

        # Generate OTP value
        if int(OTPEn) == 1:
            OTP = "{0:06d}".format(
                secrets.generate_otp(self.application.server_secret.rng))
        else:
            OTP = '0'

        log.info("%s generate OTP" % request_info)

        successCode = self.application.server_secret.validate_pass2_value(
            mpin_id, u, ut, y, v_data)

        pinError = 0
        pinErrorCost = 0

        # Authentication Token expiry
        expires = Time.syncedISO(seconds=SIGNATURE_EXPIRES_OFFSET_SECONDS)

        # Form Authentication token
        token = {
            "mpin_id": mpin_id,
            "mpin_id_hex": mpin_id_hex,
            "successCode": successCode,
            "pinError": pinError,
            "pinErrorCost": pinErrorCost,
            "expires": expires,
            "WID": WID,
            "OTP": OTP
        }
        log.debug("%s M-Pin Auth token: %s" % (request_info, token))

        # Form authentication 128 hex encoded One Time Password
        authOTT = secrets.generate_auth_ott(self.application.server_secret.rng)

        # Form message to return to client #
        return_data = {
            'version': VERSION,
            'pass': 2,
            'authOTT': authOTT
        }

        if int(OTPEn) == 1:
            return_data['OTP'] = OTP

        if WID != "0":
            # Login with mobile
            I = self.storage.find(stage="auth", wid=WID)

            wid_flow = "wid"
            flow = "mobile"

            # if not I:
            #     log.error("Invalid or expired access number: {0} for mpinid: {1}".format(WID, mpinId))
            #     self.set_status(412, reason="INVALID OR EXPIRED ACCESS NUMBER")
            #     self.finish()
            #     return

            if I:
                I.update(authOTT=authOTT, mpinid=mpin_id, authToken=token)

        else:
            wid_flow = "browser"

            if int(token.get("OTP", "0")) != 0:
                flow = "OTP"
            else:
                flow = "Browser"

            self.storage.add(
                expire_time=Time.ISOtoDateTime(expires),
                stage="auth",
                authOTT=authOTT,
                mpinId=mpin_id,
                wid="",
                webOTT=0,
                authToken=token
            )

        log.debug("New M-Pin Authentication token / {0}. Flow: {1}".format(wid_flow, flow))

        # Always send 200 to PIN Pad even if the user is not authenticated
        reason = "OK"
        log.debug("%s %s" % (request_info, return_data))
        self.set_status(200, reason=reason)
        self.content_type = 'application/json'
        self.write(return_data)
        self.finish()
        return

###
# End TwoPass Protocol ###
###


class AuthenticationProtocol(object):

    @staticmethod
    def handlers(protocol, rpsPrefix='rps'):
        """ Register handlers needed for the authentication protocol """
        supportedProtocolsHandlers = {
            '2pass': [
                    # Authentication
                    (r"/{0}/pass1".format(rpsPrefix), Pass1Handler),
                    (r"/{0}/pass2".format(rpsPrefix), Pass2Handler),
                ],
            '1pass': [],
        }

        return supportedProtocolsHandlers.get(protocol, [])

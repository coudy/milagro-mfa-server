import tornado.web
from tornado.log import app_log as log
from tornado.options import options

from constants import VERSION


# BASE HANDLERS
class BaseHandler(tornado.web.RequestHandler):

    def set_default_headers(self):
        try:
            log.debug("Origin Header %s" % self.request.headers['Origin'])
            if self.request.headers['Origin'] in options.allowOrigin:
                self.set_header("Access-Control-Allow-Origin", self.request.headers['Origin'])
            elif "*" in options.allowOrigin:
                self.set_header("Access-Control-Allow-Origin", "*")
        except:
            log.debug("Origin header not defined")
        self.set_header("Access-Control-Allow-Credentials", "true")
        self.set_header("Access-Control-Allow-Methods", "GET,PUT,POST,DELETE,OPTIONS")
        self.set_header("Access-Control-Allow-Headers",
                        "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, X-Requested-By, If-Modified-Since, X-File-Name, Cache-Control, WWW-Authenticate")

    def write_error(self, status_code, **kwargs):
        self.set_status(status_code, reason=self._reason)
        self.content_type = 'application/json'
        self.write({'version': VERSION, 'message': self._reason})

    def options(self, *args, **kwargs):
        self.set_status(200, reason="OK")
        self.content_type = 'application/json'
        self.write({'version': VERSION, 'message': "options request"})
        self.finish()
        return

    def finish(self, *args, **kwargs):
        if self._status_code == 401:
            self.set_header("WWW-Authenticate", "Authenticate")
        super(BaseHandler, self).finish(*args, **kwargs)

    @property
    def storage(self):
        return self.application.storage


class PrivateBaseHandler(BaseHandler):

    def prepare(self):
        # TODO: Check the remoteIP option
        # allow connections from whitelisted IP's
        # print self.request.remote_ip
        # self.set_status(404)
        # self.finish()
        pass

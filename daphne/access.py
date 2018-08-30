import datetime


class AccessLogGenerator(object):
    """
    Object that implements the Daphne "action logger" internal interface in
    order to provide an access log in something resembling NCSA format.
    """

    def __init__(self, stream):
        self.stream = stream

    def __call__(self, protocol, action, details):
        """
        Called when an action happens; use it to generate log entries.
        """
        # HTTP requests
        if protocol == "http" and action == "complete":
            self.write_entry(
                host=details["client"],
                date=datetime.datetime.now(),
                request_method="%(method)s" % details,
                request_path="%(path)s" % details,
                status=details["status"],
                length=details["size"],
                protocol=protocol,
            )
        # Websocket requests
        elif protocol == "websocket" and action == "connecting":
            self.write_entry(
                host=details["client"],
                date=datetime.datetime.now(),
                request_method="WSCONNECTING",
                request_path="%(path)s" % details,
                protocol=protocol,
            )
        elif protocol == "websocket" and action == "rejected":
            self.write_entry(
                host=details["client"],
                date=datetime.datetime.now(),
                request_method="WSREJECT",
                request_path="%(path)s" % details,
                protocol=protocol,
            )
        elif protocol == "websocket" and action == "connected":
            self.write_entry(
                host=details["client"],
                date=datetime.datetime.now(),
                request_method="WSCONNECT",
                request_path="%(path)s" % details,
                protocol=protocol,
            )
        elif protocol == "websocket" and action == "disconnected":
            self.write_entry(
                host=details["client"],
                date=datetime.datetime.now(),
                request_method="WSDISCONNECT",
                request_path="%(path)s" % details,
                protocol=protocol,
            )

    def write_entry(
        self, host, date, request_method, request_path, protocol, status=None, length=None, ident=None, user=None
    ):
        """
        Writes an NCSA-style entry to the log file (some liberty is taken with
        what the entries are for non-HTTP)
        """

        self.stream.write(
            (
                '{'
                '"when": {when},'
                '"username": {username},'
                '"httpRequest": {{'
                '"requestMethod": {request_method},'
                '"requestUrl": {request_path},'
                '"protocol": {protocol}},'
                '"responseSize": {response_size},'
                '"status": {status},'
                '"remoteIp": {remote_ip},'
                '"userAgent": {user_agent}'
                '}}'
                '"severity": {severity}'
                '}'
            ).format(
                when=date.strftime("%Y-%m-%d %H:%M:%S"),
                request_method=request_method,
                request_path=request_path,
                procotol=protocol,
                severity="INFO",
                remote_ip=host,
                user_agent=ident or "-",
                username=user or "-",
                status=status or "-",
                response_size=length or "-",
            )
        )

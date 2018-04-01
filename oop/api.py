#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import json
import datetime
import logging
import hashlib
import uuid
from optparse import OptionParser
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}

class Field(object):

    def __init__(self, required=False, nullable=True):
        self.required = required
        self.nullable = nullable

        # не совсем понятно, зачем хранить value в словаре, если на каждое поле всеравно инциализируется отдельный
        # экземпляр Field и словарь будет содержать всегда 1 ключ... Разве что если значение еще не устанавливалось
        # он будет пустой - как признак того, что поле не инициализировано.
        # Пока попробую просто хранить значение напрямую...
        #self.value = {} # WeakKeyDictionary()
        self.value = None

    def __get__(self, instance, owner):
        if not self.nullable and self.value is None:
            # значение еще не устанавливалось. Для not null надо вызывать исключение, в остальных случаях не существенно
            raise ValueError('Value is not set!')

        return self.value

    def __set__(self, instance, value):
        # остановился на более широком понимании "не пустое", т.к. сдается мне, что в Т.З. всетаки имеется ввиду,
        # что если nullable=False, то поле должно быть не пустым в самом широком смысле, а не только not is None
        if not self.nullable and not value: # value is None:
            raise ValueError('Write EMPTY value to NOT EMPTY field!')

        self.value = value

class CharField(Field):

    def __set__(self, instance, value):
        if value is not None and not isinstance(value, (str, unicode)):
            raise TypeError('Invalid value type! Expected: string or unicode, got: {0}'.format(type(value)))

        super(CharField, self).__set__(instance, value)

class ArgumentsField(Field):

    def __set__(self, instance, value):
        if value is not None and not isinstance(value, dict):
            raise TypeError('Invalid value type! Expected: dict, got: {0}'.format(type(value)))

        super(ArgumentsField, self).__set__(instance, value)

class EmailField(CharField):

    def __set__(self, instance, value):
        super(EmailField, self).__set__(instance, value)

        if '@' not in value:
            raise ValueError('Invalid value! Value must be a e-mail address')

class PhoneField(Field):

    def __set__(self, instance, value):
        if value is not None and not isinstance(value, (int, str, unicode)):
            raise TypeError('Invalid value type! Expected: int or string or unicode, got: {0}'.format(type(value)))

        if value and (str(len(value)) != 11 or not str(value).startswith('7')):
            raise ValueError('Invalid value! Value must be a phone number')

        super(PhoneField, self).__set__(instance, value)

class DateField(Field):

    def __set__(self, instance, value):
        if value is not None and not isinstance(value, datetime.date):
            try:
                value = datetime.date.strftime(value, '%d.%m.%Y')
            except:
                raise TypeError('Invalid value type or format! Expected: date or str format "DD.MM.YYYY",' \
                    'got: {0} of type: {1}'.format(value, type(value)))

        super(DateField, self).__set__(instance, value)

class BirthDayField(DateField):

    def __set__(self, instance, value):
        super(BirthDayField, self).__set__(instance, value)

        if self.value and datetime.date.today() - self.value > datetime.timedelta(days=365*70):
            raise ValueError('Invalid value! Age can`t be more than 70 years')

class GenderField(Field):

    def __set__(self, instance, value):
        if value is not None and not isinstance(value, int):
            raise TypeError('Invalid value type! Expected: int, got: {0}'.format(type(value)))

        if value and value not in GENDERS:
            raise ValueError('Invalid value! Value must be in the range (0, 1, 2)')

        super(GenderField, self).__set__(instance, value)

class ClientIDsField(Field):

    def __init__(self, required=False):
        super(ClientIDsField, self).__init__(required=required, nullable=False)

    def __set__(self, instance, value):
        if value is not None and not isinstance(value, (list, tuple)):
            raise TypeError('Invalid value type! Expected: list or tuple, got: {0}'.format(type(value)))

        if not value:
            raise ValueError('Invalid value! Value cannot be empty or None')

        super(ClientIDsField, self).__set__(instance, value)


class ClientsInterestsRequest(object):

    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)

    def __init__(self, **kwargs):
        self.client_ids = kwargs.get('client_ids', tuple())
        self.date = kwargs.get('date', None)

class OnlineScoreRequest(object):

    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def __init__(self, **kwargs):
        self.first_name = kwargs.get('first_name', None)
        self.last_name = kwargs.get('last_name', None)
        self.email = kwargs.get('email', None)
        self.phone = kwargs.get('phone', None)
        self.birthday = kwargs.get('birthday', None)
        self.gender = kwargs.get('gender', None)

        if not self.is_valid():
            raise Exception(u'Не заданы все обязательные параметры запроса!')

    def is_valid(self):
        return (self.phone is not None or self.email is not None) and (
            self.first_name is not None or self.last_name is not None) and (
            self.gender is not None or self.birthday is not None)

class MethodRequest(object):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    def __init__(self, **kwargs):
        self.account = kwargs.get('account', None)
        self.login = kwargs.get('login', None)
        self.token = kwargs.get('token', None)
        self.arguments = kwargs.get('arguments', {})
        self.method = kwargs.get('method', None)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


def check_auth(request):
    if request.login == ADMIN_LOGIN:
        digest = hashlib.sha512(datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).hexdigest()
    else:
        digest = hashlib.sha512(request.account + request.login + SALT).hexdigest()
    if digest == request.token:
        return True
    return False

def method_handler(request, ctx, store):
    response, code = None, None
    request_ = MethodRequest(**request['body'])

    if not check_auth(request_):
        return ERRORS[FORBIDDEN], FORBIDDEN

    return response, code


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        data_string = ''

        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            # todo: Убери replace перед сдачей!
            request = json.loads(data_string.decode('cp1251').replace("'", '"'))
        except:
            logging.exception('Error!')
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
                except Exception, e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r))
        return


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(filename=opts.log, level=logging.INFO,
        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()

#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import json
import datetime
import logging
import hashlib
import uuid
from weakref import WeakKeyDictionary
from optparse import OptionParser
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler

import scoring
import store

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

debug = False


class Field(object):

    def __init__(self, required=False, nullable=True, field_name=None):
        self.required = required
        self.nullable = nullable
        self.field_name = field_name
        self.value = WeakKeyDictionary()

    def __get__(self, instance, owner):
        if (not self.nullable or self.required) and not self.value[instance]:
            # значение еще не устанавливалось. Для обязательных полей надо вызывать исключение,
            # в остальных случаях не существенно
            raise ValueError(self.error_message('Not specified REQUIRED or NOT NULL field value!'))

        return self.value.get(instance, None)

    def __set__(self, instance, value):
        # флаг None будет сигнализировать о том, что поле вобще отсутсвует в запросе
        if self.required and value is None:
            raise ValueError(self.error_message('Missing required value!'))

        # остановился на более широком понимании "не пустое", т.к. сдается мне, что в Т.З. всетаки имеется ввиду,
        # что если nullable=False, то поле должно быть не пустым в самом широком смысле, а не только not is None
        if not self.nullable and not value:  # value is None:
            raise ValueError(self.error_message('Write EMPTY value to NOT EMPTY field!'))

        self.value[instance] = value

    def error_message(self, msg):
        return '{0}{1}'.format('Field: {0}. '.format(self.field_name) if self.field_name else '', msg)

class CharField(Field):

    def __set__(self, instance, value):
        if value is not None and not isinstance(value, (str, unicode)):
            raise TypeError(self.error_message('Invalid value type of Char field! Expected: string or unicode, '
                                               'got: {0} of type {1}'.format(value, type(value))))

        super(CharField, self).__set__(instance, value)

class ArgumentsField(Field):

    def __set__(self, instance, value):
        if value is not None and not isinstance(value, dict):
            raise TypeError(self.error_message('Invalid value type of Arguments filed! Expected: dict, got: '
                                               '{0} of type {1}'.format(value, type(value))))

        super(ArgumentsField, self).__set__(instance, value)

class EmailField(CharField):

    def __set__(self, instance, value):
        super(EmailField, self).__set__(instance, value)

        if value and '@' not in value:
            raise ValueError(self.error_message('Invalid value of Email field! Value must be a e-mail address'))

class PhoneField(Field):

    def __set__(self, instance, value):
        if value is not None and not isinstance(value, (int, str, unicode)):
            raise TypeError(self.error_message('Invalid value type of Phone field! Expected: int or string or unicode,'
                                               ' got: {0} of type {1}'.format(value, type(value))))

        if value and (len(str(value)) != 11 or not str(value).startswith('7')):
            raise ValueError(self.error_message('Invalid value! Value must be a phone number'))

        super(PhoneField, self).__set__(instance, value)

class DateField(Field):

    def __set__(self, instance, value):
        if value is not None and not isinstance(value, (datetime.datetime, datetime.date)):
            try:
                value = datetime.datetime.strptime(value, '%d.%m.%Y').date()
            except:
                raise TypeError(self.error_message('Invalid value type or format of Date field! ' 
                    'Expected: date or str format "DD.MM.YYYY", got: {0} of type: {1}'.format(value, type(value))))

        if value is not None and isinstance(value, datetime.datetime):
            value = value.date()

        super(DateField, self).__set__(instance, value)

class BirthDayField(DateField):

    def __set__(self, instance, value):
        super(BirthDayField, self).__set__(instance, value)

        if self.value[instance] and datetime.date.today() - self.value[instance] > datetime.timedelta(days=365*70):
            raise ValueError(self.error_message('Invalid value of Birthday field! Age can`t be more than 70 years'))

class GenderField(Field):

    def __set__(self, instance, value):
        if value is not None and not isinstance(value, int):
            raise TypeError(self.error_message('Invalid value type of Gender field! Expected: int, '
                                               'got: {0} of type {1}'.format(value, type(value))))

        if value and value not in GENDERS:
            raise ValueError(self.error_message('Invalid value of Gender field! Value must be in the range '
                                                '(0 - unknown, 1 - male, 2 - female)'))

        super(GenderField, self).__set__(instance, value)

class ClientIDsField(Field):

    def __init__(self, required=False, field_name=None):
        super(ClientIDsField, self).__init__(required=required, nullable=False, field_name=field_name)

    def __set__(self, instance, value):
        if value is not None and not isinstance(value, (list, tuple)):
            raise TypeError(self.error_message('Invalid value type of Client id`s field! Expected: list or tuple, '
                                               'got: {0} of type {1}'.format(value, type(value))))

        if not value:
            raise ValueError(self.error_message('Invalid value of Client id`s field! Value cannot be empty or None'))

        super(ClientIDsField, self).__set__(instance, value)


class RequestBase(object):

    def __init__(self, **kwargs):
        for field in self.__class__.__dict__:
            if isinstance(self.__class__.__dict__[field], Field):
                setattr(self, field, kwargs.get(field, None))


class ClientsInterestsRequest(RequestBase):

    client_ids = ClientIDsField(required=True, field_name='client_ids')
    date = DateField(required=False, nullable=True, field_name='date')


class OnlineScoreRequest(RequestBase):

    first_name = CharField(required=False, nullable=True, field_name='first_name')
    last_name = CharField(required=False, nullable=True, field_name='last_name')
    email = EmailField(required=False, nullable=True, field_name='email')
    phone = PhoneField(required=False, nullable=True, field_name='phone')
    birthday = BirthDayField(required=False, nullable=True, field_name='birthday')
    gender = GenderField(required=False, nullable=True, field_name='gender')

    def __init__(self, **kwargs):
        super(OnlineScoreRequest, self).__init__(**kwargs)

        if not self.is_valid():
            raise ValueError('Not all required fields are filled in: {0}'.format(self.invalid_fields()))

    def is_valid(self):
        return (self.phone and self.email) or (self.first_name and self.last_name) or (self.gender and self.birthday)

    def invalid_fields(self):
        msg = []
        if not self.phone or not self.email:
            msg.append('Phone and Email')
        if not self.first_name or not self.last_name:
            msg.append('First name and Last name')
        if not self.gender or not self.birthday:
            msg.append('Gender and Birthday')
        return ' or '.join(msg)


class MethodRequest(RequestBase):

    account = CharField(required=False, nullable=True, field_name='account')
    login = CharField(required=True, nullable=True, field_name='login')
    token = CharField(required=True, nullable=True, field_name='token')
    arguments = ArgumentsField(required=True, nullable=True, field_name='arguments')
    method = CharField(required=True, nullable=False, field_name='method')

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


def get_token(account, login):
    if login == ADMIN_LOGIN:
        return hashlib.sha512(datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).hexdigest()
    else:
        return hashlib.sha512(account + login + SALT).hexdigest()

def check_auth(request):
    digest = get_token(request.account if request.account else '', request.login)

    if debug:
        logging.debug('Actual digest: {0}'.format(digest))

    if digest == request.token:
        return True

    return False

def method_handler(request, ctx, store):
    """ returns: response - json data or str (error message), code - response code """

    router = {
        'online_score': scores_handler,
        'clients_interests': interests_handler
    }

    try:
        request_ = MethodRequest(**request['body'])

        if not check_auth(request_):
            return ERRORS[FORBIDDEN], FORBIDDEN

        if request_.method in router:
            return router[request_.method](request_, ctx, store)
        else:
            return "{0}! {1}".format(ERRORS[BAD_REQUEST], 'Method "{0}" not found'.format(request_.method)), BAD_REQUEST
    except (TypeError, ValueError), e:
        return "{0}! {1}".format(ERRORS[INVALID_REQUEST], e), INVALID_REQUEST

def scores_handler(request, context, store):
    context['has'] = [field for field, value in request.arguments.items() if value]

    if request.is_admin:
        return {'score': 42}, OK

    obj = OnlineScoreRequest(**request.arguments)
    return {'score': scoring.get_score(store, obj.phone, obj.email, obj.birthday, obj.gender,
        obj.first_name, obj.last_name)}, OK

def interests_handler(request, context, store):
    context['nclients'] = len(request.arguments.get('client_ids', ()))
    res = {}
    obj = ClientsInterestsRequest(**request.arguments)

    for cid in obj.client_ids:
        res['client_id{0}'.format(cid)] = scoring.get_interests(store, cid)

    return res, OK


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = store.MyStore()

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        data_string = ''

        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            # под windows тут надо немного поправить механизм декодирования параметров запроса
            # да, и кавычки заменять, потому что в командной строке нельзя экранировать параметры одинарной кавычкой
            if os.name == 'nt':
                request = json.loads(data_string.decode('cp1251').replace("'", '"'))
            else:
                request = json.loads(data_string)
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
    logging.basicConfig(filename=opts.log, level=logging.DEBUG if debug else logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()

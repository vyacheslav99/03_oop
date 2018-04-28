# -*- coding: utf-8 -*-

import unittest

import api
import store

def cases(case_list):
    def decorate(func):
        def test(inst):
            for name, params in case_list:
                func(inst, params, name)
        return test
    return decorate

test_fields_vectors = (
    ('type_args_field', {"account": "horns&hoofs", "login": "h&f", "method": "clients_interests", "arguments": [4,6,8,'aaa']}),
    ('type_id_field', {"account": "horns&hoofs", "login": "h&f", "method": "clients_interests",
        "arguments": {"client_ids": '1,2,3,4,5', "date": "20.07.2017"}}),
    ('type_date_field', {"account": "horns&hoofs", "login": "h&f", "method": "clients_interests",
        "arguments": {"client_ids": [1,2,3], "date": "2017-07-20"}}),
    ('type_char_field', {"account": "horns&hoofs", "login": "h&f", "method": "online_score", "arguments": {"phone": "79175002040",
        "email": "stupnikov@otus.ru", "first_name": 987, "last_name": "Ступников", "birthday": "01.01.1990", "gender": 1}}),
    ('type_phone_field', {"account": "horns&hoofs", "login": "h&f", "method": "online_score", "arguments": {"phone": 258.8693241,
        "email": "stupnikov@otus.ru", "first_name": "Стансилав", "last_name": "Ступников", "birthday": "01.01.1990",
        "gender": 1}}),
    ('type_gender_field', {"account": "horns&hoofs", "login": "h&f", "method": "online_score", "arguments": {"phone": "79175002040",
        "email": "stupnikov@otus.ru", "first_name": "Стансилав", "last_name": "Ступников", "birthday": "01.01.1990",
        "gender": '1'}}),
    ('invalid_email', {"account": "horns&hoofs", "login": "h&f", "method": "online_score", "arguments": {"phone": "79175002040",
        "email": "stupnikov.ru", "first_name": "Стансилав", "last_name": "Ступников", "birthday": "01.01.1990", "gender": 1}}),
    ('invalid_phone', {"account": "horns&hoofs", "login": "h&f", "method": "online_score", "arguments": {"phone": 2284356,
        "email": "stupnikov.ru", "first_name": "Стансилав", "last_name": "Ступников", "birthday": "01.01.1990", "gender": 1}}),
    ('empty_id_field', {"account": "horns&hoofs", "login": "h&f", "method": "clients_interests",
        "arguments": {"client_ids": [], "date": "20.07.2017"}}),
    ('invalid_birthday', {"account": "horns&hoofs", "login": "h&f", "method": "online_score", "arguments": {"phone": "79175002040",
        "email": "stupnikov@otus.ru", "first_name": "Стансилав", "last_name": "Ступников", "birthday": "01.01.1856",
        "gender": 1}}),
    ('invalid_gender', {"account": "horns&hoofs", "login": "h&f", "method": "online_score", "arguments": {"phone": "79175002040",
        "email": "stupnikov@otus.ru", "first_name": "Стансилав", "last_name": "Ступников", "birthday": "01.01.1990",
        "gender": -1}})
)

class TestSuite(unittest.TestCase):

    def setUp(self):
        self.context = {}
        self.headers = {}
        self.store = store.MyStore()

    def get_response(self, request, calc_token=True):
        if calc_token:
            request['token'] = api.get_token(request.get('account', ''), request.get('login', ''))
        return api.method_handler({"body": request, "headers": self.headers}, self.context, self.store)

    # проверка компонентов системы
    def test_empty_request(self):
        _, code = self.get_response({})
        self.assertEqual(api.INVALID_REQUEST, code)

    def test_bad_auth(self):
        _, code = self.get_response({"account": "horns&hoofs", "login": "h&f", "method": "online_score",
            "token": "55cc9ce545bcd144300fe9efc28e65d415b923ebb6be1e19d2750a2c03e80dd209a27954dca045e5bb12418e7d89b6d718a9e35af3",
            "arguments": {"phone": "79175002040", "email": "stupnikov@otus.ru", "first_name": "Стансилав",
                          "last_name": "Ступников", "birthday": "01.01.1990", "gender": 1}}, calc_token=False)
        self.assertEqual(api.FORBIDDEN, code)

    def test_non_exist_method(self):
        _, code = self.get_response({"account": "horns&hoofs", "login": "h&f", "method": "bend",
            "arguments": {"phone": "79175002040", "email": "stupnikov@otus.ru", "first_name": "Стансилав",
                          "last_name": "Ступников", "birthday": "01.01.1990", "gender": 1}})
        self.assertEqual(api.BAD_REQUEST, code)

    def test_score_valid_user(self):
        _, code = self.get_response({"account": "horns&hoofs", "login": "h&f", "method": "online_score",
            "arguments": {"phone": "79175002040", "email": "stupnikov@otus.ru", "first_name": "Стансилав",
                          "last_name": "Ступников", "birthday": "01.01.1990", "gender": 1}})
        self.assertEqual(api.OK, code)

    def test_score_valid_admin(self):
        _, code = self.get_response({"account": "horns&hoofs", "login": api.ADMIN_LOGIN, "method": "online_score",
            "arguments": {"phone": "79175002040", "email": "stupnikov@otus.ru", "first_name": "Стансилав",
                          "last_name": "Ступников", "birthday": "01.01.1990", "gender": 1}})
        self.assertEqual(api.OK, code)

    def test_score_incomplete_data(self):
        _, code = self.get_response({"account": "horns&hoofs", "login": "h&f", "method": "online_score",
            "arguments": {"phone": "79175002040", "first_name": "Стансилав", "birthday": "01.01.1990"}})
        self.assertEqual(api.INVALID_REQUEST, code)

    def test_int_valid_user(self):
        _, code = self.get_response({"account": "horns&hoofs", "login": "h&f", "method": "clients_interests",
                                     "arguments": {"client_ids": [1,2,3,4], "date": "20.07.2017"}})
        self.assertEqual(api.OK, code)

    def test_int_valid_admin(self):
        _, code = self.get_response({"account": "horns&hoofs", "login": api.ADMIN_LOGIN, "method": "clients_interests",
                                     "arguments": {"client_ids": [1,2,3,4], "date": "20.07.2017"}})
        self.assertEqual(api.OK, code)

    # проверки полей
    @cases(test_fields_vectors)
    def test_check_field(self, request, test_name):
        _, code = self.get_response(request)
        self.assertEqual(api.INVALID_REQUEST, code, 'Failed case "%s"' % test_name)


if __name__ == "__main__":
    unittest.main()

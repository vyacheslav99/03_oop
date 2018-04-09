# -*- coding: utf-8 -*-

import unittest
import hashlib

import api
import store


class TestSuite(unittest.TestCase):

    def setUp(self):
        self.context = {}
        self.headers = {}
        self.store = store.MyStore()

    def get_response(self, request, calc_token=True):
        if calc_token:
            request['token'] = api.get_token(request.get('account', ''), request.get('login', ''))
        return api.method_handler({"body": request, "headers": self.headers}, self.context, self.store)

    def test_empty_request(self):
        _, code = self.get_response({})
        self.assertEqual(api.INVALID_REQUEST, code)

    def test_bad_auth(self):
        _, code = self.get_response({"account": "horns&hoofs", "login": "h&f", "method": "online_score",
            "token": "55cc9ce545bcd144300fe9efc28e65d415b923ebb6be1e19d2750a2c03e80dd209a27954dca045e5bb12418e7d89b6d718a9e35af3",
            "arguments": {"phone": "79175002040", "email": "stupnikov@otus.ru", "first_name": "Стансилав", "last_name": "Ступников",
            "birthday": "01.01.1990", "gender": 1}}, calc_token=False)
        self.assertEqual(api.FORBIDDEN, code)

    def test_score_valid_user(self):
        _, code = self.get_response({"account": "horns&hoofs", "login": "h&f", "method": "online_score",
            #"token": "55cc9ce545bcd144300fe9efc28e65d415b923ebb6be1e19d2750a2c03e80dd209a27954dca045e5bb12418e7d89b6d718a9e35af3",
            "arguments": {"phone": "79175002040", "email": "stupnikov@otus.ru", "first_name": "Стансилав", "last_name": "Ступников",
            "birthday": "01.01.1990", "gender": 1}})
        self.assertEqual(api.OK, code)

    def test_score_valid_admin(self):
        _, code = self.get_response({"account": "horns&hoofs", "login": api.ADMIN_LOGIN, "method": "online_score",
            "arguments": {"phone": "79175002040", "email": "stupnikov@otus.ru", "first_name": "Стансилав", "last_name": "Ступников",
            "birthday": "01.01.1990", "gender": 1}})
        self.assertEqual(api.OK, code)

    def test_int_valid_user(self):
        _, code = self.get_response({"account": "horns&hoofs", "login": "h&f", "method": "clients_interests",
                                     "arguments": {"client_ids": [1,2,3,4], "date": "20.07.2017"}})
        self.assertEqual(api.OK, code)

    def test_int_valid_admin(self):
        _, code = self.get_response({"account": "horns&hoofs", "login": api.ADMIN_LOGIN, "method": "clients_interests",
                                     "arguments": {"client_ids": [1,2,3,4], "date": "20.07.2017"}})
        self.assertEqual(api.OK, code)


if __name__ == "__main__":
    unittest.main()

import unittest
from unittest import mock
import os
import sys
import pymongo
sys.path.append(os.path.join(os.path.split(__file__)[0], '..', 'src'))
import userLoginTool
import jwt

class TestUserLoginTool(unittest.TestCase):
    @mock.patch('pymongo.MongoClient')
    @mock.patch('userLoginTool.utils.db_helper.DatabaseConnector.query_user_with_username', return_value=None)
    def test_register(self, mock_mongo, find_one):
        loginNOut = userLoginTool.LoginNOut("fake_db_name", "fake_db_connection_str")
        loginNOut.register_user('foo', 'bar')


    @mock.patch('pymongo.MongoClient')
    @mock.patch('userLoginTool.utils.db_helper.DatabaseConnector.query_user_with_username', return_value={
        'password': b'\xd9s\xac\x7f\x17\xd7\x9fH)8l3\xf4\x88\xd66!\xe7\xb9\xfd\x919\x9e\xae\xdc\xa5\xb1|u5\xe2\xb9',
        'salt': 'LptMXaj'
    })
    def test_login(self, client, query):
        loginNOut = userLoginTool.LoginNOut("fake_db_name", "fake_db_connection_str")       
        token = loginNOut.get_token('foo', 'bar')
        assert token

    @mock.patch('pymongo.MongoClient')
    def test_verify_token(self, client):
        loginNOut = userLoginTool.LoginNOut("fake_db_name", "fake_db_connection_str")  
        with mock.patch('userLoginTool.utils.db_helper.DatabaseConnector.query_user_with_username', return_value={
            'password': b'\xd9s\xac\x7f\x17\xd7\x9fH)8l3\xf4\x88\xd66!\xe7\xb9\xfd\x919\x9e\xae\xdc\xa5\xb1|u5\xe2\xb9',
            'salt': 'LptMXaj'
        }):
            token = loginNOut.get_token('foo', 'bar')
        token_body = jwt.decode(token, loginNOut._token_salt, algorithms=['HS256'])
        user_token = token_body['data']['token']
        with mock.patch('userLoginTool.utils.db_helper.DatabaseConnector.query_user_token', return_value={'token': user_token, 'expire_time': float('inf')}):
            user = loginNOut.varify_token(token)
            assert user
    

if __name__ == '__main__':
    unittest.main()
import logging
from utils.db_helper import DatabaseConnector
from utils import self_defined_errors
from utils.constants import Constants
import datetime
import random
import string
import time
from multiprocessing import Process
import jwt

class LoginNOut:
    def __init__(self, db_name: str, db_connection_string: str) -> None:
        self._db_connection_string = db_connection_string
        self._db_name = db_name
        self._logger = logging.getLogger("LoginNOut")
        self._token_salt = ''
        self._body_salt = ''
        self._body_salt_expire = 0.0

    def _gen_salt(self, salt_len: int) -> str:
        return ''.join(random.sample(string.ascii_letters + string.digits, salt_len))  

    def _update_body_salt(self):
        while True:
            salt_len = random.randint(Constants.SALT_LEN_MIN, Constants.SALT_LEN_MAX)
            self._body_salt = self._gen_salt(salt_len)
            self._body_salt_expire = datetime.datetime.utcnow().timestamp() + Constants.SALT_EXPIRE_TIME
            time.sleep(Constants.SALT_EXPIRE_TIME)

    def start(self):
        if not self._db_connection_string or not self._db_name:
            raise self_defined_errors.InitError("must specify the database connection string and a database name")
        self._db_connector = DatabaseConnector(self._db_connection_string, self._db_name)
        salt_len = random.randint(Constants.SALT_LEN_MIN, Constants.SALT_LEN_MAX)
        self._token_salt = self._gen_salt(salt_len)
        self._update_process = Process(target=self._update_body_salt)

    def stop(self):
        self._update_process.join()


    def get_current_salt(self):
        return self._body_salt, self._body_salt_expire - datetime.datetime.utcnow().timestamp()

    def varify_token(self, token: str):
        try:
            body = jwt.decode(token, self._token_salt, algorithms=["HS256"])
            username = body['username']
            token = body['token']
            token_col = self._db_connector.query_user_token(username)
            if not token_col:
                self._logger.warn('wrong token')
                return None
            cur_time = datetime.datetime.utcnow().timestamp()
            if token == token_col.get('token') and \
                cur_time >= token_col.get('expire_time', float('inf')):
                self._db_connector.update_user_token(username, token, cur_time + Constants.TOKEN_EXPIRE_TIME)
                return username
            return None
        except self_defined_errors.DataBaseError as e:
            self._logger.warn('cannot get user token from db')
            return None            
        except jwt.exceptions.InvalidTokenError:   
            self._logger.warn('invalid token')         
            return None
        except KeyError:
            self._logger.warn('invalid token body')
            return None    
        finally:
            return None   


    def get_token(self, username: str, password: str):
        user = self._db_connector.query_user_with_username(username)
        if not user:
            return None
        if 'password' not in user or 'salt' not in user:
            raise self_defined_errors.UserError('wrong data in db, should re-register the user')
        try:
            stored_pwd = jwt.decode(user['password'], user['salt'], algorithms=["HS256"])
        except jwt.exceptions.InvalidTokenError:
            self._logger.warn('decode hashed password failed')
            raise self_defined_errors.UserError('wrong data in db, should re-register the user')            
        if stored_pwd == password:
            salt_len = random.randint(Constants.SALT_LEN_MIN, Constants.SALT_LEN_MAX)
            token = self._gen_salt(salt_len)
            expire_time = datetime.datetime.utcnow().timestamp() + Constants.TOKEN_EXPIRE_TIME
            res = self._db_connector.update_user_token(username, token, expire_time)
            if res.modified_count == 0:
                raise self_defined_errors.UserError('wrong data in db, should re-register the user')
            ret = {
                'data': {
                    'username': username,
                    'token': token
                }
            }
            return jwt.encode(ret, self._token_salt, algorithm="HS256")

    def register_user(self, username: str, password: str):
        user = self._db_connector.query_user_with_username(username)
        if user:
            raise self_defined_errors.UserError('user already exists')
        salt_len = random.randint(Constants.SALT_LEN_MIN, Constants.SALT_LEN_MAX)
        salt = self._gen_salt(salt_len)
        hashed_pwd = jwt.encode(password, salt, algorithm="HS256")
        self._db_connector.register_user(username, hashed_pwd, salt)


    def clear_token(self, username: str):
        if not username:
            raise self_defined_errors.UserError("username is required")
        res = self._db_connector.clear_user_token(username)
        return res.modified_count
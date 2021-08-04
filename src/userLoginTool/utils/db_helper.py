import pymongo
import logging
from . import self_defined_errors

class DatabaseConnector:
    def __init__(self, db_connection_string: str, db_name: str):
        self._db_client = pymongo.MongoClient(db_connection_string)
        self._database = self._db_client[db_name]
        self._logger = logging.getLogger("db_helper")

    def check_mongo_connection(self) -> bool:
        try:
            self._db_client.server_info()
        except pymongo.errors.ServerSelectionTimeoutError:
            self.logger.error("database connection failed")
            return False
        return True

    def query_user_with_username(self, username: str):
        col = self._database.get_collection('User')
        if not col:
            raise self_defined_errors.DataBaseError(f'{username}: miss User table in database')
        return col.find_one({'username': username})

    def register_user(self, username: str, password: str, salt: str):
        if not username or not password or not salt:
            raise self_defined_errors.DataBaseError("missed required parameter")
        col = self._database.get_collection('User')
        if not col:
            raise self_defined_errors.DataBaseError(f'{username}: miss User table in database')
        col.insert_one({
            'username': username,
            'password': password,
            'salt': salt
        })        

    def update_user_token(self, username, token, expire_time):
        col = self._database.get_collection('User')
        if not col:
            raise self_defined_errors.DataBaseError(f'{username}: miss User table in database')        
        return col.update_one({'username': username}, {'token': {'token': token, 'expire_time': expire_time}}, upsert=True)


    def query_user_token(self, username):
        col = self._database.get_collection('User')
        if not col:
            raise self_defined_errors.DataBaseError(f'{username}: miss User table in database')   
        user = col.find_one({'username': username})
        if user is None:
            self._logger.info(f'{username}: miss user info')
            return None
        if 'token' in user:
            return user['token']
        self._logger.info(f'{username}: miss user token')
        return None


    def clear_user_token(self, username):
        col = self._database.get_collection('User')
        if not col:
            raise self_defined_errors.DataBaseError(f'{username}: miss User table in database')            
        return col.update_one({'username': username}, {'token': None})
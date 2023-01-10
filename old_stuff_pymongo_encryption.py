from lib.communication import Comunication
from lib.logger import Logger
from lib.logger import Logger
from lib.schema import SchemaRoutes
from lib.system import System

from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.errors import ServerSelectionTimeoutError

from json import loads
from ast import literal_eval as loads_array

from base64 import b64decode, b64encode
from bson.binary import Binary, STANDARD
from bson.codec_options import CodecOptions
from os import urandom
from pymongo import MongoClient
from pymongo.encryption import (Algorithm, ClientEncryption)


class DatabaseOperations():
    MONGO_ENCRYPTION: bool=False
    CLIENT_ENCRYPTOR: ClientEncryption = None
    KMS_DB_HASH: str=None

    ENVIROMENTAL: list = []
    CONNECTED: bool = False
    DATABASE: Database = None
    COLLECTION_DB: Collection = None
    MONGOCLIENT: MongoClient = None

    class DatabaseEncryptor():
        KEY_VAULT_NAMESPACE = 'local_encryption.__keyVault'
        KEY_VAULT_DB_NAME, KEY_VAULT_COLL_NAME = KEY_VAULT_NAMESPACE.split(".", 1)

        def generateNewClientEncryption(master_key_bytes: bytes=None, key_vault_namespace: str=None, database_client: MongoClient=None):
            return ClientEncryption(
                kms_providers={ 'local': { 'key': master_key_bytes }},
                key_vault_namespace=key_vault_namespace,
                key_vault_client=database_client,
                codec_options=CodecOptions(uuid_representation=STANDARD)
            )

        def registerMasterKeyInMongo(master_key_bytes: bytes=None, client_encryptor: ClientEncryption=None):
            DatabaseKeyVault = DatabaseOperations.MONGOCLIENT[DatabaseOperations.DatabaseEncryptor.KEY_VAULT_DB_NAME][DatabaseOperations.DatabaseEncryptor.KEY_VAULT_COLL_NAME]
            DatabaseKeyVault.create_index('keyAltNames', unique=True, partialFilterExpression={'keyAltNames': {'$exists': True}})
            if len(list(DatabaseKeyVault.find({ "keyAltNames": DatabaseOperations.KMS_DB_HASH }))) <= 0:
                # Save master key data into key vault.
                master_key_hash_uid = client_encryptor.create_data_key('local', key_alt_names=[DatabaseOperations.KMS_DB_HASH])
                # Success.
                DatabaseOperations.DatabaseEncryptor.MasterKeyUtils.notifyGeneratedMasterKey(master_key_bytes, DatabaseOperations.KMS_DB_HASH, master_key_hash_uid)

        def encryptJson(non_encrypted_json: dict or list=None, enable_mongo_encryption: bool=False):
            if non_encrypted_json == None:
                return {}
            if not enable_mongo_encryption:
                return non_encrypted_json
            try:
                def encryptValue(non_encrypted_value):
                    return DatabaseOperations.CLIENT_ENCRYPTOR.encrypt(non_encrypted_value, Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Deterministic, key_alt_name=DatabaseOperations.KMS_DB_HASH)
                
                def encryptJsonValues(json: dict):
                    try:
                        for key in json.keys():
                            try:
                                if key != '_id':
                                    json[key] = encryptValue((f'_object:{json[key]}' if isinstance(json[key], dict) else f'_list:{json[key]}' if (isinstance(json[key], dict) or isinstance(json[key], list) ) else json[key]))
                            except:
                                continue
                    except:
                        pass
                    return json

                if isinstance(non_encrypted_json, list):
                    for json in non_encrypted_json:
                        json = encryptJsonValues(json)
                else:
                    return encryptJsonValues(non_encrypted_json)
                return non_encrypted_json
            except Exception as exception: 
                Logger.exception(exception, 'databaseOperations.py/database_encryptor/encryptJson')
                raise exception

        def decryptJson(cursor_encrypted_json_array: dict or list=None, enable_mongo_encryption: bool=False):
            if cursor_encrypted_json_array == None:
                return {}
            if not enable_mongo_encryption:
                return cursor_encrypted_json_array
            try:
                def decryptValue(encrypted_value):
                    return DatabaseOperations.CLIENT_ENCRYPTOR.decrypt(Binary(encrypted_value, 6))
                
                def decryptJsonValues(json: dict):
                    for key in json.keys():
                        try:
                            if key != '_id':
                                json[key] = decryptValue(json[key])
                                if str(json[key]).__contains__('_list:'):
                                    json[key] = str(json[key]).replace('_list:', '')
                                    try:
                                        json[key] = loads_array(json[key])
                                    except:
                                        continue
                                elif str(json[key]).__contains__('_object:'):
                                    json[key] = str(json[key]).replace('_object:', '').replace('\'', '"').replace('False', 'false').replace('True', 'true')
                                    try: 
                                        loads(json[key])
                                        json[key] = loads(json[key])
                                    except:
                                        continue
                            else:
                                json[key] = str(json[key])
                        except:
                            continue
                    return json

                if isinstance(cursor_encrypted_json_array, list):
                    for json in cursor_encrypted_json_array:
                        json = decryptJsonValues(json)
                else:
                    return decryptJsonValues(cursor_encrypted_json_array)
                return cursor_encrypted_json_array
            except Exception as exception: 
                Logger.exception(exception, 'databaseOperations.py/database_encryptor/decryptJson')
                raise exception

        class MasterKeyUtils():
            def generateNewMasterKey():
                return Binary(urandom(96))

            def notifyGeneratedMasterKey(master_key_bytes: bytes=None, master_key_hash: str=None, master_key_uid: str=None):
                notification_msg = ''
                notification_msg += master_key_hash + '\n'
                notification_msg += b64encode(master_key_bytes).decode('utf-8') + '\n'
                notification_msg += b64encode(master_key_uid).decode('utf-8')
                Comunication.notify('New master key generated successfuly.', notification_msg)

            def getMasterKey(env):
                try: return b64decode(env['KMS_DB_KEY'].encode('ascii'))
                except: return None

            def getHashMasterKey(key: bytes=None):
                try: key = key.decode('utf-8')
                except: key = str(key)
                return System.getHash(key)

    # Connect to the database and save database connection in this class.
    @staticmethod
    def initialize(env):
        try:
            Logger.log('~ Connecting to database...')
            # MongoDB connection stuff.
            DatabaseOperations.ENVIROMENTAL = env
            DatabaseOperations.MONGOCLIENT = MongoClient(env['BACKEND_MONGODB_CONNECTIONSTRING'])
            DatabaseOperations.MONGOCLIENT.server_info()
            DatabaseOperations.DATABASE = DatabaseOperations.MONGOCLIENT[env['BACKEND_MONGODB_DATABASE']]
            try:
                # Encryption.
                MASTER_KEY = DatabaseOperations.DatabaseEncryptor.MasterKeyUtils.getMasterKey(env)
                DatabaseOperations.CLIENT_ENCRYPTOR = DatabaseOperations.DatabaseEncryptor.generateNewClientEncryption(MASTER_KEY, DatabaseOperations.DatabaseEncryptor.KEY_VAULT_NAMESPACE, DatabaseOperations.MONGOCLIENT)
                # Get hash of master key provided.
                DatabaseOperations.KMS_DB_HASH = env['KMS_DB_HASH']
                # Save Key in mongo if not exists.
                DatabaseOperations.DatabaseEncryptor.registerMasterKeyInMongo(MASTER_KEY, DatabaseOperations.CLIENT_ENCRYPTOR)
                # Success.
                DatabaseOperations.CONNECTED = True
                Logger.log('\n~ Success connection to database.')
            except Exception as exception:
                DatabaseOperations.CONNECTED = False
                Logger.log('~ Failure creating Client Encryption...')
                Logger.exception(exception, 'databaseOperations.py/initialize/encryption')
        except Exception as exception:
            DatabaseOperations.CONNECTED = False
            Logger.log('~ Failure configuration from database...')
            DatabaseOperations.initialize(env)
            if not isinstance(exception, ServerSelectionTimeoutError):
                Logger.exception(exception, 'databaseOperations.py/initialize')

    def isDatabaseConnected():
        try:
            isConnected = (DatabaseOperations.CONNECTED and DatabaseOperations.DATABASE != None and DatabaseOperations.MONGOCLIENT != None)
            if isConnected:
                DatabaseOperations.MONGOCLIENT.server_info()
                return True
            return isConnected
        except:
            return False

    @staticmethod
    def insert(collection: str=None, json: dict={}, enable_mongo_encryption: bool=False):
        try:
            if collection == None or collection == '':
                return 'Invalid collection.'
            if json == {}:
                return 'Check your empty json.'
            if not DatabaseOperations.isDatabaseConnected():
                log = f'[ Database ] NOT_CONNECTED: [INSERT] [COLLECTION: {collection}] [DATA LENGTH: {len(json)}]'
                Comunication.notify(msg=f'Not connected to database.\n\n{log}', type_notification='database')
                Logger.log(log)
                return 'Not connected to DB.'
            else:
                if SchemaRoutes.is_json(json):
                    return DatabaseOperations.DATABASE[collection].insert(DatabaseOperations.DatabaseEncryptor.encryptJson(json, enable_mongo_encryption))
                else:
                    return 'Not valid JSON.'
        except Exception as exception:
            Logger.exception(exception, 'databaseOperations.py/insert')
            return 'Not successful.'

    @staticmethod
    def find(collection: str=None, query: dict={}, enable_mongo_decryption: bool=False, limit: int=1):
        try:
            if collection == None or collection == '':
                return 'Invalid collection.'
            if not DatabaseOperations.isDatabaseConnected():
                log = f'[ Database ] NOT_CONNECTED: [FIND] [COLLECTION: {collection}] [QUERY: {query}] [LIMIT: {limit}]'
                Comunication.notify(msg=f'Not connected to database.\n\n{log}', type_notification='database')
                Logger.log(log)
                return 'Not connected to DB.'
            else:
                return  DatabaseOperations.DatabaseEncryptor.decryptJson(list(DatabaseOperations.DATABASE[collection].find(query).limit(limit)), enable_mongo_decryption)
        except Exception as exception:
            Logger.exception(exception, 'databaseOperations.py/find')
            return 'Not successful.'

    @staticmethod
    def update(collection: str=None, query: dict={}, new_json: dict={}):
        try:
            if collection == None or collection == '':
                return 'Invalid collection.'
            if query == {} or new_json == {}:
                return 'Check your json update and query.'
            if not DatabaseOperations.isDatabaseConnected():
                log = f'[ Database ] NOT_CONNECTED: [UPDATE_ONE] [COLLECTION: {collection}] [QUERY: {query}] [DATA LENGTH: {len(new_json)}]'
                Comunication.notify(msg=f'Not connected to database.\n\n{log}', type_notification='database')
                Logger.log(log)
                return 'Not connected to DB.'
            else:
                if SchemaRoutes.is_json(new_json):
                    return str(DatabaseOperations.DATABASE[collection].update(query, new_json)['nModified']) + ' updated.'
                else:
                    return 'Not valid JSON.'
        except Exception as exception:
            Logger.exception(exception, 'databaseOperations.py/updateOne')
            return 'Not successful.'

    @staticmethod
    def delete(collection: str=None, query: dict={}, many: bool=False):
        try:
            if collection == None or collection == '':
                return 'Invalid collection.'
            if not DatabaseOperations.isDatabaseConnected():
                log = f'[ Database ] NOT_CONNECTED: [DELETE_ONE] [COLLECTION: {collection}] [QUERY: {query}]'
                Comunication.notify(msg=f'Not connected to database.\n\n{log}', type_notification='database')
                Logger.log(log)
                return 'Not connected to DB.'
            else:
                operation = (DatabaseOperations.DATABASE[collection].delete_many(query) if many else DatabaseOperations.DATABASE[collection].delete_one(query))
                return f'Successful acknowledged {operation.deleted_count}.' if operation.acknowledged else f'Not successful acknowledged {operation.deleted_count}.'
        except Exception as exception:
            Logger.exception(exception, 'databaseOperations.py/deleteOne')
            return 'Not successful.'

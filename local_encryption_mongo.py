from base64 import b64encode, b64decode
from bson.binary import STANDARD, Binary
from bson.codec_options import CodecOptions
from uuid import uuid5, NAMESPACE_OID

from os import urandom
from pymongo import MongoClient
from pymongo.encryption import (Algorithm, ClientEncryption)


class MasterKeyUtils():
    def generateNewMasterKey():
        return Binary(urandom(96))

    def saveMasterKey(master_key_bytes: bytes=None, master_key_hash: str=None, master_key_uid: str=None):
        # Hash and urandom.bytes.
        with open(f'master_key_{master_key_hash}', 'wb') as file_master_key:
            file_master_key.write(b64encode(master_key_bytes))
            file_master_key.close()
        # Binary data from bson.
        with open(f'master_key_metadata_{master_key_hash}', 'wb') as file_master_key_metadata:
            file_master_key_metadata.write(b64encode(master_key_uid))
            file_master_key_metadata.close()

    def readMasterKey(master_key_file_name: str=None):
        try:
            master_key_b64 = open(master_key_file_name, 'r')
            return b64decode(master_key_b64.read().encode('ascii')).decode('utf-8')
        except:
            pass
        return master_key_file_name

    def getHashMasterKey(key: bytes=None):
        try: key = key.decode('utf-8')
        except: key = str(key)
        return str(uuid5(NAMESPACE_OID, key)).replace('-', '')


class DatabaseUtils():
    def getClientEncryption(keyString: str=None, keyVaultNamespace: str=None, DatabaseClient: MongoClient=None):
        return ClientEncryption(
            kms_providers={ 'local': { 'key': keyString }},
            key_vault_namespace=keyVaultNamespace,
            key_vault_client=DatabaseClient,
            codec_options=CodecOptions(uuid_representation=STANDARD)
        )

    def createMongoClient(connection_string: str='mongodb://localhost:27017'):
        return MongoClient(connection_string)


if __name__ == '__main__':
    DatabaseClient = DatabaseUtils.createMongoClient()
    test_coll = DatabaseClient['test_db']['test_coll']
    test_coll.drop()

    ## KeyVault config.
    key_vault_namespace = 'local_encryption.__keyVault'
    key_vault_db_name, key_vault_coll_name = key_vault_namespace.split('.', 1)

    ## KeyVault database config.
    key_vault_coll = DatabaseClient[key_vault_db_name][key_vault_coll_name]
    # Add data-key to KeyVault database.
    key_vault_coll.drop()
    key_vault_coll.drop_indexes()
    key_vault_coll.create_index('keyAltNames', unique=True, partialFilterExpression={'keyAltNames': {'$exists': True}})

    ## Creates new client encryption with KeyVault config.
    generated_master_key = MasterKeyUtils.generateNewMasterKey()
    generated_master_key_hash = MasterKeyUtils.getHashMasterKey(generated_master_key)
    
    ## Create client encryption.
    client_encryption = DatabaseUtils.getClientEncryption(generated_master_key, key_vault_namespace, DatabaseClient)

    ## Insert to KeyVault.
    generated_master_key_uid = client_encryption.create_data_key('local')
    MasterKeyUtils.saveMasterKey(generated_master_key, generated_master_key_hash, generated_master_key_uid)

    #### Explicitly encrypt a field.
    json_test = {
        'name': 'John Wick',
        'age': 40
    }

    for i in range(15):
        json_test_temp = json_test.copy()
        json_test_temp['name'] = json_test_temp['name'] + '_' + str(i)
        json_test_temp['age'] = json_test_temp['age'] + i
        
        json_test_temp['age'] = client_encryption.encrypt(json_test_temp['age'], Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Random, key_id=generated_master_key_uid)
        test_coll.insert_one(json_test_temp)

    for cursor in test_coll.find({}):
        print(cursor)
        cursor['age'] = client_encryption.decrypt(Binary(cursor['age'], 6))
        print(cursor)


    #### Cleanup resources
    client_encryption.close()
    DatabaseClient.close()

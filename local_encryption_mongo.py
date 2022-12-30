from base64 import b64decode, b64encode
from bson.binary import STANDARD, Binary
from bson.codec_options import CodecOptions
from uuid import uuid5, NAMESPACE_OID

from dotenv import load_dotenv
load_dotenv()

from os import urandom, environ
from pymongo import MongoClient
from pymongo.encryption import (Algorithm, ClientEncryption)



class MasterKeyUtils():
    def generateNewMasterKey():
        return b64encode(Binary(urandom(96))).decode('utf-8')

    def convertMasterKey(keyString: str=''):
        if keyString == '':
            return MasterKeyUtils.generateNewMasterKey()
        else:
            return b64decode(keyString.encode('ascii'))

    def getHashMasterKey(keyString: str=''):
        return str(uuid5(NAMESPACE_OID, keyString))


class DatabaseUtils():
    def getClientEncryption(keyString: str='', keyVaultNamespace: str='', keyVaultColl: str=''):
        try:
            if keyString == '':
                keyString = MasterKeyUtils.generateNewMasterKey()
            return ClientEncryption(
                kms_providers={ "local": { "key": keyString }},
                key_vault_namespace=keyVaultNamespace,
                key_vault_client=keyVaultColl,
                codec_options=CodecOptions(uuid_representation=STANDARD)
            )
        except Exception as exception:
            raise exception

    def createMongoClient():
        return MongoClient('mongodb://localhost:27017')


if __name__ == '__main__':
    DatabaseClient = DatabaseUtils.createMongoClient()
    test_coll = DatabaseClient['test_db']['test_coll']
    test_coll.drop()

# KeyVault config.
key_vault_namespace = "local_encryption.__keyVault"
key_vault_db_name, key_vault_coll_name = key_vault_namespace.split(".", 1)

# KeyVault database config.
key_vault_coll = DatabaseClient[key_vault_db_name][key_vault_coll_name]
key_vault_coll.create_index("keyAltNames", unique=True, partialFilterExpression={"keyAltNames": {"$exists": True}})

# Creates new client encryption with KeyVault config.
client_encryption = MasterKeyUtils.generateNewMasterKey(MasterKeyUtils.convertMasterKey(environ['MASTER_KEY']), key_vault_namespace, key_vault_coll_name)

# Insert to KeyVault if does'nt exist the key.
data_key_id = client_encryption.create_data_key('local', key_alt_names=['backend_app_encryption'])

## Explicitly encrypt a field.
json_test = {
    "name": "John Wick",
    "age": 50
}

age_field_encrypted = client_encryption.encrypt(json_test["age"], Algorithm.AEAD_AES_256_CBC_HMAC_SHA_512_Deterministic, key_id=data_key_id)
json_test["age"] = age_field_encrypted

test_coll.insert_one(json_test)
for cursor in test_coll.find({}):
    print(cursor)


## Cleanup resources
client_encryption.close()
DatabaseClient.close()
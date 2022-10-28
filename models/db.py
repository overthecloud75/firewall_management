from pymongo import MongoClient
from bson.objectid import ObjectId
# https://stackoverflow.com/questions/7846001/what-is-the-correct-way-to-query-mongodb-for-id-using-string-by-using-python

from configs import MONGO_URL 

mongoClient = MongoClient(MONGO_URL)
db = mongoClient['report']

# createIndex https://velopert.com/560
db.fail2ban_logs.create_index([('timestamp', 1), ('ip', 1)])
db.auth_logs.create_index([('timestamp', 1), ('ip', 1)])
db.nginx_access_logs.create_index([('timestamp', 1), ('ip', 1)])
db.nginx_error_logs.create_index([('timestamp', 1), ('ip', 1)])

class BasicModel:
    def __init__(self, model):
        self.model = model 
        self.db = db
        self.collection = self.db[self.model]
        
    def get_by_id(self, _id=''):
        try:
            data = self.collection.find_one({'_id': ObjectId(_id)})
        except Exception as e:
            data = None
            print(e)
        return data

    def post_by_id(self, request_data={}):
        try:
            _id = request_data['_id']
            del request_data['_id']
            self.collection.update_one({'_id': ObjectId(_id)}, {'$set': request_data}, upsert=True)
        except Exception as e:
            print(e)

    def _get_by_ip(self, ip):
        data_list = []
        results = self.collection.find({'ip': ip}).sort('timestamp', -1)
        for result in results:
            data_list.append(result)
        return data_list 


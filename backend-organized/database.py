import pymongo
from decouple import config

class Database:
    def __init__(self):
        # Establish a connection to the MongoDB database
        self.client = pymongo.MongoClient(config('MONGO_URI'))
        self.db = self.client['Stylin8']

    def get_user_collection(self):
        # Returns the 'User' collection
        return self.db['User']

    def get_clothes_collection(self):
        # Returns the 'Clothes' collection
        return self.db['Clothes']

    def insert_user(self, user_data):
        # Insert a new user into the 'User' collection
        return self.get_user_collection().insert_one(user_data)

    def find_user(self, query):
        # Find a user in the 'User' collection
        return self.get_user_collection().find_one(query)

    def update_user(self, query, update_data):
        # Update a user in the 'User' collection
        return self.get_user_collection().update_one(query, update_data)

    def insert_clothe(self, clothe_data):
        # Insert a new clothing item into the 'Clothes' collection
        return self.get_clothes_collection().insert_one(clothe_data)

    # Add other necessary database operations as methods of this class

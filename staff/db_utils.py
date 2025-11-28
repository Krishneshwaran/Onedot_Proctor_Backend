import os
from dotenv import load_dotenv
from pymongo import MongoClient

# Load environment variables
load_dotenv()

# Fetch MongoDB URI
MONGODB_URI = os.getenv('MONGODB_URI')
if not MONGODB_URI:
    raise ValueError("MongoDB URI is not set in environment variables.")

# Singleton MongoDB client
_client = MongoClient(MONGODB_URI)
_db = _client['test_portal_db']

def get_questions_collection():
    return _db['MCQ_Questions_Library']

def get_tests_collection():
    return _db['MCQ_Tests_Library']
import csv
import json
import uuid
import re
import logging
from django.conf import settings
import jwt
import os
from bson import ObjectId
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.files.storage import FileSystemStorage
import bleach
import pymongo.errors
from .db_utils import get_questions_collection, get_tests_collection
from datetime import datetime, timezone

JWT_SECRET = 'test'
JWT_ALGORITHM = "HS256"

# Configure logging
logger = logging.getLogger(__name__)

# Collections from utils
questions_collection = get_questions_collection()
tests_collection = get_tests_collection()

# Maximum string length for fields
MAX_STRING_LENGTH = 500

# Helper Functions
def sanitize_input(value):
    """Sanitize input to prevent injection attacks."""
    if isinstance(value, str):
        return bleach.clean(value[:MAX_STRING_LENGTH])
    return value

def validate_options(options, min_options=2, max_options=6):
    """Validate options list."""
    non_empty_options = [opt for opt in options if opt.strip()]
    return min_options <= len(non_empty_options) <= max_options and len(set(non_empty_options)) == len(non_empty_options)

def validate_correct_answer(correct_answer, options):
    """Ensure correct answer is in options."""
    return correct_answer in options

def handle_exception(e, default_message="An unexpected error occurred"):
    """Standardize exception handling."""
    logger.error(f"Error: {str(e)}")
    if isinstance(e, json.JSONDecodeError):
        return JsonResponse({"error": "Invalid JSON payload"}, status=400)
    elif isinstance(e, pymongo.errors.ConnectionFailure):
        return JsonResponse({"error": "Database connection failed"}, status=503)
    return JsonResponse({"error": default_message}, status=500)

def extract_jwt_token(request):
    """Extract JWT token from Authorization header or cookies."""
    # First try to get from Authorization header
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header.split(" ")[1]
    
    # If not in header, try to get from cookies
    jwt_cookie = request.COOKIES.get('jwt')
    if jwt_cookie:
        return jwt_cookie
        
    return None

def validate_jwt_token(token):
    """
    Validates the JWT token and returns the decoded payload if valid.
    Returns None if invalid.
    """
    try:
        # Decode and verify the token
        decoded_payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        
        # Check if the token has expired
        if 'exp' in decoded_payload:
            exp_timestamp = decoded_payload['exp']
            current_timestamp = datetime.now(tz=timezone.utc).timestamp()
            
            if current_timestamp > exp_timestamp:
                return None  # Token has expired
        
        return decoded_payload
    except jwt.InvalidTokenError:
        return None  # Invalid token
    except Exception as e:
        logger.error(f"Error validating JWT token: {e}")
        return None

def check_permissions(request):
    """JWT-based permission check from header or cookies."""
    token = extract_jwt_token(request)
    if not token:
        return JsonResponse({"error": "Authentication required"}, status=401)
    
    # Validate the JWT token
    decoded_payload = validate_jwt_token(token)
    if not decoded_payload:
        return JsonResponse({"error": "Invalid or expired token"}, status=401)
    
    # Check if the token contains either a staff_user or student_id
    # This ensures only valid users can access the endpoints
    if not (decoded_payload.get('staff_user') or decoded_payload.get('student_id')):
        return JsonResponse({"error": "Insufficient permissions"}, status=403)
    
    # Optionally add more specific role-based checks here if needed
    
    return None


# View Functions
@csrf_exempt
def bulk_upload_mcq(request):
    # permission_error = check_permissions(request)
    # if permission_error:
    #     return permission_error

    if request.method == "POST" and request.FILES.get("file"):
        file = request.FILES["file"]
        if not file.name.endswith('.csv'):
            return JsonResponse({"error": "File must be a CSV"}, status=400)

        fs = FileSystemStorage(location="uploads/")
        filename = fs.save(file.name, file)
        file_path = fs.path(filename)

        try:
            with open(file_path, "r", encoding="utf-8-sig") as csv_file:
                csv_reader = csv.DictReader(csv_file)
                questions = []
                for row in csv_reader:
                    first_key = list(row.keys())[0]
                    question = sanitize_input(row.get(first_key if '\ufeff' in first_key else "question", "").strip())
                    options = [sanitize_input(row.get(f"option{i}", "").strip()) for i in range(1, 7) if row.get(f"option{i}")]
                    correct_answer = sanitize_input(row.get("correctAnswer", "").strip())
                    level = sanitize_input(row.get("Level", "general").strip().lower())
                    tags = sanitize_input(row.get("tags", "").strip())
                    blooms = sanitize_input(row.get("blooms", "").strip())

                    if level not in {"easy", "medium", "hard"}:
                        level = "general"

                    if not all([question, correct_answer]) or not validate_options(options):
                        logger.warning(f"Skipping invalid row: {row}")
                        continue

                    if not validate_correct_answer(correct_answer, options):
                        logger.warning(f"Invalid answer for question: {question}")
                        continue

                    question_data = {
                        "question_id": str(uuid.uuid4()),
                        "question": question,
                        "options": options,
                        "correctAnswer": correct_answer,
                        "level": level,
                        "tags": tags,
                        "blooms": blooms
                    }
                    questions.append(question_data)

                if questions:
                    result = questions_collection.insert_many(questions)
                    logger.info(f"Inserted {len(result.inserted_ids)} questions")
                    return JsonResponse({
                        "message": f"File uploaded and {len(result.inserted_ids)} questions stored successfully!",
                        "inserted_count": len(result.inserted_ids)
                    }, status=200)
                return JsonResponse({"error": "No valid questions found in the CSV file"}, status=400)

        except csv.Error as e:
            return JsonResponse({"error": f"CSV parsing error: {str(e)}"}, status=400)
        except Exception as e:
            return handle_exception(e)
        finally:
            fs.delete(filename)

    return JsonResponse({"error": "Invalid request. Please upload a file"}, status=400)

@csrf_exempt
def upload_single_question(request):
    # permission_error = check_permissions(request)
    # if permission_error:
    #     return permission_error

    if request.method == "POST":
        try:
            data = json.loads(request.body)
            question = sanitize_input(data.get("question", "").strip())
            options = [sanitize_input(data.get(f"option{i}", "").strip()) for i in range(1, 7)]
            correct_answer = sanitize_input(data.get("answer", "").strip())
            level = sanitize_input(data.get("level", "general").strip())
            tags = [sanitize_input(tag) for tag in data.get("tags", [])]
            blooms = sanitize_input(data.get("blooms", "").strip())

            non_empty_options = [opt for opt in options if opt]
            if not all([question, correct_answer]) or not validate_options(non_empty_options):
                return JsonResponse({"error": "Missing required fields or invalid options"}, status=400)

            if not validate_correct_answer(correct_answer, non_empty_options):
                return JsonResponse({"error": "Invalid answer"}, status=400)
            
            question_id = str(uuid.uuid4())

            question_data = {
                "question_id": str(uuid.uuid4()),
                "question": question,
                "options": non_empty_options,
                "correctAnswer": correct_answer,
                "level": level,
                "tags": tags,
                "blooms": blooms
            }

            result = questions_collection.insert_one(question_data)
            return JsonResponse({
                "message": "Question uploaded successfully!",
                "question_id": question_id
            }, status=200)

        except Exception as e:
            return handle_exception(e)

    return JsonResponse({"error": "Only POST requests are allowed"}, status=405)

@csrf_exempt
def fetch_all_questions(request):
    try:
        level = request.GET.get('level', '').strip()
        tags = request.GET.getlist('tags')
        search = request.GET.get('search', '').strip()

        query = {}
        if level:
            query['level'] = level
        if tags:
            query['tags'] = {'$all': tags}
        if search:
            query['$or'] = [
                {'question': {'$regex': re.escape(search), '$options': 'i'}},
                {'tags': {'$regex': re.escape(search), '$options': 'i'}}
            ]

        questions = list(questions_collection.find(query, {'_id': 0}))
        return JsonResponse({"questions": questions}, status=200)

    except Exception as e:
        return handle_exception(e)

@csrf_exempt
def update_question(request, question_id):
    # permission_error = check_permissions(request)
    # if permission_error:
    #     return permission_error

    if request.method == "PUT":
        try:
            data = json.loads(request.body)
            question = sanitize_input(data.get("question", "").strip())
            options = [sanitize_input(opt) for opt in data.get("options", [])]
            correct_answer = sanitize_input(data.get("correctAnswer", "").strip())
            level = sanitize_input(data.get("level", "general").strip())
            tags = [sanitize_input(tag) for tag in data.get("tags", [])]

            if not all([question, correct_answer]) or not validate_options(options, max_options=4):
                return JsonResponse({"error": "Invalid input data"}, status=400)

            if not validate_correct_answer(correct_answer, options):
                return JsonResponse({"error": "Answer must be one of the options"}, status=400)

            update_data = {
                "question": question,
                "options": options,
                "correctAnswer": correct_answer,
                "level": level,
                "tags": tags,
            }

            result = questions_collection.update_one({"question_id": question_id}, {"$set": update_data})
            if result.matched_count == 0:
                return JsonResponse({"error": "Question not found"}, status=404)

            return JsonResponse({"message": "Question updated successfully"}, status=200)

        except Exception as e:
            return handle_exception(e)

    return JsonResponse({"error": "Only PUT requests are allowed"}, status=405)

@csrf_exempt
def delete_question(request, question_id):
    # permission_error = check_permissions(request)
    # if permission_error:
    #     return permission_error

    if not question_id or question_id == "undefined":
        return JsonResponse({"error": "Invalid question ID"}, status=400)

    if request.method == "DELETE":
        try:
            result = questions_collection.delete_one({"question_id": question_id})
            if result.deleted_count == 0:
                return JsonResponse({"error": "Question not found"}, status=404)

            return JsonResponse({"message": "Question deleted successfully"}, status=200)

        except Exception as e:
            return handle_exception(e)

    return JsonResponse({"error": "Only DELETE requests are allowed"}, status=405)

@csrf_exempt
def create_test(request):
    # Skip authentication check for this endpoint
    # permission_error = check_permissions(request)
    # if permission_error:
    #     return permission_error

    if request.method == "POST":
        try:
            data = json.loads(request.body)
            test_name = sanitize_input(data.get("test_name", "").strip())
            questions = data.get("questions", [])
            level = sanitize_input(data.get("level", "general").strip())
            tags = [sanitize_input(tag) for tag in data.get("tags", [])]
            category = sanitize_input(data.get("category", "").strip())

            if not test_name or not questions:
                return JsonResponse({"error": "Test name and questions are required"}, status=400)

            test_data = {
                "test_id": str(uuid.uuid4()),
                "test_name": test_name,
                "questions": questions,
                "level": level,
                "tags": tags,
                "category": category
            }

            result = tests_collection.insert_one(test_data)
            return JsonResponse({
                "message": "Test created successfully!",
                "test_id": str(result.inserted_id)
            }, status=200)

        except Exception as e:
            return handle_exception(e)

    return JsonResponse({"error": "Only POST requests are allowed"}, status=405)


@csrf_exempt
def update_test(request, test_id):
    # Skip authentication check for this endpoint
    # permission_error = check_permissions(request)
    # if permission_error:
    #     return permission_error

    if request.method == "PUT":
        try:
            data = json.loads(request.body)
            test_name = sanitize_input(data.get("test_name", "").strip())
            level = sanitize_input(data.get("level", "general").strip())
            tags = [sanitize_input(tag) for tag in data.get("tags", [])]
            category = sanitize_input(data.get("category", "").strip())

            if not test_name or not category:
                return JsonResponse({"error": "Test name and category are required"}, status=400)

            update_data = {
                "test_name": test_name,
                "level": level,
                "tags": tags,
                "category": category
            }

            result = tests_collection.update_one({"test_id": test_id}, {"$set": update_data})
            if result.matched_count == 0:
                return JsonResponse({"error": "Test not found"}, status=404)

            return JsonResponse({"message": "Test updated successfully"}, status=200)

        except Exception as e:
            return handle_exception(e)

    return JsonResponse({"error": "Only PUT requests are allowed"}, status=405)

@csrf_exempt
def delete_test(request, test_id):
    # Skip authentication check for this endpoint
    # permission_error = check_permissions(request)
    # if permission_error:
    #     return permission_error

    if request.method == "DELETE":
        try:
            result = tests_collection.delete_one({"test_id": test_id})
            if result.deleted_count == 0:
                return JsonResponse({"error": "Test not found"}, status=404)

            return JsonResponse({"message": "Test deleted successfully"}, status=200)

        except Exception as e:
            return handle_exception(e)

    return JsonResponse({"error": "Only DELETE requests are allowed"}, status=405)
@csrf_exempt
def fetch_all_tests(request):
    try:
        query = {}
        sort_field = None
        sort_order = 1

        search_query = request.GET.get('search')
        if search_query:
            query['$or'] = [
                {'test_name': {'$regex': search_query, '$options': 'i'}},
                {'questions.question': {'$regex': search_query, '$options': 'i'}}
            ]

        filter_level = request.GET.get('level')
        if filter_level:
            query['level'] = filter_level

        sort_param = request.GET.get('sort')
        if sort_param:
            if sort_param == 'name_asc':
                sort_field = 'test_name'
                sort_order = 1
            elif sort_param == 'name_desc':
                sort_field = 'test_name'
                sort_order = -1
            elif sort_param == 'level_asc':
                sort_field = 'level'
                sort_order = 1
            elif sort_param == 'level_desc':
                sort_field = 'level'
                sort_order = -1

        tests = list(tests_collection.find(query).sort(sort_field, sort_order) if sort_field else tests_collection.find(query))
        tests = [json.loads(json.dumps(test, default=str)) for test in tests]
        return JsonResponse({"tests": tests}, status=200)

    except Exception as e:
        return handle_exception(e)

@csrf_exempt
def fetch_questions_for_test(request):
    try:
        test_id = request.GET.get('test_id')
        if not test_id:
            return JsonResponse({"error": "test_id is required"}, status=400)

        query = {'test_id': test_id}
        sort_field = None
        sort_order = 1

        search_query = request.GET.get('search')
        if search_query:
            query['questions.question'] = {'$regex': search_query, '$options': 'i'}

        filter_level = request.GET.get('level')
        if filter_level:
            query['questions.level'] = filter_level

        sort_param = request.GET.get('sort')
        if sort_param:
            if sort_param == 'name_asc':
                sort_field = 'questions.question'
                sort_order = 1
            elif sort_param == 'name_desc':
                sort_field = 'questions.question'
                sort_order = -1
            elif sort_param == 'level_asc':
                sort_field = 'questions.level'
                sort_order = 1
            elif sort_param == 'level_desc':
                sort_field = 'questions.level'
                sort_order = -1

        test = tests_collection.find_one(query, {'questions': 1})
        if not test:
            return JsonResponse({"error": "Test not found"}, status=404)

        questions = test.get('questions', [])
        if search_query:
            questions = [q for q in questions if re.search(search_query, q['question'], re.IGNORECASE)]
        if filter_level:
            questions = [q for q in questions if q['level'] == filter_level]
        if sort_field:
            questions = sorted(questions, key=lambda q: q.get(sort_field.split('.')[1]), reverse=(sort_order == -1))

        return JsonResponse({"questions": questions or []}, status=200)

    except Exception as e:
        return handle_exception(e)

@csrf_exempt
def bulk_upload_test(request):
    # Skip the authentication check for this particular endpoint
    # permission_error = check_permissions(request)
    # if permission_error:
    #     return permission_error

    if request.method == "POST":
        try:
            data = json.loads(request.body)
            test_id = data.get("test_id")
            test_name = sanitize_input(data.get("test_name", "").strip())
            level = sanitize_input(data.get("level", "general").strip().lower())
            tags = [sanitize_input(tag) for tag in data.get("tags", [])]
            questions = data.get("questions", [])
            category = sanitize_input(data.get("category", "").strip())

            # Rest of your existing function remains unchanged

            valid_questions = []
            for q in questions:
                question = sanitize_input(q.get("question", "").strip())
                options = [sanitize_input(opt) for opt in q.get("options", [])]
                correct_answer = sanitize_input(q.get("correctAnswer", "").strip())
                q_level = sanitize_input(q.get("level", "general").strip().lower())
                q_tags = [sanitize_input(tag) for tag in q.get("tags", [])]
                blooms = sanitize_input(q.get("blooms", "").strip())

                if not all([question, correct_answer, blooms]) or not validate_options(options):
                    continue
                if not validate_correct_answer(correct_answer, options):
                    continue

                valid_questions.append({
                    "question_id": str(uuid.uuid4()),
                    "question": question,
                    "options": options,
                    "correctAnswer": correct_answer,
                    "level": q_level,
                    "tags": q_tags,
                    "blooms": blooms
                })

            test_document = {
                "_id": ObjectId(),
                "test_id": test_id,
                "test_name": test_name,
                "level": level,
                "tags": tags,
                "questions": valid_questions,
                "category": category
            }

            result = tests_collection.update_one(
                {"test_id": test_id},
                {"$set": test_document},
                upsert=True
            )

            if result.upserted_id or result.modified_count > 0:
                return JsonResponse({
                    "message": f"Questions added to test {test_name} successfully!",
                    "inserted_count": len(valid_questions)
                }, status=200)
            return JsonResponse({"error": f"Test {test_name} not found"}, status=404)

        except Exception as e:
            return handle_exception(e)

    return JsonResponse({"error": "Invalid request"}, status=400)

@csrf_exempt
def delete_question_from_test(request, test_id, question_id):
    # Skip authentication check for this endpoint
    # permission_error = check_permissions(request)
    # if permission_error:
    #     return permission_error

    if request.method == "DELETE":
        try:
            result = tests_collection.update_one(
                {"test_id": test_id},
                {"$pull": {"questions": {"question_id": question_id}}}
            )
            if result.modified_count == 0:
                return JsonResponse({"error": "Question not found in the test"}, status=404)

            return JsonResponse({"message": "Question deleted from the test successfully"}, status=200)

        except Exception as e:
            return handle_exception(e)

    return JsonResponse({"error": "Only DELETE requests are allowed"}, status=405)

@csrf_exempt
def bulk_upload_questions_to_test(request):
    permission_error = check_permissions(request)
    if permission_error:
        return permission_error

    if request.method == "POST":
        try:
            data = json.loads(request.body)
            test_id = data.get("test_id").strip()
            questions = data.get("questions", [])
            print(f"Received test_id: '{test_id}'")
            print(f"Received questions count: {len(questions)}")

            if not test_id:
                return JsonResponse({"error": "test_id is required"}, status=400)

            valid_questions = []
            for q in questions:
                question = sanitize_input(q.get("question", "").strip())
                options = [sanitize_input(opt.strip()) for opt in q.get("options", [])]  # Fix here
                correct_answer = sanitize_input(q.get("correctAnswer", "").strip())
                level = sanitize_input(q.get("level", "general").strip().lower())
                tags = [sanitize_input(tag) for tag in q.get("tags", [])]
                blooms = sanitize_input(q.get("blooms", "").strip())

                non_empty_options = [opt for opt in options if opt]
                print(f"Question: {question}, Options: {non_empty_options}, Correct: {correct_answer}")
                if not all([question, correct_answer]) or not validate_options(non_empty_options):
                    print("Skipping: Validation failed for required fields or options")
                    continue
                if not validate_correct_answer(correct_answer, non_empty_options):
                    print("Skipping: Correct answer not in options")
                    continue

                valid_questions.append({
                    "question_id": str(uuid.uuid4()),
                    "question": question,
                    "options": non_empty_options,
                    "correctAnswer": correct_answer,
                    "level": level,
                    "tags": tags,
                    "blooms": blooms
                })

            print(f"Valid questions to insert: {len(valid_questions)}")
            result = tests_collection.update_one(
                {"test_id": test_id},
                {"$push": {"questions": {"$each": valid_questions}}}
            )
            print(f"Modified count: {result.modified_count}")

            if result.modified_count > 0:
                return JsonResponse({
                    "message": f"Added {len(valid_questions)} questions to test {test_id} successfully!",
                    "inserted_count": len(valid_questions)
                }, status=200)
            return JsonResponse({"error": f"Test {test_id} not found"}, status=404)

        except Exception as e:
            return handle_exception(e)

    return JsonResponse({"error": "Invalid request"}, status=400)

@csrf_exempt
def append_question_to_test(request):
    # Skip authentication check for this endpoint
    # permission_error = check_permissions(request)
    # if permission_error:
    #     return permission_error

    if request.method == "POST":
        try:
            data = json.loads(request.body)
            test_id = data.get("test_id")
            question = sanitize_input(data.get("question", "").strip())
            options = [sanitize_input(data.get(f"option{i}", "").strip()) for i in range(1, 5)]
            correct_answer = sanitize_input(data.get("correctAnswer", "").strip())
            level = sanitize_input(data.get("level", "general").strip().lower())
            tags = [sanitize_input(tag) for tag in data.get("tags", [])]
            blooms = sanitize_input(data.get("blooms", "").strip())

            non_empty_options = [opt for opt in options if opt]
            if not all([test_id, question, correct_answer]) or not validate_options(non_empty_options):
                return JsonResponse({"error": "Missing required fields or invalid options"}, status=400)

            if not validate_correct_answer(correct_answer, non_empty_options):
                return JsonResponse({"error": "Invalid answer"}, status=400)

            new_question = {
                "question_id": str(uuid.uuid4()),
                "question": question,
                "options": non_empty_options,
                "correctAnswer": correct_answer,
                "level": level,
                "tags": tags,
                "blooms": blooms
            }

            result = tests_collection.update_one(
                {"test_id": test_id},
                {"$push": {"questions": new_question}}
            )

            if result.modified_count == 0:
                return JsonResponse({"error": "Test not found"}, status=404)

            return JsonResponse({"message": "Question appended to the test successfully"}, status=200)

        except Exception as e:
            return handle_exception(e)

    return JsonResponse({"error": "Only POST requests are allowed"}, status=405)

@csrf_exempt
def edit_question_in_test(request, test_id, question_id):
    # Skip authentication check for this endpoint
    # permission_error = check_permissions(request)
    # if permission_error:
    #     return permission_error

    if request.method == "PUT":
        try:
            data = json.loads(request.body)
            question = sanitize_input(data.get("question", "").strip())
            options = [sanitize_input(opt) for opt in data.get("options", [])]
            correct_answer = sanitize_input(data.get("correctAnswer", "").strip())
            level = sanitize_input(data.get("level", "general").strip().lower())
            tags = [sanitize_input(tag) for tag in data.get("tags", [])]
            blooms = sanitize_input(data.get("blooms", "").strip())

            if not all([question, correct_answer]) or not validate_options(options, max_options=4):
                return JsonResponse({"error": "Invalid input data"}, status=400)

            if not validate_correct_answer(correct_answer, options):
                return JsonResponse({"error": "Answer must be one of the options"}, status=400)

            result = tests_collection.update_one(
                {"test_id": test_id, "questions.question_id": question_id},
                {"$set": {
                    "questions.$.question": question,
                    "questions.$.options": options,
                    "questions.$.correctAnswer": correct_answer,
                    "questions.$.level": level,
                    "questions.$.tags": tags,
                    "questions.$.blooms": blooms
                }}
            )

            if result.matched_count == 0:
                return JsonResponse({"error": "Question not found in the test"}, status=404)

            return JsonResponse({"message": "Question updated successfully"}, status=200)

        except Exception as e:
            return handle_exception(e)

    return JsonResponse({"error": "Only PUT requests are allowed"}, status=405)

# Indexing for performance (run once during setup)
def setup_indexes():
    questions_collection.create_index([("question_id", 1)], unique=True)
    tests_collection.create_index([("test_id", 1)], unique=True)
    tests_collection.create_index([("questions.question_id", 1)])

if __name__ == "__main__":
    setup_indexes()
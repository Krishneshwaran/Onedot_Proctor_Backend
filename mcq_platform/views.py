import os
import json
import re
import jwt
import datetime
import csv
from io import StringIO
import google.generativeai as genai
import logging
from bson.objectid import ObjectId
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from bson import errors
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from pymongo import MongoClient
import random
from dotenv import load_dotenv


# Load environment variables from .env file
load_dotenv()

# Initialize MongoDB client
client = MongoClient(os.getenv("MONGODB_URI"))
db = client["test_portal_db"]
collection = db["MCQ_Assessment_Data"]
section_collection = db["MCQ_Assessment_Section_Data"]
assessment_questions_collection = db["MCQ_Assessment_Data"]
mcq_report_collection = db["MCQ_Assessment_report"]
coding_report_collection = db["coding_report"]
staff_collection = db['staff']
students_collection = db['students']
certificate_collection = db['certificate']

logger = logging.getLogger(__name__)

SECRET_KEY = os.getenv("SECRET_KEY")
JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM")


# Configure the model
# Configure the model
api_key = os.environ.get("GEMINI_AI_KEY")  # Get the key from .env
genai.configure(api_key=api_key)
model = genai.GenerativeModel('gemini-1.5-pro')

def decode_token(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        contest_id = payload.get("contestId")
        if not contest_id:
            raise ValueError("Invalid token: 'contestId' not found.")
        return contest_id
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired.")
    except jwt.InvalidTokenError:
        raise ValueError("Invalid token.")

@csrf_exempt
def start_contest(request):
    """
    Start a new contest by generating a JWT token for the given contest ID.

    Args:
        request: The HTTP request object containing the contest ID in the request body.

    Returns:
        JsonResponse: A JSON response containing the generated token if successful, or an error message if not.
    """
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            contest_id = data.get("contestId")
            if not contest_id:
                return JsonResponse({"error": "Contest ID is required"}, status=400)

            payload = {
                "contestId": contest_id,
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1),
            }
            token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

            return JsonResponse({"token": token}, status=200)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    return JsonResponse({"error": "Invalid request method"}, status=400)

@csrf_exempt
def get_test_date(request):
    if request.method == "GET":
        student_id = request.GET.get("student_id")
        contest_id = request.GET.get("contest_id")
        collection_result = db["MCQ_Assessment_report"]

        if not student_id or not contest_id:
            return JsonResponse({"error": "Missing student_id or contest_id"}, status=400)

        # Find the contest document with the matching contest_id
        contest = collection_result.find_one({"contest_id": contest_id})
        if not contest:
            return JsonResponse({"error": "Contest not found"}, status=404)

        # Find the student record with completed status
        student_data = next(
            (student for student in contest["students"] 
             if student["student_id"] == student_id and student["status"].lower() == "completed"),
            None
        )

        if not student_data:
            return JsonResponse({"error": "Student not found or contest not completed"}, status=404)

        # Get the finish time
        finish_time = student_data.get("finishTime", None)

        if isinstance(finish_time, str):  # If it's a string, convert it to datetime
            finish_time = datetime.datetime.strptime(finish_time, "%Y-%m-%dT%H:%M:%S.%fZ")
        elif not isinstance(finish_time, datetime.datetime):  # If it's in an unexpected format
            return JsonResponse({"error": "Invalid finish time format"}, status=500)

        return JsonResponse({"finish_time": finish_time.isoformat()})

    return JsonResponse({"error": "Invalid request method"}, status=405)

def generate_token(contest_id):
    """
    Generate a JWT token for a given contest ID.

    Args:
        contest_id: The ID of the contest for which the token is generated.

    Returns:
        str: The generated JWT token.
    """
    payload = {
        "contest_id": contest_id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import json
import datetime
from bson import ObjectId

@csrf_exempt
def save_data(request):
    """
    Save assessment data for a contest with robust algorithm handling.
    """
    if request.method != "POST":
        return JsonResponse({"error": "Invalid request method"}, status=400)
    
    try:
        # Multi-source token retrieval
        jwt_token = None
        
        # Try cookies
        for cookie_name in ["jwt", "access_token", "token", "stafftoken"]:
            if cookie_name in request.COOKIES:
                jwt_token = request.COOKIES.get(cookie_name)
                break
                
        # Try header
        if not jwt_token:
            auth_header = request.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                jwt_token = auth_header.split(' ')[1]
        
        # Try body
        if not jwt_token:
            try:
                data = json.loads(request.body)
                for field in ['token', 'stafftoken', 'access_token', 'jwt']:
                    if field in data:
                        jwt_token = data.get(field)
                        if jwt_token:
                            break
            except:
                pass
                
        if not jwt_token:
            return JsonResponse({"error": "Authentication credentials were not provided."}, status=401)
        
        # Clean token
        jwt_token = jwt_token.strip().replace('"', '').replace("'", "") if isinstance(jwt_token, str) else jwt_token
        
        # *** FIX: Try multiple algorithms and secrets ***
        decoded_token = None
        last_error = None
        
        # Array of possible algorithms to try
        algorithms = ["HS256", "RS256"]
        if JWT_ALGORITHM:
            algorithms.insert(0, JWT_ALGORITHM)  # Try configured algorithm first
            
        # Secrets to try
        secrets = [JWT_SECRET]
        if SECRET_KEY and SECRET_KEY != JWT_SECRET:
            secrets.append(SECRET_KEY)
            
        # Try each combination of secret and algorithm
        for secret in secrets:
            if not secret:
                continue
                
            for alg in algorithms:
                try:
                    decoded_token = jwt.decode(jwt_token, secret, algorithms=[alg])
                    break  # Success - exit loop
                except Exception as e:
                    last_error = e
                    continue
                    
            if decoded_token:
                break  # Found a working combination
                
        if not decoded_token:
            return JsonResponse({"error": f"Token validation failed: {str(last_error)}"}, status=401)
            
        # Extract staff_id - check multiple possible field names
        staff_id = None
        for field in ['staff_user', 'staff_id', 'user_id', 'id', 'sub']:
            if field in decoded_token:
                staff_id = decoded_token.get(field)
                if staff_id:
                    break
                    
        if not staff_id:
            return JsonResponse({"error": "Invalid token payload: missing staff ID"}, status=401)
            
        # Find staff details
        try:
            # Convert to ObjectId if it's a string and valid format
            if isinstance(staff_id, str) and len(staff_id) == 24:
                try:
                    staff_id_obj = ObjectId(staff_id)
                except:
                    staff_id_obj = staff_id
            else:
                staff_id_obj = staff_id
                
            staff_details = staff_collection.find_one({"_id": staff_id_obj})
            
            # Try alternate fields if first attempt fails
            if not staff_details:
                staff_details = staff_collection.find_one({"staffId": staff_id})
                
            if not staff_details:
                return JsonResponse({"error": "Staff not found"}, status=404)
                
        except Exception as e:
            return JsonResponse({"error": f"Database error: {str(e)}"}, status=500)
            
        # Parse request data
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({"error": "Invalid JSON data"}, status=400)
            
        # Add staff info to data
        data.update({
            "staffId": staff_id,
            "department": staff_details.get("department"),
            "college": staff_details.get("collegename"),
            "name": staff_details.get("full_name")
        })
        
        # Validate contest ID
        contest_id = data.get("contestId")
        if not contest_id:
            return JsonResponse({"error": "contestId is required"}, status=400)
            
        # Validate assessment overview and dates
        if "assessmentOverview" not in data or "registrationStart" not in data["assessmentOverview"] or "registrationEnd" not in data["assessmentOverview"]:
            return JsonResponse({"error": "'registrationStart' or 'registrationEnd' is missing in 'assessmentOverview'"}, status=400)
            
        # Handle date conversion
        try:
            # Try multiple date formats for each date field
            for field in ["registrationStart", "registrationEnd"]:
                date_str = data["assessmentOverview"][field]
                
                if isinstance(date_str, str):
                    try:
                        # Try direct ISO format
                        data["assessmentOverview"][field] = datetime.datetime.fromisoformat(date_str)
                    except ValueError:
                        # Clean the date string and try again
                        clean_date = date_str.replace('Z', '')
                        if '+' in clean_date:
                            clean_date = clean_date.split('+')[0]
                        if '.' in clean_date:
                            clean_date = clean_date.split('.')[0]
                            
                        # For YYYY-MM-DDThh:mm format (without seconds)
                        if len(clean_date) == 16:
                            clean_date += ":00"
                            
                        data["assessmentOverview"][field] = datetime.datetime.fromisoformat(clean_date)
        except ValueError as e:
            return JsonResponse({"error": f"Invalid date format: {str(e)}"}, status=400)
            
        # Insert data
        try:
            collection.insert_one(data)
        except Exception as e:
            return JsonResponse({"error": f"Database error: {str(e)}"}, status=500)
            
        # Return success response
        return JsonResponse({
            "message": "Data saved successfully",
            "contestId": contest_id,
            "staffDetails": {
                "name": staff_details.get("full_name"),
                "department": staff_details.get("department"),
                "college": staff_details.get("collegename")
            }
        }, status=200)
        
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)
        
@csrf_exempt
def save_question(request):
    """
    Save questions for a contest.

    Args:
        request: The HTTP request object containing the questions in the request body.

    Returns:
        JsonResponse: A JSON response indicating success or an error message if the data is invalid or missing.
    """
    if request.method == "POST":
        try:
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                return JsonResponse({"error": "Authorization header missing or invalid."}, status=401)

            token = auth_header.split(" ")[1]
            contest_id = decode_token(token)

            data = json.loads(request.body)
            questions = data.get("questions", [])

            if not questions:
                return JsonResponse({"error": "No questions provided"}, status=400)

            assessment = assessment_questions_collection.find_one({"contestId": contest_id})
            if not assessment:
                assessment_questions_collection.insert_one({
                    "contestId": contest_id,
                    "questions": [],
                    "previousQuestionCount": 0
                })
                previous_count = 0
            else:
                previous_count = len(assessment.get("questions", []))

            added_questions = []
            for question in questions:
                question_id = ObjectId()
                question["_id"] = question_id
                added_questions.append(question)

            if added_questions:
                assessment_questions_collection.update_one(
                    {"contestId": contest_id},
                    {
                        "$push": {"questions": {"$each": added_questions}},
                        "$set": {"previousQuestionCount": previous_count}
                    }
                )

            for question in added_questions:
                question["_id"] = str(question["_id"])

            return JsonResponse({
                "message": "Questions added successfully!",
                "added_questions": added_questions,
                "previousQuestionCount": previous_count
            }, status=200)

        except ValueError as e:
            return JsonResponse({"error": str(e)}, status=401)
        except Exception as e:
            return JsonResponse({"error": f"An unexpected error occurred: {str(e)}"}, status=500)
    return JsonResponse({"error": "Invalid request method"}, status=405)

@csrf_exempt
def get_questions(request):
    """
    Retrieve questions for a contest.

    Args:
        request: The HTTP request object.

    Returns:
        JsonResponse: A JSON response containing the questions if found, or an error message if not.
    """
    if request.method == "GET":
        try:
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                return JsonResponse({"error": "Unauthorized access"}, status=401)

            token = auth_header.split(" ")[1]
            contest_id = decode_token(token)

            assessment = assessment_questions_collection.find_one({"contestId": contest_id})
            if not assessment:
                assessment_questions_collection.insert_one({
                    "contestId": contest_id,
                    "questions": []
                })
                assessment = {"contestId": contest_id, "questions": []}

            questions = assessment.get("questions", [])
            previousQuestionCount = assessment.get("previousQuestionCount", 0)

            unique_questions = []
            seen_questions = set()
            duplicate_count = 0

            for question in questions:
                question_key = f"{question['question']}-{'-'.join(question['options'])}"
                if question_key not in seen_questions:
                    seen_questions.add(question_key)
                    unique_questions.append(question)
                else:
                    duplicate_count += 1

            new_previous_question_count = len(unique_questions)
            assessment_questions_collection.update_one(
                {"contestId": contest_id},
                {"$set": {"questions": unique_questions, "previousQuestionCount": new_previous_question_count}}
            )

            for question in unique_questions:
                if "_id" in question:
                    question["_id"] = str(question["_id"])

            return JsonResponse({
                "questions": unique_questions,
                "duplicates_removed": duplicate_count,
                "previousQuestionCount": previousQuestionCount,
            }, status=200)

        except ValueError as e:
            return JsonResponse({"error": str(e)}, status=401)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request method"}, status=400)

@csrf_exempt
def update_mcqquestion(request, question_id):
    """
    Update a specific MCQ question in a contest.

    Args:
        request: The HTTP request object containing the updated question data in the request body.
        question_id: The ID of the question to be updated.

    Returns:
        JsonResponse: A JSON response indicating success or an error message if the question is not found or the data is invalid.
    """
    if request.method == "PUT":
        try:
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                return JsonResponse({"error": "Authorization header missing or invalid."}, status=401)

            token = auth_header.split(" ")[1]
            contest_id = decode_token(token)

            data = json.loads(request.body)

            try:
                object_id = ObjectId(question_id)
            except Exception:
                return JsonResponse({"error": "Invalid question ID format."}, status=400)

            result = assessment_questions_collection.update_one(
                {
                    "contestId": contest_id,
                    "questions._id": object_id
                },
                {
                    "$set": {
                        "questions.$.question": data.get("question"),
                        "questions.$.options": data.get("options"),
                        "questions.$.correctAnswer": data.get("correctAnswer"),
                        "questions.$.level": data.get("level"),
                        "questions.$.tags": data.get("tags", [])
                    }
                }
            )

            if result.matched_count == 0:
                return JsonResponse({"error": "Question not found"}, status=404)

            return JsonResponse({"message": "Question updated successfully"}, status=200)

        except Exception as e:
            return JsonResponse({"error": f"An unexpected error occurred: {str(e)}"}, status=500)
    return JsonResponse({"error": "Invalid request method"}, status=405)

@csrf_exempt
def delete_question(request, question_id):
    """
    Delete a specific MCQ question from a contest.

    Args:
        request: The HTTP request object.
        question_id: The ID of the question to be deleted.

    Returns:
        JsonResponse: A JSON response indicating success or an error message if the question is not found.
    """
    if request.method == "DELETE":
        try:
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                return JsonResponse({"error": "Authorization header missing or invalid."}, status=401)

            token = auth_header.split(" ")[1]
            contest_id = decode_token(token)

            assessment = assessment_questions_collection.find_one({"contestId": contest_id})
            if not assessment:
                return JsonResponse({"error": "Contest not found"}, status=404)

            try:
                object_id = ObjectId(question_id)
            except Exception:
                return JsonResponse({"error": "Invalid question ID format."}, status=400)

            question_to_delete = None
            for question in assessment.get("questions", []):
                if question["_id"] == object_id:
                    question_to_delete = question
                    break

            if not question_to_delete:
                return JsonResponse({"error": "Question not found"}, status=404)

            result = assessment_questions_collection.update_one(
                {"contestId": contest_id},
                {"$pull": {"questions": {"question": question_to_delete["question"], "options": question_to_delete["options"]}}}
            )

            if result.modified_count == 0:
                return JsonResponse({"error": "Question not found"}, status=404)

            return JsonResponse({"message": "All duplicate questions deleted successfully"}, status=200)

        except Exception as e:
            return JsonResponse({"error": f"An unexpected error occurred: {str(e)}"}, status=500)

    return JsonResponse({"error": "Invalid request method"}, status=405)

@csrf_exempt
def update_question(request):
    """
    Update a question in a contest.

    Args:
        request: The HTTP request object containing the updated question data in the request body.

    Returns:
        JsonResponse: A JSON response indicating success or an error message if the question is not found or the data is invalid.
    """
    if request.method == "PUT":
        try:
            token = request.headers.get("Authorization").split(" ")[1]
            contest_id = decode_token(token)

            data = json.loads(request.body)
            question_id = data.get("question_id")

            result = assessment_questions_collection.update_one(
                {
                    "contest_id": contest_id,
                    "questions.question_id": question_id,
                },
                {
                    "$set": {
                        "questions.$.questionType": data.get("questionType", "MCQ"),
                        "questions.$.question": data.get("question", ""),
                        "questions.$.options": data.get("options", []),
                        "questions.$.correctAnswer": data.get("correctAnswer", ""),
                        "questions.$.mark": data.get("mark", 0),
                        "questions.$.negativeMark": data.get("negativeMark", 0),
                        "questions.$.randomizeOrder": data.get("randomizeOrder", False),
                    }
                }
            )

            if result.matched_count == 0:
                return JsonResponse({"error": "Question not found"}, status=404)

            return JsonResponse({"message": "Question updated successfully"})
        except ValueError as e:
            return JsonResponse({"error": str(e)}, status=401)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    return JsonResponse({"error": "Invalid request method"}, status=400)

@csrf_exempt
def finish_contest(request):
    """
    Finalize a contest by saving the question data.

    Args:
        request: The HTTP request object containing the question data in the request body.

    Returns:
        JsonResponse: A JSON response indicating success or an error message if the data is invalid or missing.
    """
    if request.method == "POST":
        try:
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                return JsonResponse({"error": "Authorization header missing or invalid."}, status=401)

            token = auth_header.split(" ")[1]
            contest_id = decode_token(token)

            data = json.loads(request.body)
            questions_data = data.get("questions", [])

            if not questions_data:
                return JsonResponse({"error": "No question data provided."}, status=400)

            existing_entry = collection.find_one({"contestId": contest_id})

            if existing_entry:
                collection.update_one(
                    {"contestId": contest_id},
                    {"$set": {"questions": questions_data}}
                )
            else:
                collection.insert_one({
                    "contestId": contest_id,
                    "questions": questions_data,
                    "assessmentOverview": {},
                    "testConfiguration": {}
                })

            return JsonResponse({"message": "Contest finished successfully!"}, status=200)
        except ValueError as e:
            return JsonResponse({"error": str(e)}, status=401)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    return JsonResponse({"error": "Invalid request method"}, status=400)

@csrf_exempt
def bulk_upload_questions(request):
    """
    Bulk upload questions from a CSV file for a contest.

    Args:
        request: The HTTP request object containing the CSV file in the request body.

    Returns:
        JsonResponse: A JSON response containing the parsed questions or an error message if the file is invalid.
    """
    if request.method == "POST":
        try:
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                return JsonResponse({"error": "Authorization header missing or invalid."}, status=401)

            token = auth_header.split(" ")[1]
            contest_id = decode_token(token)

            file = request.FILES.get("file")
            if not file:
                return JsonResponse({"error": "No file uploaded"}, status=400)

            file_data = file.read().decode("utf-8")
            csv_reader = csv.DictReader(StringIO(file_data))
            questions = []

            for row in csv_reader:
                try:
                    mark = int(row.get("mark", 0)) if row.get("mark") else 0
                    negative_mark = int(row.get("negative_marking", 0)) if row.get("negative_marking") else 0

                    question = {
                        "questionType": "MCQ",
                        "question": row.get("question", "").strip(),
                        "options": [
                            row.get("option_1", "").strip(),
                            row.get("option_2", "").strip(),
                            row.get("option_3", "").strip(),
                            row.get("option_4", "").strip(),
                            row.get("option_5", "").strip(),
                            row.get("option_6", "").strip(),
                        ],
                        "correctAnswer": row.get("correct_answer", "").strip(),
                        "mark": mark,
                        "negativeMark": negative_mark,
                        "randomizeOrder": False,
                        "level": row.get("level", "easy").strip(),
                        "tags": row.get("tags", "").split(",") if row.get("tags") else [],
                    }
                    questions.append(question)
                except Exception as e:
                    return JsonResponse({"error": f"Error in row: {row}. Details: {str(e)}"}, status=400)

            return JsonResponse({"questions": questions}, status=200)
        except ValueError as e:
            return JsonResponse({"error": str(e)}, status=401)
        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)
    return JsonResponse({"error": "Invalid request method"}, status=400)

@csrf_exempt
def publish_mcq(request):
    """
    Publish MCQ questions and assign them to selected students.

    Args:
        request: The HTTP request object containing the student IDs in the request body.

    Returns:
        JsonResponse: A JSON response indicating success or an error message if the data is invalid or missing.
    """
    if request.method == 'POST':
        try:
            auth_header = request.headers.get("Authorization")
            if not auth_header or not auth_header.startswith("Bearer "):
                return JsonResponse({"error": "Authorization header missing or invalid."}, status=401)

            token = auth_header.split(" ")[1]
            contest_id = decode_token(token)

            data = json.loads(request.body)
            selected_students = data.get('students', [])

            if not contest_id:
                return JsonResponse({'error': 'Contest ID is required'}, status=400)
            if not isinstance(selected_students, list) or not selected_students:
                return JsonResponse({'error': 'No students selected'}, status=400)

            existing_document = collection.find_one({"contestId": contest_id})
            if not existing_document:
                return JsonResponse({'error': 'Contest not found'}, status=404)

            if existing_document.get("assessmentOverview", {}).get("sectionDetails") == "Yes":
                sections = existing_document.get("sections", [])
                total_marks = sum(
                    int(section.get("numQuestions", 0)) * int(section.get("markAllotment", 0))
                    for section in sections
                )
                collection.update_one(
                    {"contestId": contest_id},
                    {"$set": {"testConfiguration.totalMarks": str(total_marks)}}
                )

            collection.update_one(
                {"contestId": contest_id},
                {
                    '$addToSet': {
                        'visible_to': {'$each': selected_students},
                    }
                }
            )

            return JsonResponse({'message': 'Questions and students appended successfully!'}, status=200)

        except Exception as e:
            return JsonResponse({'error': f'Error appending questions and students: {str(e)}'}, status=500)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)

@csrf_exempt
def get_mcqquestions(request, contestId):
    """
    Retrieve MCQ questions for a specific contest.

    Args:
        request: The HTTP request object.
        contestId: The ID of the contest.

    Returns:
        JsonResponse: A JSON response containing the MCQ questions if found, or an error message if not.
    """
    if request.method == "GET":
        try:
            assessment = collection.find_one({"contestId": contestId})
            if not assessment:
                return JsonResponse(
                    {"error": f"No assessment found for contestId: {contestId}"}, status=404
                )

            test_configuration = assessment.get("testConfiguration", {})
            questions_value = test_configuration.get("questions", 0)
            try:
                num_questions_to_fetch = int(questions_value)
            except (ValueError, TypeError):
                num_questions_to_fetch = 0

            questions = assessment.get("questions", [])

            if not questions:
                return JsonResponse(
                    {"error": "No questions found for the given contestId."}, status=404
                )

            if num_questions_to_fetch > len(questions):
                return JsonResponse(
                    {"error": "Number of questions requested exceeds available questions."},
                    status=400,
                )

            if test_configuration.get("shuffleQuestions", False):
                random.shuffle(questions)

            selected_questions = questions[:num_questions_to_fetch]

            for question in selected_questions:
                if question.get("randomizeOrder", False):
                    random.shuffle(question["options"])

            response_data = {
                "assessmentName": assessment["assessmentOverview"].get("name"),
                "duration": test_configuration.get("duration"),
                "questions": [
                    {
                        "text": question.get("question"),
                        "options": question.get("options"),
                        "mark": question.get("mark"),
                        "negativeMark": question.get("negativeMark"),
                    }
                    for question in selected_questions
                ],
            }

            return JsonResponse(response_data, safe=False, status=200)

        except Exception as e:
            return JsonResponse(
                {"error": f"Failed to fetch MCQ questions: {str(e)}"}, status=500
            )
    else:
        return JsonResponse({"error": "Invalid request method"}, status=405)

@api_view(["GET"])
@permission_classes([AllowAny])
def get_section_questions_for_contest(request, contest_id):
    """
    Retrieve section questions for a specific contest.

    Args:
        request: The HTTP request object.
        contest_id: The ID of the contest.

    Returns:
        JsonResponse: A JSON response containing the section questions if found, or an error message if not.
    """
    try:
        mcq_tests = list(assessment_questions_collection.find(
            {"contestId": contest_id},
            {"questions": 0, "correctAnswer": 0}
        ))

        if not mcq_tests:
            return JsonResponse([], safe=False, status=200)

        formatted_data = []
        for test in mcq_tests:
            for section in test.get('sections', []):
                duration = section.get('sectionDuration', {})
                if isinstance(duration, dict):
                    hours = duration.get('hours', 0)
                    minutes = duration.get('minutes', 0)
                else:
                    hours = duration // 60
                    minutes = duration % 60

                section_data = {
                    "sectionName": section.get('sectionName', ""),
                    "duration": {
                        "hours": str(hours),
                        "minutes": str(minutes)
                    },
                    "questions": []
                }

                for question in section.get('questions', []):
                    section_data["questions"].append({
                        "text": question.get("question", ""),
                        "options": question.get("options", []),
                        "mark": None,
                        "negativeMark": None
                    })

                formatted_data.append(section_data)
        return JsonResponse(formatted_data, safe=False, status=200)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
def submit_mcq_assessment(request):
    """
    Submit an MCQ assessment for a student.

    Args:
        request: The HTTP request object containing the student's answers and other details in the request body.

    Returns:
        JsonResponse: A JSON response indicating success or an error message if the data is invalid or missing.
    """
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            contest_id = data.get("contestId")
            answers = data.get("answers", {})
            fullscreen_warning = data.get("FullscreenWarning", 0)
            noise_warning = data.get("NoiseWarning", 0)
            tabswitch_warning = data.get("TabSwitchWarning", 0)
            face_warning = data.get("FaceWarning", 0)

            result_visibility = data.get("resultVisibility")
            ispublish = True if result_visibility == "Immediate release" else False

            pass_percentage = data.get("passPercentage", 50)
            student_id = data.get("studentId")

            # Get start and finish times from the request
            start_time = data.get("startTime")
            finish_time = data.get("finishTime")
            duration_in_seconds = data.get("durationInSeconds", 0)

            current_time = datetime.datetime.utcnow().isoformat()
            
            # Validate timestamps
            if not start_time or not isinstance(start_time, str) or not start_time.strip():
                start_time = current_time
                print(f"Invalid start_time, using current time: {start_time}")
            
            if not finish_time or not isinstance(finish_time, str) or not finish_time.strip():
                finish_time = current_time
                print(f"Invalid finish_time, using current time: {finish_time}")
            
            try:
                # Validate timestamps by parsing them
                datetime.datetime.fromisoformat(start_time.replace('Z', '+00:00'))
                datetime.datetime.fromisoformat(finish_time.replace('Z', '+00:00'))
            except (ValueError, TypeError) as e:
                print(f"Error parsing timestamps: {e}")
                start_time = current_time
                finish_time = current_time

            if not contest_id:
                return JsonResponse({"error": "Contest ID is required"}, status=400)
            if not student_id:
                return JsonResponse({"error": "Student ID is required"}, status=400)


            existing_report = mcq_report_collection.find_one({
                "contest_id": contest_id,
                "students": {
                    "$elemMatch": {
                        "student_id": student_id,
                        "status": "Completed"
                    }
                }
            })

            if existing_report:
                return JsonResponse({
                    "error": "You have already submitted this assessment",
                    "status": "Already_Submitted"
                }, status=400)

            assessment = collection.find_one({"contestId": contest_id})
            if not assessment:
                return JsonResponse(
                    {"error": f"No assessment found for contestId: {contest_id}"},
                    status=404,
                )

            correct_answers = 0
            total_questions = 0
            attended_questions = []
            section_summaries = {}

            sections = assessment.get("sections", [])

            if sections:
                for section in sections:
                    section_name = section.get("sectionName", "Unnamed Section")
                    section_questions = []
                    section_correct = 0
                    section_total = 0

                    student_section_answers = answers.get(section_name, {})
                    answered_questions = set(student_section_answers.keys())

                    for question in section.get("questions", []):
                        question_text = question.get("question")

                        if question_text not in answered_questions and question_text not in student_section_answers:
                            continue

                        correct_answer = question.get("answer")
                        options = question.get("options", [])
                        student_answer = student_section_answers.get(question_text)

                        question_data = {
                            "title": question_text,
                            "section": section_name,
                            "student_answer": student_answer if student_answer is not None else "notattended",
                            "correct_answer": correct_answer,
                            "options": options
                        }

                        section_questions.append(question_data)
                        attended_questions.append(question_data)

                        section_total += 1
                        if student_answer == correct_answer:
                            correct_answers += 1
                            section_correct += 1
                        total_questions += 1

                    if section_questions:
                        section_summaries[section_name] = {
                            "questions": section_questions,
                            "correct": section_correct,
                            "total": section_total,
                            "percentage": (section_correct / section_total * 100) if section_total > 0 else 0
                        }
            else:
                questions = assessment.get("questions", [])
                non_section_questions = []

                answered_question_texts = set(answers.keys())

                for question in questions:
                    question_text = question.get("question")

                    if question_text not in answered_question_texts:
                        continue

                    correct_answer = question.get("correctAnswer")
                    options = question.get("options", [])
                    student_answer = answers.get(question_text)

                    question_data = {
                        "title": question_text,
                        "student_answer": student_answer if student_answer is not None else "notattended",
                        "correct_answer": correct_answer,
                        "options": options
                    }

                    non_section_questions.append(question_data)
                    attended_questions.append(question_data)

                    if student_answer == correct_answer:
                        correct_answers += 1
                    total_questions += 1

                if non_section_questions:
                    section_summaries["Main"] = {
                        "questions": non_section_questions,
                        "correct": correct_answers,
                        "total": total_questions,
                        "percentage": (correct_answers / total_questions * 100) if total_questions > 0 else 0
                    }

            percentage = (correct_answers / total_questions) * 100 if total_questions > 0 else 0
            grade = "Pass" if percentage >= pass_percentage else "Fail"

            student_data = {
                "student_id": student_id,
                "status": "Completed",
                "grade": grade,
                "percentage": percentage,
                "attended_question": attended_questions,
                "section_summaries": section_summaries,
                "FullscreenWarning": fullscreen_warning,
                "NoiseWarning": noise_warning,
                "FaceWarning": face_warning,
                "TabSwitchWarning": tabswitch_warning,
                "startTime": start_time,
                "finishTime": finish_time,
                "duration_in_seconds": duration_in_seconds,
                "submission_timestamp": current_time
            }
            report = mcq_report_collection.find_one({"contest_id": contest_id})
            if not report:
                mcq_report_collection.insert_one({
                    "contest_id": contest_id,
                    "passPercentage": pass_percentage,
                    "students": [student_data],
                    "ispublish": ispublish,
                    "created_at": current_time
                })
            else:
                students = report.get("students", [])
                student_found = False
                for i, student in enumerate(students):
                    if student.get("student_id") == student_id:
                        students[i] = student_data
                        student_found = True
                        break

                if not student_found:
                    students.append(student_data)

                mcq_report_collection.update_one(
                    {"contest_id": contest_id},
                    {
                        "$set": {
                            "students": students,
                            "passPercentage": pass_percentage,
                            "percentage": percentage,
                            "ispublish": ispublish,
                            "updated_at": current_time
                        }
                    }
                )

                return JsonResponse({
                        "contestId": contest_id,
                        "grade": grade,
                        "percentage": percentage,
                        "passPercentage": pass_percentage,
                        "sectionsCompleted": len(section_summaries),
                        "startTime": start_time,
                        "finishTime": finish_time,
                        "durationInSeconds": duration_in_seconds
                    }, status=200)

        except Exception as e:
            return JsonResponse({"error": f"An error occurred: {str(e)}"}, status=500)

    return JsonResponse({"error": "Invalid request method"}, status=405)
@csrf_exempt
def get_correct_answer(request, contestId, regno):
    """
    Retrieve the correct answers for a student's assessment.

    Args:
        request: The HTTP request object.
        contestId: The ID of the contest.
        regno: The registration number of the student.

    Returns:
        JsonResponse: A JSON response containing the correct answers if found, or an error message if not.
    """
    if request.method == "GET":
        try:
            report = mcq_report_collection.find_one({"contest_id": contestId})
            if not report:
                return JsonResponse({"error": f"No report found for contest_id: {contestId}"}, status=404)

            student_report = next(
                (student for student in report.get("students", []) if student["student_id"] == regno), None
            )
            if not student_report:
                return JsonResponse({"error": f"No report found for student with regno: {regno}"}, status=404)

            contest_details = collection.find_one({"contestId": contestId})
            if not contest_details:
                return JsonResponse({"error": f"No contest details found for contest_id: {contestId}"}, status=404)

            contest_name = contest_details.get("assessmentOverview", {}).get("name", "Unknown Contest")

            correct_answers = sum(
                1 for q in student_report.get("attended_question", []) if q.get("student_answer") == q.get("correct_answer")
            )
            formatted_report = {
                "correct_answers": correct_answers,
            }

            return JsonResponse(formatted_report, status=200, safe=False)

        except Exception as e:
            return JsonResponse({"error": f"Failed to fetch student report: {str(e)}"}, status=500)
    else:
        return JsonResponse({"error": "Invalid request method"}, status=405)

@csrf_exempt
def get_student_report(request, contestId, regno):
    if request.method == "GET":
        try:
            report = mcq_report_collection.find_one({"contest_id": contestId})
            if not report:
                return JsonResponse({"error": f"No report found for contest_id: {contestId}"}, status=404)

            student_report = next(
                (student for student in report.get("students", []) if student["student_id"] == regno), None
            )
            if not student_report:
                return JsonResponse({"error": f"No report found for student with regno: {regno}"}, status=404)

            contest_details = collection.find_one({"contestId": contestId})
            if not contest_details:
                return JsonResponse({"error": f"No contest details found for contest_id: {contestId}"}, status=404)

            contest_name = contest_details.get("assessmentOverview", {}).get("name", "Unknown Contest")
            contest_description = contest_details.get("assessmentOverview", {}).get("description", "Unknown Contest")
            is_section = contest_details.get("assessmentOverview", {}).get("sectionDetails", "No")
            timing_type = contest_details.get("assessmentOverview", {}).get("timingType", "Overall")
            registration_start = contest_details.get("assessmentOverview", {}).get("registrationStart")
            registration_end = contest_details.get("assessmentOverview", {}).get("registrationEnd")

            if is_section == "Yes":
                no_of_sections = contest_details.get("no_of_section", 0)
                sections = contest_details.get("sections", [])
                total_questions = sum(int(section.get("numQuestions", 0)) for section in sections)
                total_marks = sum(
                    int(section.get("numQuestions", 0)) * int(section.get("markAllotment", 1))
                    for section in sections
                )
            else:
                sections = []
                no_of_sections = 0
                total_questions = int(contest_details.get("testConfiguration", {}).get("questions", 0))
                total_marks = int(contest_details.get("testConfiguration", {}).get("totalMarks", 0))

            if is_section == "Yes" and timing_type == "Overall":
                duration = contest_details.get("testConfiguration", {}).get("duration", {"hours": 0, "minutes": 0})
            elif is_section == "Yes" and timing_type == "Section":
                duration = {"hours": 0, "minutes": 0}
            else:
                duration = contest_details.get("testConfiguration", {}).get("duration", {"hours": 0, "minutes": 0})

            correct_answers = sum(
                1 for q in student_report.get("attended_question", []) if q.get("student_answer") == q.get("correct_answer")
            )

            # Parse timeTaken (assuming it's in seconds or an HH:MM:SS string)
            time_taken_raw = student_report.get("timeTaken")
            if isinstance(time_taken_raw, str) and ":" in time_taken_raw:
                try:
                    hours, minutes, seconds = map(int, time_taken_raw.split(":"))
                    time_taken = {"hours": hours, "minutes": minutes, "seconds": seconds}
                except (ValueError, TypeError):
                    time_taken = None  # Fallback if parsing fails
            elif isinstance(time_taken_raw, (int, float)):  # Assume seconds
                total_seconds = int(time_taken_raw)
                hours = total_seconds // 3600
                minutes = (total_seconds % 3600) // 60
                seconds = total_seconds % 60
                time_taken = {"hours": hours, "minutes": minutes, "seconds": seconds}
            else:
                time_taken = None  # Fallback to start_time/finish_time

            # Fallback to start_time and finish_time if timeTaken is invalid
            if not time_taken and student_report.get("startTime") and student_report.get("finishTime"):
                from datetime import datetime
                start = datetime.fromisoformat(student_report.get("startTime").replace("Z", "+00:00"))
                finish = datetime.fromisoformat(student_report.get("finishTime").replace("Z", "+00:00"))
                diff_seconds = int((finish - start).total_seconds())
                hours = diff_seconds // 3600
                minutes = (diff_seconds % 3600) // 60
                seconds = diff_seconds % 60
                time_taken = {"hours": hours, "minutes": minutes, "seconds": seconds}

            assessment_data = assessment_questions_collection.find_one({"contestId": contestId})
            generate_certificate = assessment_data.get("testConfiguration", {}).get("generateCertificate", False)

            students_scores = sorted(report.get("students", []), key=lambda x: x.get("percentage", 0), reverse=True)[:5]

            top_5_students = []
            for student in students_scores:
                try:
                    student_details = students_collection.find_one(
                        {"_id": ObjectId(student["student_id"])},
                        {"_id": 0, "name": 1, "regno": 1}
                    )
                except Exception as e:
                    student_details = None
                if student_details:
                    top_5_students.append({
                        "name": student_details.get("name", "Unknown"),
                        "regno": student_details.get("regno", "Unknown"),
                        "marks": student.get("percentage", 0)
                    })

            formatted_report = {
                "contest_id": contestId,
                "contest_name": contest_name,
                "description": contest_description,
                "student_id": regno,
                "status": student_report.get("status"),
                "grade": student_report.get("grade"),
                "start_time": student_report.get("startTime"),
                "finish_time": student_report.get("finishTime"),
                "red_flags": student_report.get("warnings", 0),
                "fullscreen": student_report.get("FullscreenWarning", 0),
                "facewarning": student_report.get("FaceWarning", 0),
                "tabswitchwarning": student_report.get("TabSwitchWarning", 0),
                "noisewarning": student_report.get("NoiseWarning", 0),
                "timeTaken": time_taken or {"hours": 0, "minutes": 0, "seconds": 0},
                "attended_questions": [
                    {
                        "id": index + 1,
                        "question": q.get("title"),
                        "options": q.get("options"),
                        "userAnswer": q.get("student_answer"),
                        "correctAnswer": q.get("correct_answer"),
                        "isCorrect": q.get("student_answer") == q.get("correct_answer"),
                    }
                    for index, q in enumerate(student_report.get("attended_question", []))
                    if q.get("student_answer") is not None
                ],
                "correct_answers": correct_answers,
                "total_questions": total_questions,
                "total_marks": total_marks,
                "duration": duration,
                "percentageScored": student_report.get("percentage", 0),
                "passPercentage": report.get("passPercentage", 0),
                "generateCertificate": generate_certificate,
                "top_5_students": top_5_students,
                "is_section": is_section,
                "timing_type": timing_type,
                "registrationStart": registration_start,
                "registrationEnd": registration_end,
                "sections": sections,
                "no_of_sections": no_of_sections,
            }

            return JsonResponse(formatted_report, status=200, safe=False)

        except Exception as e:
            return JsonResponse({"error": f"Failed to fetch student report: {str(e)}"}, status=500)
    else:
        return JsonResponse({"error": "Invalid request method"}, status=405)

@api_view(["POST"])
@permission_classes([AllowAny])
def publish_result(request, contestId):
    """
    Publish the results for a contest.

    Args:
        request: The HTTP request object.
        contestId: The ID of the contest.

    Returns:
        JsonResponse: A JSON response indicating success or an error message if the contest is not found.
    """
    try:
        if not contestId:
            return JsonResponse({"error": "Contest ID is required"}, status=400)

        result = mcq_report_collection.update_one(
            {"contest_id": contestId},
            {"$set": {"ispublish": True}}
        )

        if result.modified_count == 0:
            return JsonResponse({"error": "Contest not found or already published"}, status=404)

        return JsonResponse({"message": "Results published successfully"}, status=200)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
def generate_questions(request):
    """
    Generate questions based on the provided topic, subtopic, and level distribution.

    Args:
        request: The HTTP request object containing the topic, subtopic, and level distribution in the request body.

    Returns:
        JsonResponse: A JSON response containing the generated questions or an error message if the data is invalid.
    """
    
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            topic = data.get("topic")
            subtopic = data.get("subtopic")
            num_questions_input = data.get("num_questions")
            question_type = "Multiple Choice"
            level = data.get("level")
            level_distribution = data.get("level_distribution")
            regeneration_seed = data.get("regeneration_seed", "") # Get regeneration seed if provided

            # Rest of validation code remains the same...

            questions_data = []

            level_mapping = {
                "Remembering": "L1",
                "Understanding": "L2",
                "Applying": "L3",
                "Analyzing": "L4",
                "Evaluating": "L5",
                "Creating": "L6"
            }

            # Rest of validation code remains the same...

            for level_data in level_distribution:
                level = level_data.get('level')
                count = int(level_data.get('count', 0))

                if count <= 0:
                    continue

                if not level:
                    return JsonResponse({"error": "Level name is required for each distribution entry."}, status=400)

                short_level = level_mapping.get(level, "Unknown")

                # Modified prompt to include the regeneration seed for variation
# Update in the generate_questions function - around line 1336

# Modified prompt to include the regeneration seed for variation
                prompt = (
                    f"Generate {count} unique Multiple Choice questions on the topic '{topic}' with subtopic '{subtopic}' "
                    f"for the Bloom's Taxonomy level: {level}.\n\n"
                    f"Seed value: {regeneration_seed}\n\n"
                    f"VERY IMPORTANT: Generate completely different and unique questions. DO NOT reuse or rephrase questions or Words from previous attempts.\n\n"
                    f"IMPORTANT FORMATTING RULES:\n"
                    f"1. Each question MUST have EXACTLY 4 options (no more, no less)\n"
                    f"2. Each question must be formatted EXACTLY like this example:\n"
                    f"Question: What is the capital of France?\n"
                    f"Options: Paris;London;Berlin;Madrid\n"
                    f"Answer: Paris\n"
                    f"Negative Marking: 0\n"
                    f"Mark: 1\n"
                    f"Level: {level}\n"
                    f"Tags: Geography,Europe,Capitals\n\n"
                    f"3. Do not include A), B), C), D) or any numbering in the options\n"
                    f"4. Separate the options with semicolons only\n"
                    f"5. The correct answer MUST be exactly identical to one of the options\n"
                    f"6. Separate different questions with a blank line\n"
                    f"7. Do not include any explanation or additional text"
                )

                try:
                    response = model.generate_content(prompt)
                    question_text = response._result.candidates[0].content.parts[0].text

                    if not question_text.strip():
                        return JsonResponse({"error": "No questions generated. Please try again."}, status=500)

                    questions_list = re.split(r'\n\s*\n', question_text.strip())

                    for question in questions_list:
                        try:
                            lines = question.strip().split('\n')

                            if len(lines) < 6:
                                continue

                            question_line = lines[0]
                            question_text = question_line.replace("Question:", "", 1).strip() if question_line.startswith("Question:") else question_line

                            options_line = lines[1]
                            options_text = options_line.replace("Options:", "", 1).strip() if options_line.startswith("Options:") else options_line
                            options = [opt.strip() for opt in options_text.split(";")]

                            if len(options) > 4:
                                options = options[:4]
                            elif len(options) < 4:
                                while len(options) < 4:
                                    options.append(f"Option {len(options) + 1}")

                            answer_line = lines[2]
                            answer = answer_line.replace("Answer:", "", 1).strip() if answer_line.startswith("Answer:") else answer_line

                            if answer not in options:
                                answer_match = False
                                for i, opt in enumerate(options):
                                    if answer.lower() in opt.lower() or opt.lower() in answer.lower():
                                        answer = opt
                                        answer_match = True
                                        break

                                if not answer_match:
                                    answer = options[0]

                            neg_mark_line = lines[3]
                            neg_mark = neg_mark_line.replace("Negative Marking:", "", 1).strip() if neg_mark_line.startswith("Negative Marking:") else neg_mark_line

                            mark_line = lines[4]
                            mark = mark_line.replace("Mark:", "", 1).strip() if mark_line.startswith("Mark:") else mark_line

                            tags = []
                            if len(lines) > 6:
                                tags_line = lines[6]
                                tags_text = tags_line.replace("Tags:", "", 1).strip() if tags_line.startswith("Tags:") else tags_line
                                tags = [tag.strip() for tag in tags_text.split(",")]

                            questions_data.append({
                                "topic": topic,
                                "subtopic": subtopic,
                                "level": short_level,
                                "question_type": question_type,
                                "question": question_text,
                                "options": options,
                                "correctAnswer": answer,
                                "negativeMarking": neg_mark,
                                "mark": mark,
                                "tags": tags
                            })

                        except Exception as e:
                            continue

                except Exception as e:
                    return JsonResponse({"error": f"Error generating questions for level {level}: {str(e)}"}, status=500)

            if not questions_data:
                return JsonResponse({"error": "No valid questions were generated. Please try a different topic or level."}, status=500)

            return JsonResponse({
                "success": "Questions generated successfully",
                "questions": questions_data
            })

        except Exception as e:
            return JsonResponse({"error": f"Error generating questions: {str(e)}"}, status=500)

    return JsonResponse({"error": "Invalid request method."}, status=405)

@csrf_exempt
def save_assessment_questions(request):
    """
    Save generated questions to an assessment with robust contestId handling.
    """
    if request.method != "POST":
        return JsonResponse({"error": "Method not allowed"}, status=405)
    
    print("--- Starting save_assessment_questions function ---")
    
    try:
        # Parse request body
        data = json.loads(request.body)
        print(f"Request body keys: {list(data.keys())}")
        
        # Get contestId directly (the most important part)
        contest_id = data.get('contestId')
        if not contest_id:
            print("No contestId found in request body")
            return JsonResponse({"error": "Contest ID is required"}, status=400)
        
        print(f"Using contestId from request body: {contest_id}")
        
        # Process core data fields
        section_name = data.get('sectionName')
        num_questions = data.get('numQuestions')
        section_duration = data.get('sectionDuration')
        mark_allotment = data.get('markAllotment')
        pass_percentage = data.get('passPercentage')
        time_restriction = data.get('timeRestriction')
        questions = data.get('questions', [])
        
        if not questions:
            return JsonResponse({"error": "No questions provided"}, status=400)
        
        # Find the assessment by contestId
        assessment = None
        try:
            # First try with exact match
            assessment = collection.find_one({"contestId": contest_id})
            print(f"Looking up assessment by contestId: {contest_id}, Found: {assessment is not None}")
            
            # Try case-insensitive match if exact match fails
            if not assessment:
                assessments_list = list(collection.find())
                for a in assessments_list:
                    if a.get("contestId", "").lower() == contest_id.lower():
                        assessment = a
                        print(f"Found assessment with case-insensitive contestId match")
                        break
        except Exception as e:
            print(f"Database error: {str(e)}")
            return JsonResponse({"error": f"Database error: {str(e)}"}, status=500)

        # If no assessment found, return user-friendly error
        if not assessment:
            print(f"No assessment found with contestId: {contest_id}")
            return JsonResponse({"error": "No assessment found. Please provide a valid contestId."}, status=404)
        
        # Format questions
        formatted_questions = [{
            "question_type": "Multiple Choice",
            "question": q["question"],
            "options": q["options"],
            "answer": q["correctAnswer"] if "correctAnswer" in q else q["answer"]
        } for q in questions]
        
        # Update the database
        try:
            result = collection.update_one(
                {"_id": assessment["_id"]},
                {
                    "$push": {
                        "sections": {
                            "sectionName": section_name,
                            "numQuestions": num_questions,
                            "sectionDuration": section_duration,
                            "markAllotment": mark_allotment,
                            "passPercentage": pass_percentage,
                            "timeRestriction": time_restriction,
                            "questions": formatted_questions
                        }
                    },
                    "$inc": {"no_of_section": 1}
                }
            )
            
            if result.modified_count == 0:
                print("Failed to update assessment - modified_count=0")
                return JsonResponse({"error": "Failed to update assessment"}, status=400)
                
            print("Successfully updated assessment with questions")
        except Exception as e:
            print(f"Database update error: {str(e)}")
            return JsonResponse({"error": f"Database update error: {str(e)}"}, status=500)

        return JsonResponse({
            "success": True,
            "message": "Questions saved successfully",
            "sectionName": section_name
        })
        
    except json.JSONDecodeError:
        return JsonResponse({"error": "Invalid JSON in request body"}, status=400)
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return JsonResponse({"error": f"An unexpected error occurred: {str(e)}"}, status=500)
    
    
@api_view(['DELETE'])
@permission_classes([AllowAny])
def delete_contest_by_id(request, contest_id):
    """
    Delete a contest by its ID.

    Args:
        request: The HTTP request object.
        contest_id: The ID of the contest to be deleted.

    Returns:
        Response: A response indicating success or an error message if the contest is not found.
    """
    try:
        result = collection.delete_one({'contestId': contest_id})
        if result.deleted_count > 0:
            return Response({'message': 'Contest deleted successfully'}, status=status.HTTP_200_OK)
        else:
            return Response({'error': 'Contest not found'}, status=status.HTTP_404_NOT_FOUND)
    except Exception as e:
        return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@csrf_exempt
@permission_classes(["DELETE"])
def reassign(request, contest_id, student_id):
    """
    Reassign a student to a contest.

    Args:
        request: The HTTP request object.
        contest_id: The ID of the contest.
        student_id: The ID of the student to be reassigned.

    Returns:
        JsonResponse: A JSON response indicating success or an error message if the student or contest is not found.
    """
    try:
        contest = mcq_report_collection.find_one({"contest_id": contest_id})
        if not contest:
            return JsonResponse({"error": "Contest not found"}, status=404)

        updated_students = [s for s in contest.get("students", []) if s["student_id"] != student_id]

        result = mcq_report_collection.update_one(
            {"contest_id": contest_id},
            {"$set": {"students": updated_students}}
        )

        if result.modified_count > 0:
            return JsonResponse({"success": True, "message": "Student reassigned successfully"})
        else:
            return JsonResponse({"error": "Student not found or no changes made"}, status=400)

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

@csrf_exempt
def close_session(request, contest_id):
    """
    Close a contest session.

    Args:
        request: The HTTP request object.
        contest_id: The ID of the contest to be closed.

    Returns:
        JsonResponse: A JSON response indicating success or an error message if the contest is not found.
    """
    if request.method == "POST":
        try:
            result = collection.update_one(
                {"contestId": contest_id},
                {"$set": {"Overall_Status": "closed"}}
            )

            if result.modified_count > 0:
                return JsonResponse({"message": "Session closed successfully."}, status=200)
            else:
                return JsonResponse({"message": "Contest ID not found or already closed."}, status=404)

        except Exception as e:
            return JsonResponse({"message": f"Internal server error: {str(e)}"}, status=500)

    return JsonResponse({"message": "Invalid request method."}, status=405)

@csrf_exempt
def store_certificate(request):
    """
    Store certificate data for a student.

    Args:
        request: The HTTP request object containing the certificate data in the request body.

    Returns:
        JsonResponse: A JSON response indicating success or an error message if the data is invalid.
    """

    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            unique_id = data.get('uniqueId')
            student_name = data.get('studentName')
            contest_name = data.get('contestName')
            student_id = data.get('studentId')

            certificate_data = {
                'uniqueId': unique_id,
                'studentName': student_name,
                'contestName': contest_name,
                'studentId': student_id
            }

            certificate_collection.insert_one(certificate_data)
            return JsonResponse({'status': 'success', 'message': 'Certificate data stored successfully.'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})
    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'})

class CustomJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return super().default(o)

@csrf_exempt
def verify_certificate(request, unique_id=None):
    """
    Verify a certificate using its unique ID.

    Args:
        request: The HTTP request object.
        unique_id: The unique ID of the certificate to be verified.

    Returns:
        JsonResponse: A JSON response containing the certificate data if found, or an error message if not.
    """
    if request.method == 'GET' and unique_id:
        try:
            certificate = certificate_collection.find_one({'uniqueId': unique_id})
            if certificate:
                return JsonResponse({'status': 'success', 'certificate': certificate}, encoder=CustomJSONEncoder)
            else:
                return JsonResponse({'status': 'error', 'message': 'Certificate not found.'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})

    elif request.method == 'POST':
        
        try:
            data = json.loads(request.body)
            unique_id = data.get('unique_id')
            certificate = certificate_collection.find_one({'uniqueId': unique_id})
            if certificate:
                return JsonResponse({'status': 'success', 'certificate': certificate}, encoder=CustomJSONEncoder)
            else:
                return JsonResponse({'status': 'error', 'message': 'Certificate not found.'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})

    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'})

@api_view(['PUT'])
@permission_classes([AllowAny])
def update_assessment(request, contest_id):
    """
    Update an assessment's configuration.

    Args:
        request: The HTTP request object containing the updated assessment data in the request body.
        contest_id: The ID of the contest to be updated.

    Returns:
        JsonResponse: A JSON response indicating success or an error message if the data is invalid or missing.
    """
    try:
        jwt_token = request.COOKIES.get("jwt")
        if not jwt_token:
            raise AuthenticationFailed("Authentication credentials were not provided.")

        try:
            decoded_token = jwt.decode(jwt_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Access token has expired. Please log in again.")
        except jwt.InvalidTokenError:
            raise AuthenticationFailed("Invalid token. Please log in again.")

        staff_id = decoded_token.get("staff_user")
        if not staff_id:
            raise AuthenticationFailed("Invalid token payload.")

        try:
            staff = staff_collection.find_one({"_id": ObjectId(staff_id)})
        except errors.InvalidId:
            raise AuthenticationFailed("Invalid staff_id format in token")

        if not staff:
            return JsonResponse({"error": "Staff not found"}, status=404)

        assessment = assessment_questions_collection.find_one({"contestId": contest_id})
        if not assessment:
            return JsonResponse({"error": "Assessment not found"}, status=404)

        data = request.data

        assessment_overview = data.get("assessmentOverview", {})
        test_configuration = data.get("testConfiguration", {})

        try:
            registration_start = str_to_datetime(assessment_overview.get("registrationStart"))
            registration_end = str_to_datetime(assessment_overview.get("registrationEnd"))
        except ValueError as e:
            return JsonResponse({"error": "Invalid date format. Use ISO format for dates."}, status=400)

        updated_fields = {
            "assessmentOverview": {
                "name": assessment_overview.get("name", assessment["assessmentOverview"]["name"]),
                "description": assessment_overview.get("description", assessment["assessmentOverview"]["description"]),
                "registrationStart": registration_start if registration_start else assessment["assessmentOverview"]["registrationStart"],
                "registrationEnd": registration_end if registration_end else assessment["assessmentOverview"]["registrationEnd"],
                "guidelines": assessment_overview.get("guidelines", assessment["assessmentOverview"]["guidelines"]),
                "sectionDetails": assessment_overview.get("sectionDetails", assessment["assessmentOverview"].get("sectionDetails", "No")),
                "timingType": assessment_overview.get("timingType", assessment["assessmentOverview"]["timingType"]),
            },
            "testConfiguration": {
                "questions": test_configuration.get("questions", assessment["testConfiguration"]["questions"]),
                "totalMarks": test_configuration.get("totalMarks", assessment["testConfiguration"]["totalMarks"]),
                "duration": test_configuration.get("duration", assessment["testConfiguration"]["duration"]),
                "fullScreenMode": test_configuration.get("fullScreenMode", assessment["testConfiguration"]["fullScreenMode"]),
                "faceDetection": test_configuration.get("faceDetection", assessment["testConfiguration"]["faceDetection"]),
                "deviceRestriction": test_configuration.get("deviceRestriction", assessment["testConfiguration"]["deviceRestriction"]),
                "noiseDetection": test_configuration.get("noiseDetection", assessment["testConfiguration"]["noiseDetection"]),
                "passPercentage": test_configuration.get("passPercentage", assessment["testConfiguration"]["passPercentage"]),
                "resultVisibility": test_configuration.get("resultVisibility", assessment["testConfiguration"]["resultVisibility"]),
                "fullScreenModeCount": test_configuration.get("fullScreenModeCount", assessment["testConfiguration"].get("fullScreenModeCount", 0)),
                "faceDetectionCount": test_configuration.get("faceDetectionCount", assessment["testConfiguration"].get("faceDetectionCount", 0)),
                "noiseDetectionCount": test_configuration.get("noiseDetectionCount", assessment["testConfiguration"].get("noiseDetectionCount", 0)),
                "shuffleQuestions": test_configuration.get("shuffleQuestions", assessment["testConfiguration"].get("shuffleQuestions", False)),
                "shuffleOptions": test_configuration.get("shuffleOptions", assessment["testConfiguration"].get("shuffleOptions", False)),
            },
            "updatedAt": datetime.datetime.utcnow(),
        }

        result = assessment_questions_collection.update_one(
            {"contestId": contest_id},
            {"$set": updated_fields}
        )

        if result.modified_count == 0:
            return JsonResponse({"message": "No changes were applied"}, status=200)

        return JsonResponse({"message": "Assessment updated successfully!"}, status=200)

    except AuthenticationFailed as auth_error:
        return JsonResponse({"error": str(auth_error)}, status=401)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

def str_to_datetime(date_str):
    if not date_str or date_str == 'T':
        raise ValueError(f"Invalid datetime format: {date_str}")

    try:
        return datetime.datetime.strptime(date_str, '%Y-%m-%dT%H:%M:%S')
    except ValueError:
        try:
            return datetime.datetime.strptime(date_str, '%Y-%m-%dT%H:%M')
        except ValueError:
            raise ValueError(f"Invalid datetime format: {date_str}")

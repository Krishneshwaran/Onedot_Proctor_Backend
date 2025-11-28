from django.shortcuts import render
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from django.contrib.auth.hashers import check_password, make_password
from rest_framework.exceptions import AuthenticationFailed
from bson import ObjectId
from datetime import datetime
import logging
import json
from django.core.cache import cache
from rest_framework.views import csrf_exempt
from .utils import *
from django.core.cache import cache
from django.http import JsonResponse
from rest_framework import status
from datetime import datetime, timedelta
import jwt

logger = logging.getLogger(__name__)
from django.conf import settings
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests
import os
import re
from bson.errors import InvalidId
import bleach
import html
from jwt import PyJWTError

import pandas as pd
from io import BytesIO
import openpyxl

# Add MongoDB connection setup at the beginning of the file
from pymongo import MongoClient
import os

# MongoDB connection setup
try:
    # Initialize MongoDB connection
    client = MongoClient('mongodb+srv://krish:krish@assessment.ar5zh.mongodb.net/')
    db = client['test_portal_db']
    
    # Initialize collections
    student_collection = db['students']
    mcq_assessments_collection = db['MCQ_Assessment_Data']
    mcq_assessments_report_collection = db['MCQ_Assessment_report']
    coding_assessment_collection = db['coding_assessments']
   
    
    logger = logging.getLogger(__name__)
    logger.info("Successfully connected to MongoDB database")
except Exception as e:
    logger.error(f"Failed to connect to MongoDB: {str(e)}")
    # In production, you might want to raise an exception here or implement a retry mechanism

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
# Password validation regex - at least 8 chars, 1 uppercase, 1 lowercase, 1 digit, 1 special char
PASSWORD_REGEX = re.compile(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$')

def sanitize_input(input_string):
    """
    Sanitize input to prevent XSS and injection attacks.

    Args:
        input_string (str): The input string to sanitize.

    Returns:
        str: The sanitized input string.
    """
    if input_string is None:
        return ""
    if isinstance(input_string, str):
        # Bleach helps to sanitize HTML content
        return bleach.clean(input_string.strip(), strip=True)
    return input_string

def validate_jwt_token(request):
    """
    Validate JWT token from cookies and return decoded payload or raise authentication error.

    Args:
        request: The HTTP request object containing cookies.

    Returns:
        dict: The decoded JWT payload.

    Raises:
        AuthenticationFailed: If the token is invalid or expired.
    """
    jwt_token = request.COOKIES.get("jwt")
    if not jwt_token:
        raise AuthenticationFailed("Authentication credentials were not provided.")

    try:
        # Create a stateless JWT verification with explicit algorithms and verify requirements
        decoded_token = jwt.decode(
            jwt_token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            options={
                'verify_signature': True,
                'verify_exp': True,
                'verify_iat': True,
                'require': ['student_id', 'regno', 'exp', 'iat']
            }
        )

        # Verify we have the required fields
        if 'student_id' not in decoded_token or 'regno' not in decoded_token:
            raise AuthenticationFailed("Invalid token structure")

        # Additional verifications can be added here
        return decoded_token

    except jwt.ExpiredSignatureError:
        raise AuthenticationFailed("Access token has expired. Please log in again.")
    except jwt.InvalidTokenError as e:
        raise AuthenticationFailed(f"Invalid token: {str(e)}. Please log in again.")
    except PyJWTError as e:
        raise AuthenticationFailed(f"JWT error: {str(e)}. Please log in again.")
    except Exception as e:
        raise AuthenticationFailed(f"Authentication error: {str(e)}.")

# Secret and algorithm for signing the tokens
JWT_SECRET = 'test'
JWT_ALGORITHM = "HS256"

def generate_tokens_for_student(student_id, regno):
    """
    Generate a secure access token (JWT) for a user with a MongoDB ObjectId and regno.

    Args:
        student_id (str): The student's MongoDB ObjectId.
        regno (str): The student's registration number.

    Returns:
        dict: A dictionary containing the JWT token.
    """
    access_payload = {
        'student_id': str(student_id),
        'regno': regno,  # Add regno to the token payload
        'exp': datetime.utcnow() + timedelta(minutes=600),  # Access token expiration
        'iat': datetime.utcnow(),
    }

    # Encode the token
    token = jwt.encode(access_payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    print(token)
    return {'jwt': token}

@api_view(["POST"])
@permission_classes([AllowAny])
def student_login(request):
    """
    Login view for students with account lockout after 5 failed attempts.

    Args:
        request: The HTTP request object containing login data.

    Returns:
        Response: JSON response with login status and details.

    Raises:
        AuthenticationFailed: If login fails due to invalid credentials or account lockout.
    """
    try:
        data = request.data
        email = sanitize_input(data.get("email", ""))
        password = data.get("password", "")

        # Validate input
        if not email or not password:
            return Response({"error": "Email and password are required"}, status=400)

        # Validate email format
        if not EMAIL_REGEX.match(email):
            return Response({"error": "Invalid email format"}, status=400)

        # First check if the email exists
        student_user = student_collection.find_one({"email": email})
        if not student_user:
            # If email doesn't exist, just return invalid credentials
            # without locking (prevents email enumeration)
            return Response({"error": "Invalid email or password"}, status=401)

        # Now we know the email is valid, check if the account is locked
        # Get current lock status from the database
        lockout_info = student_user.get("lockout_info", {})
        lockout_until = lockout_info.get("lockout_until")

        if lockout_until:
            # Parse the lockout time properly, handling both string and datetime objects
            try:
                lockout_time = datetime.fromisoformat(lockout_until) if isinstance(lockout_until, str) else lockout_until
                now = datetime.now()
                if now < lockout_time:
                    # Account is locked
                    remaining_seconds = int((lockout_time - now).total_seconds())
                    return Response({
                        "error": "Account temporarily locked due to too many failed login attempts",
                        "lockout_time": remaining_seconds
                    }, status=429)
            except (ValueError, TypeError) as e:
                logger.error(f"Error processing lockout time: {e}")
                # If there's an error with the lockout format, treat as not locked
                pass

        # Check password hash
        stored_password = student_user.get("password")

        # If password is incorrect - handle failed attempt
        if not check_password(password, stored_password):
            logger.warning(f"Login failed: Incorrect password for {email}")

            # Increment attempt counter
            attempts = lockout_info.get("attempts", 0) + 1
            lockout_info = {"attempts": attempts, "lockout_until": None}

            # If 5 attempts reached, lock the account
            if attempts >= 5:
                lockout_until = datetime.now() + timedelta(minutes=2)
                lockout_info["lockout_until"] = lockout_until.isoformat()

                # Update the document with lockout information
                student_collection.update_one(
                    {"email": email},
                    {"$set": {"lockout_info": lockout_info}}
                )

                return Response({
                    "error": "Account temporarily locked due to too many failed login attempts",
                    "lockout_time": 120  # 2 minutes in seconds
                }, status=429)

            # Update the failed attempts count
            student_collection.update_one(
                {"email": email},
                {"$set": {"lockout_info": lockout_info}}
            )

            # Calculate remaining attempts
            remaining_attempts = 5 - attempts
            error_message = f"Invalid email or password. {remaining_attempts} attempts remaining before account lock."

            return Response({"error": error_message}, status=401)

        # Password is correct, reset lockout information if any
        if lockout_info.get("attempts", 0) > 0:
            student_collection.update_one(
                {"email": email},
                {"$set": {"lockout_info": {"attempts": 0, "lockout_until": None}}}
            )

        # Generate tokens and complete login
        tokens = generate_tokens_for_student(
            str(student_user["_id"]),
            student_user.get("regno")
        )

        # Include profile image if available
        profile_image = student_user.get("profileImage", "")

        # Create response and set secure cookie
        response = Response({
            "message": "Login successful",
            "tokens": tokens,
            "studentId": str(student_user["_id"]),
            "name": sanitize_input(student_user["name"]),
            "email": student_user["email"],
            "regno": sanitize_input(student_user["regno"]),
            "dept": sanitize_input(student_user["dept"]),
            "collegename": sanitize_input(student_user["collegename"]),
            "profileImage": profile_image  # Include profile image in response
        })

        # Set cookie with improved security
        response.set_cookie(
            key='jwt',
            value=tokens['jwt'],
            httponly=True,
            samesite='None',
            secure=True,
            max_age=1 * 24 * 60 * 60  # 24 hours
        )
        return response

    except KeyError as e:
        logger.error(f"Missing key: {e}")
        return Response({"error": "Invalid data provided"}, status=400)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return Response({"error": "An unexpected error occurred"}, status=500)

@api_view(["POST"])
@permission_classes([AllowAny])
def student_logout(request):
    """
    Clear all authentication cookies for student logout.

    Args:
        request: The HTTP request object.

    Returns:
        Response: JSON response indicating logout success.
    """
    try:
        # Create a response object with success message
        response = Response({"message": "Logout successful"}, status=200)

        # Delete the JWT cookie with enhanced cookie clearing
        for path in ['/', '/api', '/api/student']:
            response.delete_cookie(
                key='jwt',
                path=path,
                domain=None
            )
            # Also clear refreshToken and username
            response.delete_cookie(key='refreshToken', path=path, domain=None)
            response.delete_cookie(key='username', path=path, domain=None)

        # Clear additional cookies that might exist
        response.delete_cookie(key='profilePicture', path='/', domain=None)

        return response

    except Exception as e:
        logger.error(f"Error during student logout: {str(e)}")
        return Response(
            {"error": "Something went wrong. Please try again later."},
            status=500
        )

@api_view(["POST"])
@permission_classes([AllowAny])
def set_new_password(request):
    """
    API for students to set a new password after first login.

    Args:
        request: The HTTP request object containing new password data.

    Returns:
        Response: JSON response indicating password update status.

    Raises:
        Response: If the input data is invalid or the user is not found.
    """
    try:
        data = request.data
        email = sanitize_input(data.get("email", ""))
        new_password = data.get("new_password", "")

        # Validate input
        if not email or not new_password:
            return Response({"error": "Email and new password are required"}, status=400)

        # Validate email format
        if not EMAIL_REGEX.match(email):
            return Response({"error": "Invalid email format"}, status=400)

        # Validate password strength
        if len(new_password) < 8:
            return Response({"error": "Password must be at least 8 characters long"}, status=400)

        if not re.search("[A-Z]", new_password):
            return Response({"error": "Password must contain at least one uppercase letter"}, status=400)

        if not re.search("[a-z]", new_password):
            return Response({"error": "Password must contain at least one lowercase letter"}, status=400)

        if not re.search("[0-9]", new_password):
            return Response({"error": "Password must contain at least one number"}, status=400)

        if not re.search("[!@#$%^&*(),.?\":{}|<>]", new_password):
            return Response({"error": "Password must contain at least one special character"}, status=400)

        # Fetch student user from MongoDB
        student_user = student_collection.find_one({"email": email})
        if not student_user:
            return Response({"error": "User not found"}, status=404)

        # Ensure student is setting password for the first time
        if student_user.get("setpassword", False):
            return Response({"error": "Password is already set. Please use the login feature."}, status=400)

        # Update password and set `setpassword` to True
        student_collection.update_one(
            {"email": email},
            {
                "$set": {
                    "password": make_password(new_password),
                    "setpassword": True,
                    "updated_at": datetime.now()
                }
            }
        )

        return Response({"message": "Password updated successfully. You can now log in."}, status=200)

    except Exception as e:
        logger.error(f"Error updating password: {e}")
        return Response({"error": "Something went wrong. Please try again later."}, status=500)

@api_view(["POST"])
@permission_classes([AllowAny])
def student_signup(request):
    """
    Signup view for students (Created by Admin).

    Args:
        request: The HTTP request object containing student signup data.

    Returns:
        Response: JSON response indicating signup success or failure.

    Raises:
        Response: If the input data is invalid or the user already exists.
    """
    try:
        # Extract data from request
        data = request.data
        # Sanitize all inputs
        student_user = {
            "name": sanitize_input(data.get("name", "")),
            "email": sanitize_input(data.get("email", "")),
            "password": make_password("SNS@123"),  # Default password set
            "collegename": sanitize_input(data.get("collegename", "")),
            "dept": sanitize_input(data.get("dept", "")),
            "regno": sanitize_input(data.get("regno", "")),
            "year": sanitize_input(data.get("year", "")),
            "setpassword": False,  # New field (Student must set their own password)
            "created_at": datetime.now(),
            "updated_at": datetime.now(),
        }

        # Validate required fields
        required_fields = ["name", "email", "dept", "collegename", "regno", "year"]
        missing_fields = [field for field in required_fields if not student_user[field]]
        if missing_fields:
            return Response(
                {"error": f"Missing required fields: {', '.join(missing_fields)}"},
                status=400,
            )

        # Validate email format
        if not EMAIL_REGEX.match(student_user["email"]):
            return Response({"error": "Invalid email format"}, status=400)

        # Validate year field
        valid_years = ["I", "II", "III", "IV"]
        if student_user["year"] not in valid_years:
            return Response({"error": "Invalid year. Must be one of I, II, III, IV."}, status=400)

        # Check if email already exists
        if student_collection.find_one({"email": student_user["email"]}):
            return Response({"error": "Email already exists"}, status=400)

        # Check if regno already exists
        if student_collection.find_one({"regno": student_user["regno"]}):
            return Response({"error": "Registration number already exists"}, status=400)

        # Insert student profile into MongoDB
        student_collection.insert_one(student_user)
        return Response({"message": "Signup successful"}, status=201)

    except Exception as e:
        logger.error(f"Error during student signup: {e}")
        return Response(
            {"error": "Something went wrong. Please try again later."}, status=500
        )

@api_view(["POST"])
@permission_classes([AllowAny])
def update_profile_picture(request):
    """
    Update the profile picture of a student.

    Args:
        request: The HTTP request object containing the profile picture data.

    Returns:
        Response: JSON response indicating profile picture update status.

    Raises:
        AuthenticationFailed: If the JWT token is invalid or expired.
    """
    try:
        jwt_token = request.COOKIES.get("jwt")
        if not jwt_token:
            raise AuthenticationFailed("Authentication credentials were not provided.")

        # Decode JWT token
        try:
            decoded_token = jwt.decode(jwt_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Access token has expired. Please log in again.")
        except jwt.InvalidTokenError:
            raise AuthenticationFailed("Invalid token. Please log in again.")

        student_id = decoded_token.get("student_id")

        if not student_id:
            raise AuthenticationFailed("Invalid token payload.")

        # Check which approach is being used (file upload or base64)
        if 'profileImageBase64' in request.data:
            # Process base64 image
            base64_image = request.data.get('profileImageBase64')

            # Basic validation for base64 images
            if not base64_image or not isinstance(base64_image, str) or not base64_image.startswith('data:image/'):
                return Response({"error": "Invalid base64 image format"}, status=400)

            # Update the user's profile in the database with base64 data
            from bson import ObjectId
            student_collection.update_one(
                {"_id": ObjectId(student_id)},
                {"$set": {"profileImage": base64_image}}
            )

            # Return the base64 data in the response
            return Response({
                "message": "Profile picture updated successfully",
                "profileImage": base64_image
            }, status=200)
        elif 'profileImage' in request.FILES:
            # Original file upload method
            image_file = request.FILES['profileImage']

            # Validate file type
            if not image_file.content_type.startswith('image/'):
                return Response({"error": "Invalid file type. Please upload an image."}, status=400)

            # Validate file size (max 5MB)
            if image_file.size > 5 * 1024 * 1024:
                return Response({"error": "Image size too large. Maximum size is 5MB."}, status=400)

            # Read the file content
            file_content = image_file.read()

            # Convert to base64
            import base64
            base64_image = base64.b64encode(file_content).decode('utf-8')

            # Add the content type prefix for the data URL
            content_type = image_file.content_type
            base64_image_with_prefix = f"data:{content_type};base64,{base64_image}"

            # Update the user's profile in the database with base64 data
            from bson import ObjectId
            student_collection.update_one(
                {"_id": ObjectId(student_id)},
                {"$set": {"profileImage": base64_image_with_prefix}}
            )

            # Return the base64 data in the response
            return Response({
                "message": "Profile picture updated successfully",
                "profileImage": base64_image_with_prefix
            }, status=200)
        else:
            return Response({"error": "No image provided"}, status=400)

    except Exception as e:
        logger.error(f"Error updating profile picture: {str(e)}")
        return Response({"error": f"Failed to update profile picture: {str(e)}"}, status=500)

@api_view(["POST"])
@permission_classes([AllowAny])
def google_login(request):
    """
    Google login with account lockout protection.

    Args:
        request: The HTTP request object containing the Google ID token.

    Returns:
        Response: JSON response indicating login status and details.

    Raises:
        AuthenticationFailed: If the Google token is invalid or the account is locked.
    """
    try:
        data = request.data
        token = data.get("token")  # Google ID token

        if not token:
            return Response({"error": "Google token is required"}, status=400)

        try:
            client_id = os.environ.get('GOOGLE_OAUTH2_CLIENT_ID')
            if not client_id:
                logger.error("Google OAuth client ID not configured")
                return Response({"error": "Google authentication not properly configured"}, status=500)

            idinfo = id_token.verify_oauth2_token(
                token, google_requests.Request(), client_id,
                clock_skew_in_seconds=10
            )

            # Get user email from the token
            email = idinfo['email']

            # Extract profile picture URL
            profile_picture = idinfo.get('picture')
            logger.info(f"Google profile picture URL: {profile_picture}")

            # Check if email is verified by Google
            if not idinfo.get('email_verified', False):
                return Response({"error": "Email not verified by Google"}, status=400)

            # Check if student exists in database
            student_user = student_collection.find_one({"email": email})

            if not student_user:
                return Response({
                    "error": "No account found with this Google email."
                }, status=404)

            # Check if account is locked
            lockout_info = student_user.get("lockout_info", {})
            lockout_until = lockout_info.get("lockout_until")

            if lockout_until:
                lockout_time = datetime.fromisoformat(lockout_until)
                now = datetime.now()
                if now < lockout_time:
                    # Account is locked
                    remaining_seconds = int((lockout_time - now).total_seconds())
                    return Response({
                        "error": "Account temporarily locked due to too many failed login attempts",
                        "lockout_time": remaining_seconds
                    }, status=429)

            # Reset lockout information on successful login
            if lockout_info.get("attempts", 0) > 0:
                student_collection.update_one(
                    {"email": email},
                    {"$set": {"lockout_info": {"attempts": 0, "lockout_until": None}}}
                )

            # Generate tokens
            tokens = generate_tokens_for_student(
                str(student_user["_id"]),
                student_user.get("regno")
            )

            # Include stored profile image from database if available
            stored_profile_image = student_user.get("profileImage")

            # Use Google profile picture as fallback if no stored profile image
            profile_picture_to_use = stored_profile_image or profile_picture

            # Create response with explicit profile picture
            response = Response({
                "message": "Login successful",
                "tokens": tokens,
                "studentId": str(student_user["_id"]),
                "name": student_user["name"],
                "email": student_user["email"],
                "regno": student_user["regno"],
                "dept": student_user["dept"],
                "collegename": student_user["collegename"],
                "profileImage": profile_picture_to_use,  # Return stored image or Google image
            })

            # Set cookies as before
            response.set_cookie(
                key='jwt',
                value=tokens['jwt'],
                httponly=True,
                samesite='None',
                secure=True,
                max_age=1 * 24 * 60 * 60
            )

            return response

        except ValueError as e:
            logger.error(f"Invalid Google token: {e}")
            return Response({"error": "Invalid Google token"}, status=401)

    except Exception as e:
        logger.error(f"Google login error: {e}")
        return Response({"error": "An unexpected error occurred"}, status=500)

@api_view(["POST"])
@permission_classes([AllowAny])
def bulk_student_signup(request):
    """
    Bulk signup for students using XLSX or CSV file with enhanced validation.

    Args:
        request: The HTTP request object containing the file to upload.

    Returns:
        Response: JSON response indicating bulk signup status and errors.

    Raises:
        Response: If the file is invalid or contains errors.
    """
    try:
        # Check if file is in request
        if 'file' not in request.FILES:
            return Response({"error": "No file provided. Please select a file to upload."}, status=400)

        file = request.FILES['file']
        file_extension = file.name.split('.')[-1].lower()

        # Process file based on extension
        if file_extension == 'csv':
            try:
                df = pd.read_csv(file)
            except Exception as e:
                return Response({"error": f"Invalid CSV file: {str(e)}"}, status=400)
        elif file_extension in ['xlsx', 'xls']:
            try:
                df = pd.read_excel(file)
            except Exception as e:
                return Response({"error": f"Invalid Excel file: {str(e)}"}, status=400)
        else:
            return Response({"error": f"Unsupported file format: .{file_extension}. Please upload a CSV or XLSX file."}, status=400)

        # Convert registration number column to string
        if 'regno' in df.columns:
            df['regno'] = df['regno'].astype(str)
            
        # Convert phone to string if present
        if 'phone' in df.columns:
            df['phone'] = df['phone'].astype(str)

        # Validate dataframe columns - added phone to required columns
        required_columns = ["name", "email", "dept", "collegename", "regno", "year", "phone"]
        missing_columns = [col for col in required_columns if col not in df.columns]

        if missing_columns:
            return Response(
                {"error": f"Missing columns in the file: {', '.join(missing_columns)}. Please ensure your file has all required fields."},
                status=400
            )

        # Check if file is empty
        if len(df) == 0:
            return Response({"error": "The uploaded file contains no data."}, status=400)

        # Process each row with sanitization
        success_count = 0
        errors = []
        valid_years = ["I", "II", "III", "IV"]
        email_regex = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        phone_regex = re.compile(r'^\d{10}$')  # Simple regex for 10-digit phone numbers

        for index, row in df.iterrows():
            try:
                # Skip rows with missing required values
                missing_fields = [field for field in required_columns if pd.isnull(row[field])]
                if missing_fields:
                    errors.append({
                        "row": index + 2,
                        "error": f"Missing required fields: {', '.join(missing_fields)}"
                    })
                    continue

                # Sanitize inputs
                sanitized_data = {
                    "name": sanitize_input(str(row['name']).strip()),
                    "email": sanitize_input(str(row['email']).strip()),
                    "collegename": sanitize_input(str(row['collegename']).strip()),
                    "dept": sanitize_input(str(row['dept']).strip()),
                    "regno": sanitize_input(str(row['regno']).strip()),
                    "year": sanitize_input(str(row['year']).strip()),
                    "phone": sanitize_input(str(row['phone']).strip()),  # Add phone field
                }

                # Validate email format
                if not email_regex.match(sanitized_data['email']):
                    errors.append({
                        "row": index + 2,
                        "error": f"Invalid email format: {sanitized_data['email']}"
                    })
                    continue

                # Validate phone format
                if not phone_regex.match(sanitized_data['phone']):
                    errors.append({
                        "row": index + 2,
                        "error": f"Invalid phone number format: {sanitized_data['phone']}. Must be 10 digits with no spaces or dashes."
                    })
                    continue

                # Check year validity
                if sanitized_data['year'] not in valid_years:
                    errors.append({
                        "row": index + 2,
                        "error": f"Invalid year for {sanitized_data['regno']}. Must be one of I, II, III, IV."
                    })
                    continue

                # Check if email already exists
                if student_collection.find_one({"email": sanitized_data['email']}):
                    errors.append({
                        "row": index + 2,
                        "error": f"Email already exists: {sanitized_data['email']}"
                    })
                    continue

                # Check if regno already exists - ensure it's compared as string
                if student_collection.find_one({"regno": sanitized_data['regno']}):
                    errors.append({
                        "row": index + 2,
                        "error": f"Registration number already exists: {sanitized_data['regno']}"
                    })
                    continue
                    
                # Check if phone already exists
                if student_collection.find_one({"phone": sanitized_data['phone']}):
                    errors.append({
                        "row": index + 2,
                        "error": f"Phone number already exists: {sanitized_data['phone']}"
                    })
                    continue

                # Create student record
                student_user = {
                    **sanitized_data,
                    "password": make_password("SNS@123"),  # Default password set
                    "setpassword": False,  # Student must reset password
                    "created_at": datetime.now(),
                    "updated_at": datetime.now(),
                }

                # Insert into database
                student_collection.insert_one(student_user)
                success_count += 1

            except Exception as e:
                errors.append({
                    "row": index + 2,
                    "error": f"Error processing row: {str(e)}"
                })

        # Generate response
        response_data = {
            "success_count": success_count,
            "error_count": len(errors),
            "errors": errors if errors else None
        }

        if success_count > 0:
            return Response(response_data, status=201)
        else:
            return Response(response_data, status=400)

    except pd.errors.ParserError as e:
        logger.error(f"Error parsing file: {e}")
        return Response(
            {"error": f"Error parsing file: {str(e)}. Please check the file format."},
            status=400
        )
    except Exception as e:
        logger.error(f"Error during bulk student signup: {e}")
        return Response(
            {"error": f"Error processing file: {str(e)}"},
            status=500
        )

@api_view(["GET"])
@permission_classes([AllowAny])
def student_profile(request):
    """
    API to fetch the profile details of the logged-in student.

    Args:
        request: The HTTP request object.

    Returns:
        Response: JSON response containing the student's profile details.

    Raises:
        AuthenticationFailed: If the JWT token is invalid or expired.
    """
    try:
        # Use the enhanced JWT validation function
        decoded_token = validate_jwt_token(request)

        # Extract student ID from the decoded token
        student_id = decoded_token.get("student_id")

        # Handle if student ID is not a valid ObjectId
        try:
            # Fetch student details from the database
            student = student_collection.find_one({"_id": ObjectId(student_id)})
        except InvalidId:
            return Response({"error": "Invalid student ID format"}, status=400)

        if not student:
            return Response({"error": "Student not found"}, status=404)

        # Prepare the response data - sanitize all outputs
        response_data = {
            "studentId": str(student["_id"]),
            "name": sanitize_input(student.get("name", "")),
            "email": student.get("email", ""),  # Email addresses don't need sanitization in the same way
            "regno": sanitize_input(student.get("regno", "")),
            "dept": sanitize_input(student.get("dept", "")),
            "collegename": sanitize_input(student.get("collegename", "")),
            "setpassword": student.get("setpassword", False),
            "profileImage": student.get("profileImage", ""),  # Profile image URLs/Base64 should be handled carefully
        }

        return Response(response_data, status=200)

    except AuthenticationFailed as auth_error:
        return Response({"error": str(auth_error)}, status=401)
    except Exception as e:
        logger.error(f"Unexpected error in student_profile: {e}")
        return Response({"error": "An unexpected error occurred"}, status=500)

@api_view(["GET"])
@permission_classes([AllowAny])  # Allow without authentication
def get_students(request):
    """
    API to fetch all students from the database.

    Args:
        request: The HTTP request object.

    Returns:
        Response: JSON response containing the list of students.
    """
    cache.clear()  # Clear cache here
    try:
        # Fetch students from the database, including the "year" field
        students = list(student_collection.find(
            {},
            {"_id": 1, "name": 1, "regno": 1, "dept": 1, "collegename": 1, "year": 1, "email":1, "section":1}  # Include "year" field
        ))

        # Rename _id to studentId and convert to string
        for student in students:
            student["studentId"] = str(student["_id"])  # Convert ObjectId to string
            del student["_id"]  # Remove original _id to avoid confusion

        return Response(students, status=200)
    except Exception as e:
        return Response({"error": str(e)}, status=500)

@api_view(["GET"])
@permission_classes([AllowAny])  # Allow unauthenticated access for testing
def get_tests_for_student(request):
    """
    API to fetch tests assigned to a student based on regno from JWT.

    Args:
        request: The HTTP request object.

    Returns:
        Response: JSON response containing the list of tests assigned to the student.

    Raises:
        AuthenticationFailed: If the JWT token is invalid or expired.
    """
    try:
        # Retrieve the JWT token from cookies
        jwt_token = request.COOKIES.get("jwt")
        if not jwt_token:
            raise AuthenticationFailed("Authentication credentials were not provided.")

        # Decode the JWT token
        try:
            decoded_token = jwt.decode(jwt_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Access token has expired. Please log in again.")
        except jwt.InvalidTokenError:
            raise AuthenticationFailed("Invalid token. Please log in again.")

        # Extract regno from the decoded token
        regno = decoded_token.get("regno")
        if not regno:
            return JsonResponse({"error": "Invalid token payload."}, status=401)

        # Fetch contests where the student is visible in visible_to
        contests = list(coding_assessments_collection.find(
            {"visible_to": regno}  # Filter only on 'visible_to'
        ))

        if not contests:
            return JsonResponse([], safe=False, status=200)  # Return an empty list if no contests are found

        # Convert ObjectId to string for JSON compatibility and format response
        formatted_response = [
            {
                **contest,  # Spread the entire contest object
                "_id": str(contest["_id"]),  # Convert _id (ObjectId) to string
            }
            for contest in contests
        ]

        return JsonResponse(formatted_response, safe=False, status=200)

    except AuthenticationFailed as auth_error:
        return JsonResponse({"error": str(auth_error)}, status=401)
    except Exception as e:
        print("Error fetching tests for student:", str(e))
        return JsonResponse({"error": "Failed to fetch tests"}, status=500)

@api_view(["GET"])
@permission_classes([AllowAny])  # Allow unauthenticated access for testing
def get_mcq_tests_for_student(request):
    """
    API to fetch MCQ tests assigned to a student based on regno from JWT,
    including the entire document.
    """
    try:
        # Retrieve the JWT token from cookies
        jwt_token = request.COOKIES.get("jwt")
        if not jwt_token:
            raise AuthenticationFailed("Authentication credentials were not provided.")

        # Decode the JWT token
        try:
            decoded_token = jwt.decode(jwt_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Access token has expired. Please log in again.")
        except jwt.InvalidTokenError:
            raise AuthenticationFailed("Invalid token. Please log in again.")

        # Extract regno from the decoded token
        regno = decoded_token.get("regno")
        if not regno:
            return JsonResponse({"error": "Invalid token payload."}, status=401)

        # Optimize: Add projection to fetch only needed fields and exclude unnecessary ones
        mcq_tests = list(mcq_assessments_collection.find(
            {"visible_to": regno},
            {"questions": 0, "correctAnswer": 0 }
        ))

        if not mcq_tests:
            return JsonResponse([], safe=False, status=200)

        # Optimize: Use list comprehension for faster processing
        formatted_response = [{
            **test,
            "_id": test['contestId'],
            "assessment_type": "mcq",
            "sections": bool(test.get('sections'))
        } for test in mcq_tests]

        return JsonResponse(formatted_response, safe=False, status=200)
    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500) 
   
    
@api_view(["GET"])
@permission_classes([AllowAny])  # Allow unauthenticated access for testing
def get_coding_reports_for_student(request):
    """
    API to fetch coding reports for a student based on student_id from JWT.

    Args:
        request: The HTTP request object.

    Returns:
        Response: JSON response containing the list of coding reports for the student.

    Raises:
        AuthenticationFailed: If the JWT token is invalid or expired.
    """
    try:
        # Retrieve the JWT token from cookies
        jwt_token = request.COOKIES.get("jwt")
        if not jwt_token:
            raise AuthenticationFailed("Authentication credentials were not provided.")

        # Decode the JWT token
        try:
            decoded_token = jwt.decode(jwt_token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Access token has expired. Please log in again.")
        except jwt.InvalidTokenError:
            raise AuthenticationFailed("Invalid token. Please log in again.")

        # Extract student_id from the decoded token
        student_id = decoded_token.get("student_id")
        if not student_id:
            return JsonResponse({"error": "Invalid token payload."}, status=401)

        # Fetch coding reports where the student's student_id matches
        coding_reports = list(coding_report_collection.find({}))

        if not coding_reports:
            return JsonResponse([], safe=False, status=200)  # Return an empty list if no reports are found

        # Convert ObjectId to string for JSON compatibility and format response
        formatted_response = []
        for report in coding_reports:
            for student in report["students"]:
                if student["student_id"] == student_id:
                    formatted_response.append({
                        "contest_id": report["contest_id"],
                        "student_id": student["student_id"],
                        "status": student["status"]
                    })

        return JsonResponse(formatted_response, safe=False, status=200)

    except AuthenticationFailed as auth_error:
        return JsonResponse({"error": str(auth_error)}, status=401)
    except Exception as e:
        print("Error fetching coding reports for student:", str(e))
        return JsonResponse({"error": "Failed to fetch coding reports"}, status=500)

@api_view(["GET"])
@permission_classes([AllowAny])
def get_mcq_reports_for_student(request):
    """
    API to fetch MCQ reports for a student based on student_id from JWT.

    Args:
        request: The HTTP request object.

    Returns:
        Response: JSON response containing the list of MCQ reports for the student.

    Raises:
        AuthenticationFailed: If the JWT token is invalid or expired.
    """
    try:
        # Use the enhanced JWT validation function
        decoded_token = validate_jwt_token(request)

        student_id = decoded_token.get("student_id")

        # Validate student_id format
        try:
            # Just validate the ObjectId format, we don't need to fetch the student here
            ObjectId(student_id)
        except InvalidId:
            return JsonResponse({"error": "Invalid student ID format"}, status=400)

        # Use aggregation pipeline for better performance
        pipeline = [
            {
                "$match": {
                    "students.student_id": student_id
                }
            },
            {
                "$project": {
                    "_id": 0,
                    "contest_id": 1,
                    "students": {
                        "$filter": {
                            "input": "$students",
                            "as": "student",
                            "cond": {"$eq": ["$$student.student_id", student_id]}
                        }
                    }
                }
            }
        ]

        mcq_reports = list(mcq_assessments_report_collection.aggregate(pipeline))

        if not mcq_reports:
            return JsonResponse([], safe=False, status=200)

        # Sanitize and format the response
        formatted_response = []
        for report in mcq_reports:
            for student in report["students"]:
                formatted_response.append({
                    "contest_id": sanitize_input(report["contest_id"]),
                    "student_id": sanitize_input(student["student_id"]),
                    "status": sanitize_input(student["status"])
                })

        return JsonResponse(formatted_response, safe=False, status=200)

    except AuthenticationFailed as auth_error:
        return JsonResponse({"error": str(auth_error)}, status=401)
    except Exception as e:
        logger.error(f"Error fetching MCQ reports for student: {str(e)}")
        return JsonResponse({"error": f"Failed to fetch MCQ reports: {str(e)}"}, status=500)

@csrf_exempt
def check_publish_status(request):
    """
    API to check whether the results for a specific test or contest have been published.

    Args:
        request: The HTTP request object containing test IDs.

    Returns:
        Response: JSON response indicating the publish status of the tests.

    Raises:
        Response: If the request method is invalid or an error occurs.
    """
    try:
        if request.method != 'POST':
            return JsonResponse({"error": "Invalid request method"}, status=405)

        data = json.loads(request.body)
        test_ids = data.get('testIds', [])

        if not test_ids:
            return JsonResponse({}, status=200)

        # Optimize: Use bulk operations for multiple IDs
        mcq_reports = mcq_assessments_report_collection.find(
            {"contest_id": {"$in": test_ids}},
            {"contest_id": 1, "ispublish": 1}
        )
        coding_reports = coding_report_collection.find(
            {"contest_id": {"$in": test_ids}},
            {"contest_id": 1, "ispublish": 1}
        )

        # Combine results from both collections
        publish_status = {}
        for report in list(mcq_reports) + list(coding_reports):
            contest_id = report["contest_id"]
            if contest_id not in publish_status:  # Only take first occurrence
                publish_status[contest_id] = report.get("ispublish", False)

        # Fill in missing test_ids with False
        for test_id in test_ids:
            if test_id not in publish_status:
                publish_status[test_id] = False

        return JsonResponse(publish_status, status=200)

    except Exception as e:
        return JsonResponse({"error": f"Failed to check publish status: {str(e)}"}, status=500)

client = MongoClient('mongodb+srv://krish:krish@assessment.ar5zh.mongodb.net/')
db = client['test_portal_db']

@csrf_exempt
def student_section_details(request, contest_id):
    """
    API to get section details of a contest for students
    """
    if request.method != "GET":
        return JsonResponse({"error": "Invalid request method"}, status=405)
    
    # Sanitize and validate contest_id
    contest_id = sanitize_input(contest_id)
    if not contest_id or len(contest_id) > 100:  # Basic validation for contest_id length
        return JsonResponse({"error": "Invalid contest ID"}, status=400)
    
    try:
        # Fetch contest details by contestId
        contest = mcq_assessments_collection.find_one(
            {"contestId": contest_id},
            {
                "sections": 1,
                "assessmentOverview.guidelines": 1,
                "assessmentOverview.timingType": 1,
                "staffId": 1,
                "_id": 0
            }
        )

        if not contest:
            return JsonResponse({"error": "Contest not found"}, status=404)

        sections = contest.get("sections", [])
        guidelines = contest.get("assessmentOverview", {}).get("guidelines", "")
        timing_type = contest.get("assessmentOverview", {}).get("timingType", "")

        # Calculate total duration properly handling both integer and dictionary durations
        total_duration = 0
        for section in sections:
            section_duration = section.get("sectionDuration", 0)
            try:
                if isinstance(section_duration, dict):
                    # If duration is a dict with hours and minutes, convert to total minutes
                    hours = section_duration.get("hours", 0)
                    minutes = section_duration.get("minutes", 0)
                    if isinstance(hours, str):
                        hours = int(hours) if hours.isdigit() else 0
                    if isinstance(minutes, str):
                        minutes = int(minutes) if minutes.isdigit() else 0
                    # Add to total (in minutes)
                    total_duration += (hours * 60) + minutes
                elif isinstance(section_duration, (int, float)):
                    # If duration is already a number, add it directly
                    total_duration += section_duration
                elif isinstance(section_duration, str) and section_duration.isdigit():
                    # Handle string representations of numbers
                    total_duration += int(section_duration)
            except (ValueError, TypeError) as e:
                logger.error(f"Error calculating duration for section: {e}")
                # Skip this section duration if there's an error

        # Format the response with section name, number of questions, and duration
        section_data = []
        for section in sections:
            try:
                section_duration = section.get("sectionDuration", 0)
                # Format duration consistently as a dictionary with hours and minutes
                if isinstance(section_duration, dict):
                    formatted_duration = section_duration
                elif isinstance(section_duration, (int, float)) or (isinstance(section_duration, str) and section_duration.isdigit()):
                    # Convert numeric duration to hours and minutes dictionary
                    duration_value = int(section_duration) if isinstance(section_duration, str) else section_duration
                    formatted_duration = {
                        "hours": duration_value // 60,
                        "minutes": duration_value % 60
                    }
                else:
                    formatted_duration = {"hours": 0, "minutes": 0}

                mark_allotment = section.get("markAllotment", 0)
                
                # Sanitize all string values
                section_data.append({
                    "name": sanitize_input(section.get("sectionName", "")),
                    "numQuestions": section.get("numQuestions", 0),
                    "duration": formatted_duration,
                    "mark_allotment": mark_allotment,
                })
            except Exception as e:
                logger.error(f"Error processing section data: {e}")
                # Add a placeholder section in case of error
                section_data.append({
                    "name": "Section (error occurred)",
                    "numQuestions": 0,
                    "duration": {"hours": 0, "minutes": 0},
                    "mark_allotment": 0
                })

        # Format total duration as hours and minutes
        formatted_total_duration = {
            "hours": total_duration // 60,
            "minutes": total_duration % 60
        }

        # Prepare the base response with sanitized values
        response_data = {
            "sections": section_data,
            "guidelines": sanitize_input(guidelines),
            "totalDuration": formatted_total_duration,
            "timingType": sanitize_input(timing_type)
        }
        
        # Fetch staff details using staffId
        staff_id = contest.get('staffId')
        if staff_id:
            try:
                # Validate staffId format
                if not ObjectId.is_valid(staff_id):
                    raise InvalidId("Invalid staff ID format")
                    
                staff_collection = db['staff']
                staff_details = staff_collection.find_one(
                    {"_id": ObjectId(staff_id)},
                    {"full_name": 1, "email": 1, "phone_no": 1, "_id": 0}
                )

                if staff_details:
                    # Convert phone_no from NumberLong to string if needed
                    if 'phone_no' in staff_details and isinstance(staff_details['phone_no'], dict):
                        if '$numberLong' in staff_details['phone_no']:
                            staff_details['phone_no'] = staff_details['phone_no']['$numberLong']
                    
                    # Sanitize staff details
                    sanitized_staff_details = {
                        "full_name": sanitize_input(staff_details.get('full_name', '')),
                        "email": sanitize_input(staff_details.get('email', '')),
                        "phone_no": sanitize_input(str(staff_details.get('phone_no', '')))
                    }

                    # Add staff details to the response
                    response_data['staff_details'] = sanitized_staff_details
            except InvalidId:
                response_data['staff_details'] = {"error": "Invalid staff ID format"}
            except Exception as e:
                # Log the error but don't fail the whole request
                logger.error(f"Error fetching staff details: {str(e)}")
                response_data['staff_details'] = {"error": "Failed to fetch staff details"}

        return JsonResponse(response_data, status=200)

    except Exception as e:
        logger.error(f"Error in student_section_details: {str(e)}")
        return JsonResponse({"error": f"An unexpected error occurred: {str(e)}"}, status=500)

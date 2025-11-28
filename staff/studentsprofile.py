# Standard library imports
import json
import logging
import os
import re
import html
import signal
import secrets
import string
from functools import wraps
from datetime import datetime

# Third-party imports
import jwt
import bleach
from bson import ObjectId
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, OperationFailure, ServerSelectionTimeoutError
from pymongo import ASCENDING

# Django imports
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.cache import cache
from django.utils.html import escape
from rest_framework.exceptions import AuthenticationFailed

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
    # Log successful loading of .env file
    env_loaded = True
except ImportError:
    # Log that python-dotenv is not installed
    env_loaded = False

# Initialize logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

if env_loaded:
    logger.info("Environment variables loaded from .env file")
else:
    logger.warning("python-dotenv not installed; using default environment variables")

# Configuration from environment variables
MONGODB_URI = os.environ.get('MONGODB_URI', 'mongodb+srv://krish:krish@assessment.ar5zh.mongodb.net/')
MONGODB_DB_NAME = os.environ.get('MONGODB_DB_NAME', 'test_portal_db')
MONGODB_TIMEOUT_MS = int(os.environ.get('MONGODB_TIMEOUT_MS', 5000))
JWT_SECRET = os.environ.get('JWT_SECRET', 'test')  # Default for development only
JWT_ALGORITHM = os.environ.get('JWT_ALGORITHM', 'HS256')
SECRET_KEY = os.environ.get('SECRET_KEY', 'Rahul')  # Default for development only
VALID_STAFF_ROLES = ['Admin', 'Principal', 'HOD', 'Staff']
EMAIL_REGEX = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
CACHE_TIMEOUT = int(os.environ.get('CACHE_TIMEOUT', 600))  # Cache for 10 minutes by default
IS_PRODUCTION = os.environ.get('DJANGO_ENV') == 'production'

# Log configuration information (but not sensitive values)
logger.info(f"Using MongoDB database: {MONGODB_DB_NAME}")
logger.info(f"MongoDB timeout set to: {MONGODB_TIMEOUT_MS}ms")
logger.info(f"Cache timeout set to: {CACHE_TIMEOUT}s")
logger.info(f"Environment: {'Production' if IS_PRODUCTION else 'Development'}")

# Global variables declaration
db = None
mongo_client = None
students_collection = None
staff_collection = None




# Student data validation schema
STUDENT_SCHEMA = {
    'regno': {'type': 'text', 'required': True},
    'registration_number': {'type': 'text', 'required': False},
    'name': {'type': 'text', 'required': True},
    'email': {'type': 'email', 'required': False},
    'dept': {'type': 'text', 'required': True},
    'collegename': {'type': 'text', 'required': True},
    'year': {'type': 'text', 'required': True},
    'phone': {'type': 'text', 'required': False},
    'address': {'type': 'text', 'required': False},
    'dob': {'type': 'text', 'required': False},
    'gender': {'type': 'text', 'required': False},
}

# Time limiting decorator for security sensitive operations
class TimeoutDecorator:
    """Context manager to limit time spent in critical sections"""
    def __init__(self, seconds):
        self.seconds = seconds
        self.old_handler = None
        
    def __enter__(self):
        def handler(signum, frame):
            raise TimeoutError(f"Operation timed out after {self.seconds} seconds")
            
        # Save the old handler
        self.old_handler = signal.signal(signal.SIGALRM, handler)
        signal.setitimer(signal.ITIMER_REAL, self.seconds)
        
    def __exit__(self, type, value, traceback):
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, self.old_handler)


# Database connection helper with enhanced error handling
def get_db_connection():
    """Get MongoDB connection and collections with error handling"""
    try:
        mongo_client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=MONGODB_TIMEOUT_MS)
        # Verify connection is working
        mongo_client.admin.command('ismaster')
        db = mongo_client[MONGODB_DB_NAME]
        logger.info("Successfully connected to MongoDB")
        return db, mongo_client
    except ConnectionFailure as e:
        logger.critical(f"MongoDB Connection Error: {str(e)}")
        raise
    except ServerSelectionTimeoutError as e:
        logger.critical(f"MongoDB Server Selection Timeout: {str(e)}")
        raise

# Initialize database collections with fallback
try:
    db, mongo_client = get_db_connection()
    students_collection = db['students']
    staff_collection = db['staff']
except Exception as e:
    logger.critical(f"Failed to initialize database connection: {str(e)}")
    # We'll handle the fallback when the views are called
# After ensuring the connection is successful
try:
    students_collection.create_index([('regno', ASCENDING)], unique=True)
    students_collection.create_index([('dept', ASCENDING), ('collegename', ASCENDING)])
except Exception as e:
    logger.error(f"Failed to create indexes: {str(e)}")

if students_collection is not None:
    try:
        students_collection.create_index([('regno', ASCENDING)], unique=True)
        students_collection.create_index([('dept', ASCENDING), ('collegename', ASCENDING)])
    except Exception as e:
        logger.error(f"Failed to create indexes: {str(e)}")
else:
    logger.error("Students collection is not initialized.")


# Security helper functions
def sanitize_input(value, field_type="text"):
    """
    Sanitize input values to prevent injection attacks.
    
    Args:
        value: The input value to sanitize
        field_type: The type of field (text, email, number, etc.)
        
    Returns:
        Sanitized value or None if value is invalid for the field type
    """
    if value is None:
        return None
        
    if field_type == "text":
        # For text fields, strip HTML and dangerous characters
        if isinstance(value, str):
            # First, escape HTML
            value = escape(value.strip())
            # Then, use bleach to clean any potentially dangerous HTML/scripts
            value = bleach.clean(value, strip=True)
            return value
        return str(value) if value is not None else None
        
    elif field_type == "email":
        # For emails, validate format and sanitize
        if isinstance(value, str) and re.match(EMAIL_REGEX, value.strip()):
            return value.strip().lower()
        return None
        
    elif field_type == "number":
        # For numeric fields, ensure it's a valid number
        try:
            if isinstance(value, (int, float)):
                return value
            elif isinstance(value, str):
                # Try to convert to number if it's a string
                if value.isdigit():
                    return int(value)
                elif all(c.isdigit() or c == '.' for c in value) and value.count('.') <= 1:
                    return float(value)
        except (ValueError, TypeError):
            pass
        return None
        
    elif field_type == "boolean":
        # For boolean fields
        if isinstance(value, bool):
            return value
        elif isinstance(value, str):
            value = value.lower().strip()
            if value in ('true', 'yes', '1'):
                return True
            elif value in ('false', 'no', '0'):
                return False
        return None
        
    # Default case
    return value if value is not None else None


def validate_data_types(data, schema):
    """
    Validate that all fields in the data match their expected types.
    
    Args:
        data: Dictionary of data to validate
        schema: Dictionary mapping field names to expected types
        
    Returns:
        Tuple of (is_valid, errors)
    """
    errors = {}
    
    for field, field_schema in schema.items():
        if field not in data:
            if field_schema.get('required', False):
                errors[field] = "Field is required"
            continue
            
        field_type = field_schema.get('type', 'text')
        value = data[field]
        
        # Sanitize and type check
        sanitized = sanitize_input(value, field_type)
        
        if sanitized is None and field_schema.get('required', False):
            errors[field] = f"Invalid value for {field_type} field"
        elif field_schema.get('required', False) and isinstance(sanitized, str) and not sanitized.strip():
            errors[field] = "Field cannot be empty"
            
        # Store the sanitized value back in the data
        data[field] = sanitized
    
    return len(errors) == 0, errors


def generate_secure_error_id():
    """Generate a secure error ID for logging that doesn't expose sensitive information"""
    chars = string.ascii_letters + string.digits
    return ''.join(secrets.choice(chars) for _ in range(8))


# Enhanced error response helper
def error_response(message, status_code=400, include_details=False, error_data=None):
    """
    Create a standardized error response with security in mind.
    
    Args:
        message: User-friendly error message
        status_code: HTTP status code
        include_details: Whether to include detailed error information (for development)
        error_data: Additional error data for logging
        
    Returns:
        JsonResponse with error information
    """
    error_id = generate_secure_error_id()
    
    # Create a sanitized user-facing message
    user_message = message
    if status_code >= 500 and IS_PRODUCTION:
        user_message = f"An unexpected error occurred. Reference ID: {error_id}"
    
    # Log the full error details
    if error_data:
        logger.error(f"Error ID {error_id}: {message}", extra={
            'error_data': error_data,
            'status_code': status_code
        })
    else:
        logger.error(f"Error ID {error_id}: {message}")
    
    response_data = {"error": user_message, "error_id": error_id}
    
    if include_details and error_data and not IS_PRODUCTION:
        # Only include detailed errors in development
        response_data["details"] = error_data
        
    return JsonResponse(response_data, status=status_code)


# Data validation helpers
def validate_staff_role(role):
    """Validate that staff role is one of the expected values"""
    valid_roles = {
        'Admin': 'Admin',
        'Principal': 'Principal',
        'HOD': 'HOD',
        'Staff': 'Staff'
    }
    if role not in valid_roles:
        logger.warning(f"Invalid staff role detected: '{role}'")
        return 'Staff'  # Default to most restrictive role
    return valid_roles[role]


def validate_string_field(value, field_name, default=""):
    """Validate string fields and provide defaults for missing/invalid values"""
    if not isinstance(value, str) or not value.strip():
        logger.warning(f"Invalid {field_name} detected: {value!r}, using default")
        return default
    
    # Sanitize the string to prevent injection
    value = value.strip()
    value = bleach.clean(value, strip=True)
    return escape(value)

def validate_list_field(value, field_name):
    """Validate list fields and ensure they contain valid strings"""
    if not isinstance(value, list):
        logger.warning(f"Expected list for {field_name}, got {type(value).__name__}: {value!r}")
        return []
    
    # Filter out non-string or empty items and sanitize each item
    valid_items = []
    for item in value:
        if isinstance(item, str) and item.strip():
            # Sanitize each item
            cleaned = bleach.clean(item.strip(), strip=True)
            escaped = escape(cleaned).lower()
            valid_items.append(escaped)
    
    if len(valid_items) < len(value):
        logger.warning(f"Some invalid items filtered from {field_name}")
    
    return valid_items

def validate_email(email):
    """Validate email address format"""
    if not email or not isinstance(email, str):
        return False
    
    # Sanitize email before validation
    email = bleach.clean(email.strip(), strip=True)
    email = escape(email)
    
    return bool(re.match(EMAIL_REGEX, email))


# Enhanced JWT token extraction
def extract_jwt_payload(request):
    """Extract and validate JWT token from request with enhanced security"""
    jwt_token = request.COOKIES.get('jwt')
    if not jwt_token:
        raise AuthenticationFailed('Authentication required to access this resource.')

    try:
        # Use options to enforce security checks
        decoded_token = jwt.decode(
            jwt_token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            options={"verify_signature": True, "verify_exp": True, "verify_aud": False}
        )
    except jwt.ExpiredSignatureError:
        raise AuthenticationFailed('Your session has expired. Please log in again.')
    except jwt.InvalidTokenError:
        raise AuthenticationFailed('Invalid authentication token. Please log in again.')
    except Exception as e:
        error_id = generate_secure_error_id()
        logger.error(f"Error ID {error_id}: Unexpected JWT error: {str(e)}")
        raise AuthenticationFailed('Authentication error. Please log in again.')

    # Validate token contains required fields
    staff_id = decoded_token.get('staff_user')
    if not staff_id:
        raise AuthenticationFailed('Invalid authentication token format.')

    try:
        # Ensure staff_id is a valid ObjectId
        ObjectId(staff_id)
    except Exception:
        raise AuthenticationFailed('Invalid authentication token data.')

    return staff_id



# Query builder helper with validation
def build_student_query(staff_role, staff_college, staff_departments):
    """Build query based on staff role and permissions with validation"""
    # Validate inputs
    staff_role = validate_staff_role(staff_role)
    staff_college = validate_string_field(staff_college, "staff_college")

    # Process query based on validated role
    if staff_role == 'Admin':
        query = {}
        logger.info("Admin access: retrieving all students")
    elif staff_role == 'Principal':
        if not staff_college:
            logger.warning("Principal with no college specified, showing no students")
            query = {"_id": ObjectId("000000000000000000000000")}
        else:
            college_name = re.escape(staff_college)
            query = {'collegename': {'$regex': f'^{college_name}$', '$options': 'i'}}
    else:
        if isinstance(staff_departments, list):
            depts = [d.lower() for d in staff_departments if d and isinstance(d, str)]
            if not depts:
                logger.warning(f"Staff with role {staff_role} has no valid departments, showing no students")
                query = {"_id": ObjectId("000000000000000000000000")}
            else:
                or_conditions = [
                    {'dept': dept.upper(), 'collegename': staff_college}
                    for dept in depts
                ]
                query = {'$or': or_conditions}
                logger.info(f"HOD access with multiple departments: {depts}")
        elif staff_departments:
            department = str(staff_departments).lower()
            dept_name = re.escape(department)
            college_name = re.escape(staff_college)
            query = {'dept': department.upper(), 'collegename': staff_college}
            logger.info(f"Staff access for department: {department}")
        else:
            logger.warning(f"Staff with role {staff_role} has no department, showing no students")
            query = {"_id": ObjectId("000000000000000000000000")}

    logger.info(f"MongoDB Query: {query}")
    return query


# Add this to your get_students_with_aggregate function
def get_students_with_aggregate(request, staff_role, staff_college, staff_departments):
    """Retrieve students using MongoDB aggregation with optimized fields."""
    # Get pagination parameters
    page = int(request.GET.get('page', 1))
    page_size = min(int(request.GET.get('page_size', 20)), 100)  # Limit max page size
    skip = (page - 1) * page_size
    
    # Get sort field and direction
    sort_field = request.GET.get('sort_field', 'name')
    sort_dir = 1 if request.GET.get('sort_dir', 'asc').lower() == 'asc' else -1
    
    # Build the query using the optimized method
    query = build_student_query(staff_role, staff_college, staff_departments)
    
    try:
        pipeline = [
            # First stage: Add lowercase fields for efficient searching
            {
                '$addFields': {
                    'collegename_lower': {'$toLower': '$collegename'},
                    'dept_lower': {'$toLower': '$dept'}
                }
            },
            # Second stage: Match using the query
            {'$match': query},
            # Third stage: Sort the results
            {'$sort': {sort_field: sort_dir}},
            # Fourth stage: Implement pagination
            {'$skip': skip},
            {'$limit': page_size},
            # Final stage: Project only needed fields to reduce network transfer
            {'$project': {
                '_id': 0,
                'regno': 1,
                'name': 1,
                'email': 1,
                'dept': 1,
                'collegename': 1,
                'year': 1,
                'phone': 1,
                # Exclude the lowercase fields from results
                'collegename_lower': 0,
                'dept_lower': 0
            }}
        ]
        
        # Execute aggregation
        students = list(students_collection.aggregate(pipeline))
        
        # Get total count for pagination using a separate optimized count query
        total_count = students_collection.count_documents(query)
        
        return {
            'students': students,
            'pagination': {
                'page': page,
                'page_size': page_size,
                'total': total_count,
                'total_pages': (total_count + page_size - 1) // page_size
            }
        }
    except Exception as e:
        logger.error(f"Error in aggregation pipeline: {str(e)}")
        # Fallback to traditional query if aggregation fails
        students = list(students_collection.find(query, {'_id': 0}).skip(skip).limit(page_size))
        return {'students': students}
    
# Add this function to optimize array searches
def optimize_list_search(staff_departments):
    """Convert list to hash set for O(1) lookup performance"""
    if not staff_departments:
        return set()
        
    if isinstance(staff_departments, list):
        # Convert to set for O(1) lookups
        return {d.lower() for d in staff_departments if d and isinstance(d, str)}
    else:
        # Single department case
        return {str(staff_departments).lower()} if staff_departments else set()
        
def get_cached_student_count(staff_id, staff_role, staff_college, staff_departments):
    """Get the cached student count based on staff permissions."""
    cache_key = f"student_count:{staff_id}:{staff_role}:{staff_college}:{staff_departments}"
    cached_count = cache.get(cache_key)

    if cached_count is not None:
        logger.info(f"Retrieved student count from cache for {staff_id}")
        return cached_count

    query = build_student_query(staff_role, staff_college, staff_departments)
    count = students_collection.count_documents(query)

    cache.set(cache_key, count, CACHE_TIMEOUT)
    logger.info(f"Stored student count in cache for {staff_id}")

    return count

# Cache helper for reducing database calls
def get_cached_students(staff_id, staff_role, staff_college, staff_departments, force_refresh=False):
    """Get students from database (cache disabled for now)"""
    # Query database
    query = build_student_query(staff_role, staff_college, staff_departments)
    students = list(students_collection.find(query, {'_id': 0}))
    
    # Return data without caching
    response_data = {
        'students': students,
        'staffDepartment': staff_departments,
        'staffCollege': staff_college,
        'staffRole': staff_role,
        'status': 'success',
        'query': str(query),
        'cached': False,
        'cache_time': datetime.now().isoformat()
    }
    
    return response_data


# Enhanced staff authentication middleware
def staff_auth_required(view_func):
    """Enhanced middleware to handle staff authentication with security focus"""
    @wraps(view_func)
    def wrapped_view(request, *args, **kwargs):
        global db, mongo_client, students_collection, staff_collection
        
        # Rate limiting check
        client_ip = request.META.get('REMOTE_ADDR', '')
        cache_key = f"auth_attempt_{client_ip}"
        attempts = cache.get(cache_key, 0)
        
        if attempts >= 5:  # Max 5 failed attempts
            logger.warning(f"Rate limit exceeded for {client_ip}")
            return error_response("Too many authentication attempts. Please try again later.", 429)
            
        try:
            # Check if database connection exists, try to reconnect if not
            if mongo_client is None:
                logger.warning("Database connection not established, attempting to reconnect")
                db, mongo_client = get_db_connection()
                students_collection = db['students']
                staff_collection = db['staff']
            
            # Extract JWT payload using enhanced helper function
            staff_id = extract_jwt_payload(request)
            
            # Reset rate limiting on successful token extraction
            if attempts > 0:
                cache.delete(cache_key)
            
            # Get staff details from staff collection with error handling
            try:
                # Try to get from cache first
                cache_key = f"staff:{staff_id}"
                staff_details = cache.get(cache_key)
                
                if not staff_details:
                    staff_details = staff_collection.find_one({'_id': ObjectId(staff_id)})
                    if staff_details:
                        # Convert ObjectId to string for JSON serialization
                        staff_details['_id'] = str(staff_details['_id'])
                        cache.set(cache_key, staff_details, CACHE_TIMEOUT)
                
            except OperationFailure as e:
                logger.error(f"Database operation failed: {str(e)}")
                return error_response("Database error occurred", 500, 
                                    error_data={"operation": "staff_lookup", "error": str(e)})
            except ServerSelectionTimeoutError as e:
                logger.error(f"Database connection timeout: {str(e)}")
                return error_response("Service temporarily unavailable", 503)
            
            if not staff_details:
                return error_response("Staff account not found", 404)

            # Validate and extract staff information
            staff_role = validate_staff_role(staff_details.get('role', ''))
            staff_college = validate_string_field(staff_details.get('collegename', ''), 'staff_college')
            
            # Handle both string and array formats for department
            staff_department_raw = staff_details.get('department', '')
            if isinstance(staff_department_raw, list):
                staff_departments = validate_list_field(staff_department_raw, 'department')
                logger.info(f"Staff has multiple departments: {staff_departments}")
            else:
                staff_departments = validate_string_field(staff_department_raw, 'department').lower()
                logger.info(f"Staff has single department: {staff_departments}")

            # Add authenticated staff details to request for the view to use
            request.staff_id = staff_id
            request.staff_role = staff_role
            request.staff_college = staff_college
            request.staff_departments = staff_departments
            
            # Security audit logging
            logger.info(f"Staff authenticated: ID={staff_id}, Role={staff_role}, IP={client_ip}")
            
            # Log validated information
            logger.info(f"Staff Role (validated): {staff_role}")
            logger.info(f"Staff College (validated): {staff_college}")
            logger.info(f"Staff Departments (validated): {staff_departments}")
            
            return view_func(request, *args, **kwargs)
            
        except AuthenticationFailed as auth_failed:
            # Increment rate limiting counter on auth failure
            cache.set(cache_key, attempts + 1, 300)  # 5 minutes timeout
            
            return error_response(str(auth_failed), 401)
        except ConnectionFailure as e:
            logger.error(f"MongoDB Connection Error: {str(e)}")
            return error_response("Service temporarily unavailable", 503)
        except Exception as e:
            error_id = generate_secure_error_id()
            logger.error(f"Error ID {error_id}: Unexpected error in auth middleware: {str(e)}", exc_info=True)
            return error_response("An unexpected error occurred", 500)
    
    return wrapped_view


@csrf_exempt
@staff_auth_required
def student_profile(request):
    """Main view function for student profile operations"""
    if request.method == 'GET':
        # Check for cache busting parameter
        force_refresh = request.GET.get('refresh', '').lower() == 'true'
        
        return handle_get_request(
            request.staff_id,
            request.staff_role, 
            request.staff_college, 
            request.staff_departments,
            force_refresh
        )
    elif request.method == 'POST':
        return handle_post_request(request, request.staff_role, request.staff_college, request.staff_departments)
    else:
        return error_response("Method not allowed", 405)


def handle_get_request(staff_id, staff_role, staff_college, staff_departments, force_refresh=False):
    """Handle GET request to retrieve students based on staff permissions."""
    try:
        # Use caching helper
        try:
            cached_data = get_cached_students(
                staff_id, 
                staff_role, 
                staff_college, 
                staff_departments,
                force_refresh
            )
            return JsonResponse(cached_data, safe=False)
        except OperationFailure as e:
            logger.error(f"Query execution failed: {str(e)}")
            return error_response(
                "Database query failed", 
                500, 
                error_data={"operation": "get_students", "error": str(e)} if not IS_PRODUCTION else None
            )
        except ServerSelectionTimeoutError:
            logger.error("Database connection timeout while retrieving students")
            return error_response("Service temporarily unavailable", 503)
            
    except Exception as e:
        error_id = generate_secure_error_id()
        logger.error(f"Error ID {error_id}: Error fetching students: {str(e)}", exc_info=True)
        return error_response(
            "Error retrieving student data", 
            500, 
            error_data={"error_id": error_id} if not IS_PRODUCTION else None
        )


def handle_post_request(request, staff_role, staff_college, staff_departments):
    """Handle POST request to update student details with enhanced security."""
    try:
        # Validate request body
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return error_response("Invalid request format", 400)
        
        # Validate data structure
        if not isinstance(data, dict):
            return error_response("Invalid data structure", 400)
            
        # Enhanced validation with data type checking
        is_valid, validation_errors = validate_data_types(data, STUDENT_SCHEMA)

        
        
        if not is_valid:
            return error_response("Data validation failed", 400, 
                                error_data={"validation_errors": validation_errors})
                                
        # For Admin, use the provided data directly
        if staff_role != 'Admin':
            # For non-admins, enforce their department and college for security
            
            # If staff_departments is a list, take the first element
            if isinstance(staff_departments, list):
                department = staff_departments[0] if staff_departments else ''
            else:
                department = staff_departments
            
            # Update data with staff's department and college
            # This prevents privilege escalation by overriding these fields
            data['dept'] = department
            data['collegename'] = staff_college
            
        # Determine which field to use for query
        regno_field = "regno"
        if "registration_number" in data and "regno" not in data:
            regno_field = "registration_number"

        
            
        # Ensure the registration field is not empty
        if not data.get(regno_field):
            return error_response("Student registration number is required", 400)
            
        filter_query = {regno_field: data[regno_field]}
        
        # Prevent tampering with system fields
        if '_id' in data:
            del data['_id']  # Prevent overwriting MongoDB IDs

        if 'collegename' in data and data['collegename']:
            data['collegename_lower'] = data['collegename'].lower()
            
        if 'dept' in data and data['dept']:
            data['dept_lower'] = data['dept'].lower()
            
        # Rest of your existing code for POST handling
        
        # When saving, ensure indexes exists for these fields
        if not hasattr(handle_post_request, 'indexes_ensured'):
            ensure_database_indexes()
            handle_post_request.indexes_ensured = True
            
        # Add audit fields
        data['last_updated'] = datetime.now().isoformat()
        data['updated_by'] = request.staff_id
        
        
        try:
            # Execute update with error handling
            result = students_collection.update_one(filter_query, {"$set": data}, upsert=True)
            
            # Clear relevant caches to ensure data freshness
            staff_id = request.staff_id
            cache_key = f"students:{staff_id}:{staff_role}:{staff_college}:{staff_departments}"
            cache.delete(cache_key)
            logger.info(f"Cache cleared for {staff_id} after database update")
            
            if result.matched_count > 0:
                message = "Student details updated successfully"
                logger.info(f"Student updated: {data[regno_field]} by staff {request.staff_id}")
            else:
                message = "New student record created successfully"
                logger.info(f"New student created: {data[regno_field]} by staff {request.staff_id}")
                
            return JsonResponse({"message": message, "success": True}, status=201)
        except OperationFailure as e:
            error_id = generate_secure_error_id()
            logger.error(f"Error ID {error_id}: Database update failed: {str(e)}")
            return error_response("Database operation failed", 500, 
                                error_data={"operation": "student_update", "error_id": error_id} if not IS_PRODUCTION else None)
        
            
    except Exception as e:
            error_id = generate_secure_error_id()
            logger.error(f"Error ID {error_id}: Error in POST request: {str(e)}", exc_info=True)
            return error_response("Request processing failed", 500, 
                                error_data={"error_id": error_id} if not IS_PRODUCTION else None)
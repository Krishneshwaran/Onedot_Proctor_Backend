from django.http import JsonResponse
from django.core.cache import cache
from pymongo import MongoClient
import os
from celery import shared_task
from celery.result import AsyncResult  # Add this import for AsyncResult
from rest_framework.decorators import api_view  # Add this import for api_view
import logging
from functools import wraps
import time
# Configure logger
logger = logging.getLogger(__name__)

def db_connection():
    """
    Establish MongoDB connection using environment variables for credentials.
    
    Returns:
        tuple: MongoDB client and database objects
    """
    try:
        mongo_uri = os.environ.get('MONGODB_URI')
        db_name = os.environ.get('MONGODB_DB_NAME', 'test_portal_db')
        timeout_ms = int(os.environ.get('MONGODB_TIMEOUT_MS', 5000))
        
        client = MongoClient(mongo_uri, serverSelectionTimeoutMS=timeout_ms)
        db = client[db_name]
        # Test connection
        client.server_info()
        return client, db
    except Exception as e:
        logger.error(f"Database connection error: {str(e)}")
        raise

def measure_execution_time(func):
    """
    Decorator to measure and log the execution time of functions.
    
    Args:
        func: The function to be measured
    
    Returns:
        wrapper: Decorated function
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        execution_time = time.time() - start_time
        logger.info(f"Function {func.__name__} took {execution_time:.2f} seconds to execute")
        return result
    return wrapper

# Modify the studentstats function around line 75 to handle the processing synchronously

# Modify the studentstats function to include time spent statistics

@measure_execution_time
def studentstats(request, regno):
    """
    Retrieve assessment statistics for a specific student, including time spent.
    
    Args:
        request (HttpRequest): Django request object
        regno (str): Student registration number
        
    Returns:
        JsonResponse: Student details, assessment data, and time spent statistics
    """
    try:
        # Add a composite cache key that contains all data we need
        composite_cache_key = f"student_full_stats_{regno}"
        cached_response = cache.get(composite_cache_key)
        
        # Return cached complete response if available
        if cached_response:
            return JsonResponse(cached_response)
            
        # Get cached student data or fetch from database
        student_data = get_cached_student_data(regno)
        if not student_data:
            return JsonResponse({"error": "Student not found"}, status=404)

        student_id = str(student_data["_id"])
        
        # Create basic response with student info
        basic_response = {
            "student": {
                "student_id": student_id,
                "name": student_data.get("name", ""),
                "email": student_data.get("email", ""),
                "collegename": student_data.get("collegename", ""),
                "regno": regno,
                "dept": student_data.get("dept", ""),
                "year": student_data.get("year", ""),
                "section": student_data.get("section", ""),
                "phone": student_data.get("phone", ""),
                "profileImage": student_data.get("profileImage", ""),
            },
            "status": "processing",
            "assessments": [],
            "time_stats": {}  # Add this field for time statistics
        }
        
        # Process contests synchronously
        try:
            client, db = db_connection()
            
            # Get contest data
            result = process_student_contests(regno, student_id)
            basic_response.update(result)
            
            # Calculate time spent statistics
            time_stats = calculate_time_spent(db, student_id)
            basic_response["time_stats"] = time_stats
            
            basic_response["status"] = "completed"
            
            # Cache the result
            cache_timeout = int(os.environ.get('CACHE_TIMEOUT', 600))
            cache.set(composite_cache_key, basic_response, cache_timeout)
            
            return JsonResponse(basic_response)
        except Exception as e:
            logger.error(f"Error processing student data: {str(e)}")
            basic_response["status"] = "error"
            basic_response["error"] = str(e)
            return JsonResponse(basic_response)
        
    except Exception as e:
        logger.error(f"Error retrieving student stats: {str(e)}")
        return JsonResponse({"error": "Failed to retrieve student statistics"}, status=500)  

def calculate_time_spent(db, student_id):
    """
    Calculate time spent by a student on all tests.
    
    Args:
        db: MongoDB database connection
        student_id (str): Student ID
        
    Returns:
        dict: Time spent statistics
    """
    # Get all MCQ reports where this student has submitted assessments
    mcq_reports = list(db.MCQ_Assessment_report.find(
        {"students.student_id": student_id},
        {"contest_id": 1, "students.$": 1}
    ))
    
    # Calculate time spent
    total_seconds = 0
    completed_tests = 0
    test_details = []
    
    for report in mcq_reports:
        # Each report contains only the matching student due to the projection
        if report.get("students") and len(report["students"]) > 0:
            student = report["students"][0]  # Should be only one student due to $ projection
            
            # Check if this student has both start and finish times
            if student.get("startTime") and student.get("finishTime"):
                try:
                    # Calculate time spent on test - either use duration_in_seconds if available
                    # or calculate from timestamps
                    if student.get("duration_in_seconds"):
                        test_duration = student["duration_in_seconds"]
                    else:
                        # Parse ISO format times
                        import dateutil.parser
                        start_time = dateutil.parser.parse(student["startTime"])
                        finish_time = dateutil.parser.parse(student["finishTime"])
                        test_duration = int((finish_time - start_time).total_seconds())
                    
                    # Add to total
                    if test_duration > 0:  # Avoid negative durations
                        total_seconds += test_duration
                        completed_tests += 1
                        
                        # Get test name (if needed)
                        test_name = "Unknown Test"
                        test_info = db.MCQ_Assessment_Data.find_one(
                            {"contestId": report["contest_id"]},
                            {"assessmentOverview.name": 1}
                        )
                        if test_info and test_info.get("assessmentOverview", {}).get("name"):
                            test_name = test_info["assessmentOverview"]["name"]
                            
                        test_details.append({
                            "contest_id": report["contest_id"],
                            "test_name": test_name,
                            "duration_seconds": test_duration,
                            "formatted_duration": format_duration(test_duration)
                        })
                except Exception as e:
                    logger.error(f"Error calculating duration for test {report.get('contest_id')}: {str(e)}")
    
    # Calculate hours, minutes, seconds
    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    
    return {
        "total_seconds": total_seconds,
        "formatted_time": f"{int(hours)}h {int(minutes)}m {int(seconds)}s",
        "completed_tests": completed_tests,
        "test_details": test_details
    }
# Update the get_cached_student_data function to include profileImage

def get_cached_student_data(regno):
    """
    Get student data from cache or database.
    
    This function checks the cache first for student data and falls back
    to the database if not found, then stores the result in cache.
    
    Args:
        regno (str): Student registration number
        
    Returns:
        dict: Student data or None if not found
    """
    cache_key = f"student_data_{regno}"
    student_data = cache.get(cache_key)
    
    if student_data is None:
        client, db = db_connection()
        try:
            # Include profileImage field in the query
            student_data = db.students.find_one({"regno": regno})
            if student_data:
                # Convert ObjectId to string for JSON serialization
                student_data['_id'] = str(student_data['_id'])
                # Cache for the configured timeout period
                cache_timeout = int(os.environ.get('CACHE_TIMEOUT', 600))
                cache.set(cache_key, student_data, cache_timeout)
        finally:
            client.close()
            
    return student_data

def generate_assessment_details(student_id, contest_list):
    """
    Generate detailed assessment information for a student.
    
    Args:
        student_id (str): Student ID
        contest_list (list): List of contest data
        
    Returns:
        list: Assessment details for the student
    """
    assessments = []
    
    for contest in contest_list:
        contest_id = contest.get("contestId")
        if not contest_id:
            continue
            
        assessment_overview = contest.get("assessmentOverview", {})
        contest_status = "Yet to Start"  # Default status

        # Add assessment details
        assessments.append({
            "contestId": contest_id,
            "name": assessment_overview.get("name", ""),
            "description": assessment_overview.get("description", ""),
            "registrationStart": assessment_overview.get("registrationStart", ""),
            "registrationEnd": assessment_overview.get("registrationEnd", ""),
            "guidelines": assessment_overview.get("guidelines", ""),
            "questions": contest.get("testConfiguration", {}).get("questions", ""),
            "duration": contest.get("testConfiguration", {}).get("duration", ""),
            "passPercentage": contest.get("testConfiguration", {}).get("passPercentage", ""),
            "contestStatus": contest_status
        })
    
    return assessments

@shared_task
def process_student_contests(regno, student_id):
    """
    Asynchronous task to process contests for a student.
    
    Args:
        regno (str): Student registration number
        student_id (str): Student ID
        
    Returns:
        dict: Processed contest data
    """
    try:
        client, db = db_connection()
        
        # Use projection to fetch only needed fields
        contest_data = db.coding_assessments.find(
            {"visible_to": regno}, 
            {
                "_id": 0, 
                "contestId": 1, 
                "assessmentOverview.name": 1,
                "assessmentOverview.description": 1, 
                "assessmentOverview.registrationStart": 1,
                "assessmentOverview.registrationEnd": 1,
                "assessmentOverview.guidelines": 1,
                "testConfiguration.questions": 1,
                "testConfiguration.duration": 1,
                "testConfiguration.passPercentage": 1
            }
        )
        
        # Optimize by using list comprehension instead of list()
        contest_list = [contest for contest in contest_data]
        
        # Generate assessment details
        assessments = generate_assessment_details(student_id, contest_list)
        
        # Get student data again (it's cached, so this is fast)
        student_data = get_cached_student_data(regno)
        
        # Construct complete response
# Update the response_data in process_student_contests function (around line 206)

# Construct complete response
        response_data = {
            "student": {
                "student_id": student_id,
                "name": student_data.get("name", ""),
                "email": student_data.get("email", ""),
                "collegename": student_data.get("collegename", ""),
                "regno": regno,
                "dept": student_data.get("dept", ""),
                "year": student_data.get("year", ""),
                "section": student_data.get("section", ""),
                "phone": student_data.get("phone", ""),
                "profileImage": student_data.get("profileImage", ""),  # Add profile image
            },
            "assessments": assessments,
            "status": "completed"
        }
        
        # Cache the complete response for future requests
        composite_cache_key = f"student_full_stats_{regno}"
        cache_timeout = int(os.environ.get('CACHE_TIMEOUT', 600))
        cache.set(composite_cache_key, response_data, cache_timeout)
        
        return {"status": "completed", "assessments": assessments}
    except Exception as e:
        logger.error(f"Error in async processing of contests: {str(e)}")
        return {"status": "error", "message": str(e)}
    finally:
        if 'client' in locals():
            client.close()


@api_view(['GET'])
def check_task_status(request, task_id):
    """
    Check the status of an asynchronous processing task.
    
    Args:
        request (HttpRequest): Django request object
        task_id (str): ID of the task to check
        
    Returns:
        JsonResponse: Task status and data if complete
    """
    try:
        # Try to get cached result first (much faster than checking Celery)
        regno = request.GET.get('regno')
        if regno:
            composite_cache_key = f"student_full_stats_{regno}"
            cached_response = cache.get(composite_cache_key)
            if cached_response:
                return JsonResponse(cached_response)
        
        # Check Celery task status
        task_result = AsyncResult(task_id)
        
        if task_result.ready():
            result = task_result.get()
            if result.get('status') == 'completed':
                return JsonResponse(result)
            else:
                return JsonResponse({
                    "status": "error",
                    "message": result.get('message', 'An error occurred during processing')
                }, status=500)
        else:
            return JsonResponse({
                "status": "processing",
                "message": "Task is still running"
            })
    except Exception as e:
        return JsonResponse({
            "status": "error",
            "message": str(e)
        }, status=500)

def process_test_statuses(student_id, contest_ids, coding_report_map):
    """
    Process test statuses and calculate statistics for a student.
    
    Args:
        student_id (str): Student ID
        contest_ids (list): List of contest IDs
        coding_report_map (dict): Map of contest reports
        
    Returns:
        tuple: Completed tests count, in-progress tests count, and total score
    """
    completed_tests = 0
    in_progress_tests = 0
    total_score = 0
    
    for contest_id in contest_ids:
        report = coding_report_map.get(contest_id)
        
        if not report:
            in_progress_tests += 1
        else:
            student_found = False
            for student in report.get("students", []):
                if str(student.get("student_id")) == student_id:
                    student_found = True
                    student_status = student.get("status")
                    
                    if student_status == "Completed":
                        completed_tests += 1
                        # Could add score calculation here
                    else:
                        in_progress_tests += 1
                    break
            
            if not student_found:
                in_progress_tests += 1
                
    return completed_tests, in_progress_tests, total_score
def generate_assessment_details(student_id, contest_list):
    """
    Generate detailed assessment information for a student.
    
    Args:
        student_id (str): Student ID
        contest_list (list): List of contest data
        
    Returns:
        list: Assessment details for the student
    """
    assessments = []
    
    for contest in contest_list:
        contest_id = contest.get("contestId")
        if not contest_id:
            continue
            
        assessment_overview = contest.get("assessmentOverview", {})
        contest_status = "Yet to Start"  # Default status

        # Add assessment details
        assessments.append({
            "contestId": contest_id,
            "name": assessment_overview.get("name", ""),
            "description": assessment_overview.get("description", ""),
            "registrationStart": assessment_overview.get("registrationStart", ""),
            "registrationEnd": assessment_overview.get("registrationEnd", ""),
            "guidelines": assessment_overview.get("guidelines", ""),
            "questions": contest.get("testConfiguration", {}).get("questions", ""),
            "duration": contest.get("testConfiguration", {}).get("duration", ""),
            "passPercentage": contest.get("testConfiguration", {}).get("passPercentage", ""),
            "contestStatus": contest_status
        })
    
    return assessments
# Add this at the top of your file, after the imports

def format_duration(seconds):
    """
    Format seconds into a human-readable string.
    
    Args:
        seconds (int): Duration in seconds
        
    Returns:
        str: Formatted duration string
    """
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    
    if hours > 0:
        return f"{int(hours)}h {int(minutes)}m {int(seconds)}s"
    elif minutes > 0:
        return f"{int(minutes)}m {int(seconds)}s"
    else:
        return f"{int(seconds)}s"
    
    # Update the date parsing in your calculate_time_spent function

def calculate_time_spent(db, student_id):
    """
    Calculate time spent by a student on all tests.
    
    Args:
        db: MongoDB database connection
        student_id (str): Student ID
        
    Returns:
        dict: Time spent statistics
    """
    # Get all MCQ reports where this student has submitted assessments
    mcq_reports = list(db.MCQ_Assessment_report.find(
        {"students.student_id": student_id},
        {"contest_id": 1, "students.$": 1}
    ))
    
    # Calculate time spent
    total_seconds = 0
    completed_tests = 0
    test_details = []
    
    for report in mcq_reports:
        # Each report contains only the matching student due to the projection
        if report.get("students") and len(report["students"]) > 0:
            student = report["students"][0]  # Should be only one student due to $ projection
            
            # Check if this student has both start and finish times
            if student.get("startTime") and student.get("finishTime"):
                try:
                    # Calculate time spent on test - either use duration_in_seconds if available
                    # or calculate from timestamps
                    if student.get("durationInSeconds") and isinstance(student["durationInSeconds"], (int, float)):
                        test_duration = int(student["durationInSeconds"])
                    elif student.get("duration_in_seconds") and isinstance(student["duration_in_seconds"], (int, float)):
                        test_duration = int(student["duration_in_seconds"])
                    else:
                        # Parse ISO format times - handle different possible types
                        import dateutil.parser
                        import datetime
                        
                        start_time_str = student["startTime"] if isinstance(student["startTime"], str) else str(student["startTime"])
                        finish_time_str = student["finishTime"] if isinstance(student["finishTime"], str) else str(student["finishTime"])
                        
                        # Try to convert both to datetime objects if they aren't already
                        if isinstance(student["startTime"], datetime.datetime):
                            start_time = student["startTime"]
                        else:
                            start_time = dateutil.parser.parse(start_time_str)
                            
                        if isinstance(student["finishTime"], datetime.datetime):
                            finish_time = student["finishTime"]
                        else:
                            finish_time = dateutil.parser.parse(finish_time_str)
                        
                        # Make both timezone aware or naive to avoid comparison issues
                        if start_time.tzinfo is None and finish_time.tzinfo is not None:
                            # Use UTC for consistency
                            import pytz
                            start_time = start_time.replace(tzinfo=pytz.UTC)
                        elif finish_time.tzinfo is None and start_time.tzinfo is not None:
                            import pytz
                            finish_time = finish_time.replace(tzinfo=pytz.UTC)
                        
                        test_duration = int((finish_time - start_time).total_seconds())
                    
                    # Add to total if duration is positive and sensible (less than 24 hours)
                    if test_duration > 0 and test_duration < 86400:  # 86400 seconds = 24 hours
                        total_seconds += test_duration
                        completed_tests += 1
                        
                        # Get test name (if needed)
                        test_name = "Unknown Test"
                        test_info = db.MCQ_Assessment_Data.find_one(
                            {"contestId": report["contest_id"]},
                            {"assessmentOverview.name": 1}
                        )
                        if test_info and test_info.get("assessmentOverview", {}).get("name"):
                            test_name = test_info["assessmentOverview"]["name"]
                            
                        test_details.append({
                            "contest_id": report["contest_id"],
                            "test_name": test_name,
                            "duration_seconds": test_duration,
                            "formatted_duration": format_duration(test_duration)
                        })
                except Exception as e:
                    logger.error(f"Error calculating duration for test {report.get('contest_id')}: {str(e)}")
    
    # Calculate hours, minutes, seconds
    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    
    return {
        "total_seconds": total_seconds,
        "formatted_time": f"{int(hours)}h {int(minutes)}m {int(seconds)}s",
        "completed_tests": completed_tests,
        "test_details": test_details
    }
# Update the mcq_student_results function to include time tracking

@measure_execution_time
def mcq_student_results(request, regno):
    """
    Retrieve MCQ assessment statistics and results for a specific student.
    
    This function fetches student data, visible MCQ assessments, and assessment reports
    to generate a comprehensive view of the student's performance on MCQ assessments.
    
    Args:
        request (HttpRequest): Django request object
        regno (str): Student registration number
        
    Returns:
        JsonResponse: Student details, performance metrics, and assessment data
    """
    try:
        # Establish database connection
        client, db = db_connection()
        
        # Fetch student data
        student_data = db.students.find_one({"regno": regno})
        if not student_data:
            return JsonResponse({"error": "Student not found"}, status=404)

        student_id = str(student_data["_id"])

        # For large data volumes, consider processing in background task
        mcq_list = list(db.MCQ_Assessment_Data.find({"visible_to": regno}, {"_id": 0}))
        
        # Get visible contest IDs
        visible_contest_ids = {mcq.get("contestId") for mcq in mcq_list if mcq.get("contestId")}
        
        # Fetch reports for visible contests
        mcq_reports = db.MCQ_Assessment_report.find({"contest_id": {"$in": list(visible_contest_ids)}})
        mcq_report_map = {
            report["contest_id"]: report 
            for report in mcq_reports 
            if report["contest_id"] in visible_contest_ids
        }

        # Process MCQ test statistics
        completed_tests, in_progress_tests, average_score = process_mcq_statistics(
            student_id, visible_contest_ids, mcq_report_map
        )
        
        # Generate MCQ assessment details
        assessments = generate_mcq_assessment_details(
            student_id, mcq_list, mcq_report_map
        )
        
        # Default generate certificate value
        generate_certificate = False
        if mcq_list:
            last_mcq = mcq_list[-1]
            generate_certificate = last_mcq.get("testConfiguration", {}).get("generateCertificate", False)
            
        # Calculate time spent statistics - using the existing function
        time_stats = calculate_time_spent(db, student_id)

        # Construct response
        response_data = {
            "student": {
                "student_id": student_id,
                "name": student_data.get("name", ""),
                "email": student_data.get("email", ""),
                "collegename": student_data.get("collegename", ""),
                "year": student_data.get("year", ""),
                "dept": student_data.get("dept", ""),
                "regno": regno,
                "section": student_data.get("section", ""),
                "generateCertificate": generate_certificate,
                "profileImage": student_data.get("profileImage", ""), # Include profile image
            },
            "performance": {
                "total_tests": len(visible_contest_ids),
                "completed_tests": completed_tests,
                "in_progress_tests": in_progress_tests,
                "average_score": round(average_score, 2),
            },
            "time_stats": time_stats,  # Add time statistics here
            "assessments": assessments
        }
        
        return JsonResponse(response_data)
    
    except Exception as e:
        logger.error(f"Error retrieving MCQ results: {str(e)}")
        return JsonResponse({"error": f"Failed to retrieve MCQ results: {str(e)}"}, status=500)
    finally:
        if 'client' in locals():
            client.close()

def process_mcq_statistics(student_id, visible_contest_ids, mcq_report_map):
    """
    Process MCQ assessment statistics for a student.
    
    Args:
        student_id (str): Student ID
        visible_contest_ids (set): Set of visible contest IDs
        mcq_report_map (dict): Map of MCQ reports
        
    Returns:
        tuple: Completed tests count, in-progress tests count, and average score
    """
    completed_tests = 0
    in_progress_tests = 0
    total_percentage = 0
    scored_tests = 0
    
    for contest_id in visible_contest_ids:
        report = mcq_report_map.get(contest_id)
        if not report or "students" not in report:
            in_progress_tests += 1
            continue
            
        student_found = False
        for student in report["students"]:
            if str(student.get("student_id")) == student_id:
                student_found = True
                student_status = student.get("status")
                
                if student_status == "Completed":
                    completed_tests += 1
                    percentage = student.get("percentage", 0)
                    total_percentage += percentage
                    scored_tests += 1
                break
                
        if not student_found:
            in_progress_tests += 1
            
    average_score = (total_percentage / scored_tests) if scored_tests > 0 else 0
    return completed_tests, in_progress_tests, average_score

def generate_mcq_assessment_details(student_id, mcq_list, mcq_report_map):
    """
    Generate detailed MCQ assessment information for a student.
    
    Args:
        student_id (str): Student ID
        mcq_list (list): List of MCQ assessment data
        mcq_report_map (dict): Map of MCQ reports
        
    Returns:
        list: MCQ assessment details for the student
    """
    assessments = []
    
    for mcq in mcq_list:
        contest_id = mcq.get("contestId")
        if not contest_id:
            continue
            
        assessment_overview = mcq.get("assessmentOverview", {})
        if not (assessment_overview.get("name") and 
                assessment_overview.get("description") and
                assessment_overview.get("registrationStart") and
                assessment_overview.get("registrationEnd")):
            continue
            
        problems = []
        contest_status = "Yet to Start"
        percentage = 0
        
        # Check contest status
        report = mcq_report_map.get(contest_id)
        if report and "students" in report:
            for student in report["students"]:
                if str(student.get("student_id")) == student_id:
                    contest_status = student.get("status", "Pending")
                    percentage = student.get("percentage", 0)
                    break
                    
        # Process problems based on status
        if contest_status == "Completed" and report and "students" in report:
            for student in report["students"]:
                if str(student.get("student_id")) == student_id:
                    for problem in student.get("attended_question", []):
                        problems.append({
                            "title": problem.get("title", ""),
                            "student_answer": problem.get("student_answer", ""),
                            "correct_answer": problem.get("correct_answer", "")
                        })
                    break
        elif contest_status == "Pending":
            problems = "Pending"
        else:
            problems = "No problems yet"
            
        # Add assessment details
        assessments.append({
            "contestId": contest_id,
            "name": assessment_overview.get("name", ""),
            "description": assessment_overview.get("description", ""),
            "registrationStart": assessment_overview.get("registrationStart", ""),
            "registrationEnd": assessment_overview.get("registrationEnd", ""),
            "guidelines": assessment_overview.get("guidelines", ""),
            "questions": mcq.get("testConfiguration", {}).get("questions", ""),
            "duration": mcq.get("testConfiguration", {}).get("duration", ""),
            "passPercentage": mcq.get("testConfiguration", {}).get("passPercentage", ""),
            "problems": problems,
            "contestStatus": contest_status,
            "percentage": percentage,
            "generateCertificate": mcq.get("testConfiguration", {}).get("generateCertificate", ""),
        })
        
    return assessments

# Example of a task that could be used for processing large datasets asynchronously
@shared_task
def process_large_dataset_task(regno, contest_ids):
    """
    Asynchronous task to process large datasets of student assessment data.
    
    Args:
        regno (str): Student registration number
        contest_ids (list): List of contest IDs to process
        
    Returns:
        dict: Processed assessment data
    """
    try:
        client, db = db_connection()
        # Process data here
        return {"status": "success"}
    except Exception as e:
        logger.error(f"Error in async processing: {str(e)}")
        return {"status": "error", "message": str(e)}
    finally:
        if 'client' in locals():
            client.close()
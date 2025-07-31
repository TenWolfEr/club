from flask import Flask, request, jsonify
from json import JSONEncoder # 已修正匯入
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity, JWTManager, get_jwt
import psycopg2
from psycopg2 import extras
from psycopg2.extras import DictRow
from datetime import date, datetime
import os
from datetime import date


# --- Configuration ---
DB_URL = "postgresql://postgres:123@localhost:5432/course" # Replace with your actual DB connection string
JWT_KEY = "super-simple-key-for-personal-use" # !!! CHANGE THIS TO SOMETHING COMPLEX !!!

def create_default_users():
    """
    Checks if default users (admin, teacher, student) exist and creates them if not.
    WARNING: Uses plain text passwords! Update this with secure password hashing.
    """
    default_users_data = [
        {'username': 'admin_user', 'password': 'adminpassword', 'role': 'admin', 'email': 'admin@example.com', 'phone_number': None, 'address': None, 'department_id': None},
        {'username': 'teacher_user', 'password': 'teacherpassword', 'role': 'teacher', 'email': 'teacher@example.com', 'phone_number': None, 'address': None, 'department_id': None},
        {'username': 'student_user', 'password': 'studentpassword', 'role': 'student', 'email': 'student@example.com', 'phone_number': None, 'address': None, 'department_id': None},
    ]

    with DatabaseConnection() as (conn, cursor):
        print("Checking for default users...")
        for user_data in default_users_data:
            username = user_data['username']
            role = user_data['role']

            try:
                # Check if user exists
                cursor.execute("SELECT user_id FROM users WHERE username = %s;", (username,))
                existing_user = cursor.fetchone()

                if existing_user is None:
                    # User does not exist, insert
                    print(f"User '{username}' ({role}) not found. Creating...")
                    cursor.execute(
                        """
                        INSERT INTO users (username, password, role, email, phone_number, address, register_date, department_id)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
                        """,
                        (
                            user_data['username'],
                            user_data['password'], # WARNING: Plain text password! HASH THIS!
                            user_data['role'],
                            user_data['email'],
                            user_data['phone_number'],
                            user_data['address'],
                            date.today(), # Use current date as register date
                            user_data['department_id']
                        )
                    )
                    print(f"Successfully created user: {username}")
                else:
                    print(f"User '{username}' ({role}) already exists.")

            except psycopg2.Error as e:
                print(f"Database error while processing user '{username}': {e}")
                # Depending on severity, you might want to rollback or exit.
                # The context manager handles transaction rollback on exception.
            except Exception as e:
                print(f"An unexpected error occurred while processing user '{username}': {e}")
                # Handle other potential errors

        # The context manager will automatically commit changes here if no exceptions occurred within the 'with' block.
        print("Default user check/creation complete.")

# --- Database Connection ---
def get_db_connection():
    """Establishes and returns a new database connection."""
    try:
        conn = psycopg2.connect(DB_URL)
        return conn
    except psycopg2.Error as e:
        print(f"Database connection error: {e}")
        raise

class DatabaseConnection:
    def __enter__(self):
        self.conn = get_db_connection()
        self.cursor = self.conn.cursor(cursor_factory=extras.DictCursor)
        return self.conn, self.cursor

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.cursor:
            self.cursor.close()
        if self.conn:
            if exc_type is None:
                self.conn.commit()
            else:
                self.conn.rollback()
            self.conn.close()

# --- Custom JSON Encoder ---
class CustomJSONEncoder(JSONEncoder):
    def default(self, obj):
        if isinstance(obj, (date, datetime)):
            return obj.isoformat()
        if isinstance(obj, DictRow):
             return dict(obj)
        return super().default(obj)

# --- Flask App Setup ---
app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = JWT_KEY
app.config["JWT_TOKEN_LOCATION"] = ["headers"]
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = 3600
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = 2592000

jwt = JWTManager(app)
app.json_encoder = CustomJSONEncoder

# --- Helper Functions for Responses ---
def success_response(data=None, message="Success", status_code=200):
    response_data = {"message": message}
    if data is not None:
        if isinstance(data, DictRow):
             data = dict(data)
        elif isinstance(data, list):
            data = [dict(item) if isinstance(item, DictRow) else item for item in data]
        response_data["data"] = data
    return jsonify(response_data), status_code

def error_response(message, status_code, code=None):
    response_data = {"message": message}
    if code:
        response_data["code"] = code
    return jsonify(response_data), status_code

# --- Helper function to get user data from JWT ---
def get_current_user():
    """Helper function to get current user data from JWT token"""
    user_id = get_jwt_identity()
    claims = get_jwt()
    return {
        'user_id': int(user_id),
        'role': claims.get('role'),
        'username': claims.get('username')
    }

# --- Decorators ---
def student_required():
    def wrapper(fn):
        @jwt_required()
        def decorator(*args, **kwargs):
            user_data = get_current_user()
            if user_data.get('role') != 'student':
                return error_response("Students only", 403, "FORBIDDEN")
            return fn(*args, **kwargs)
        return decorator
    return wrapper

# --- JWT Error Handlers ---
@jwt.unauthorized_loader
def custom_unauthorized_callback(callback):
    return error_response("Missing or invalid token", 401, "UNAUTHORIZED")

@jwt.expired_token_loader
def custom_expired_token_callback(jwt_header, jwt_payload):
    return error_response("Token has expired", 401, "TOKEN_EXPIRED")

@jwt.invalid_token_loader
def custom_invalid_token_callback(callback):
    print(f"JWT INVALID TOKEN: {callback}")
    return error_response("Invalid token", 401, "INVALID_TOKEN")

@jwt.needs_fresh_token_loader
def custom_needs_fresh_token_callback(jwt_header, jwt_payload):
    return error_response("Fresh token required", 401, "FRESH_TOKEN_REQUIRED")

# --- Routes ---

# --- Authentication ---
@app.route('/api/auth/login', methods=['POST'], endpoint='auth_login')
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return error_response("Missing username or password", 400, "MISSING_CREDENTIALS")

    with DatabaseConnection() as (conn, cursor):
        try:
            cursor.execute("SELECT user_id, username, role, email, department_id, password FROM users WHERE username = %s;", (username,))
            user = cursor.fetchone()

            if user is None or user['password'] != password:
                 return error_response("Invalid username or password", 401, "INVALID_CREDENTIALS")

            # Fix: Use string as identity and pass additional data as claims
            access_token = create_access_token(
                identity=str(user['user_id']),
                additional_claims={
                    'role': user['role'], 
                    'username': user['username']
                }
            )
            refresh_token = create_refresh_token(identity=str(user['user_id']))

            user_data = dict(user)
            user_data.pop('password', None)

            return success_response({
                "token": access_token,
                "refresh_token": refresh_token,
                "user": user_data
            })

        except Exception as e:
            print(f"Login error: {e}")
            return error_response("Internal server error during login", 500)

@app.route('/api/auth/logout', methods=['POST'], endpoint='auth_logout')
@jwt_required()
def logout():
    return success_response(message="Logged out successfully")

@app.route('/api/auth/refresh-token', methods=['POST'], endpoint='auth_refresh_token')
@jwt_required(refresh=True)
def refresh_token():
    user_id = get_jwt_identity()
    
    # Get user info from database to create new token with claims
    with DatabaseConnection() as (conn, cursor):
        try:
            cursor.execute("SELECT role, username FROM users WHERE user_id = %s;", (int(user_id),))
            user = cursor.fetchone()
            
            if user is None:
                return error_response("User not found", 404)
            
            new_access_token = create_access_token(
                identity=user_id,
                additional_claims={
                    'role': user['role'],
                    'username': user['username']
                }
            )
            return success_response({"token": new_access_token})
            
        except Exception as e:
            print(f"Refresh token error: {e}")
            return error_response("Internal server error during token refresh", 500)


# --- Student Profile Management ---
@app.route('/api/students/profile', methods=['GET'], endpoint='student_get_profile')
@student_required()
def get_profile():
    user_data = get_current_user()
    user_id = user_data['user_id']
    with DatabaseConnection() as (conn, cursor):
        try:
            cursor.execute("SELECT user_id, username, role, email, phone_number, address, register_date, department_id FROM users WHERE user_id = %s;", (user_id,))
            user = cursor.fetchone()
            if user is None: return error_response("User not found", 404)
            return success_response(user)
        except Exception as e:
            print(f"Get profile error: {e}")
            return error_response("Internal server error fetching profile", 500)

@app.route('/api/students/profile', methods=['PUT'], endpoint='student_update_profile')
@student_required()
def update_profile():
    user_data = get_current_user()
    user_id = user_data['user_id']
    data = request.get_json()
    if not data: return error_response("No update data provided", 400)
    allowed_fields = ['email', 'phone_number', 'address']
    update_data = {k: v for k, v in data.items() if k in allowed_fields}
    if not update_data: return error_response("No valid update fields provided", 400)
    set_clauses = [f"{key} = %s" for key in update_data]
    query = f"UPDATE users SET {', '.join(set_clauses)} WHERE user_id = %s;"
    values = list(update_data.values()) + [user_id]
    with DatabaseConnection() as (conn, cursor):
        try:
            cursor.execute(query, values)
            if cursor.rowcount == 0: return error_response("User not found for update", 404)
            cursor.execute("SELECT user_id, username, role, email, phone_number, address, register_date, department_id FROM users WHERE user_id = %s;", (user_id,))
            updated_user = cursor.fetchone()
            return success_response(updated_user, message="Profile updated successfully")
        except Exception as e:
            print(f"Update profile error: {e}")
            return error_response("Internal server error updating profile", 500)

@app.route('/api/students/password', methods=['PATCH'], endpoint='student_update_password')
@student_required()
def update_password():
    user_data = get_current_user()
    user_id = user_data['user_id']
    data = request.get_json()
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    if not old_password or not new_password:
        return error_response("Missing old_password or new_password", 400)
    with DatabaseConnection() as (conn, cursor):
        try:
            cursor.execute("SELECT password FROM users WHERE user_id = %s;", (user_id,))
            user = cursor.fetchone()
            if user is None or user['password'] != old_password:
                 return error_response("Invalid old password", 401, "INVALID_OLD_PASSWORD")
            cursor.execute("UPDATE users SET password = %s WHERE user_id = %s;", (new_password, user_id))
            return success_response(message="Password updated successfully")
        except Exception as e:
            print(f"Update password error: {e}")
            return error_response("Internal server error updating password", 500)

# --- Course Browsing & Search ---
@app.route('/api/courses', methods=['GET'], endpoint='course_list')
@jwt_required() # Courses can be browsed by authenticated users
def list_courses():
    page = request.args.get('page', 1, type=int)
    limit = request.args.get('limit', 20, type=int)
    department_id = request.args.get('department_id', type=int)
    semester = request.args.get('semester')
    status = request.args.get('status')
    query_str = request.args.get('q')

    if limit <= 0 or page <= 0: return error_response("Invalid page or limit parameter", 400)
    offset = (page - 1) * limit

    with DatabaseConnection() as (conn, cursor):
        try:
            sql_query = """
                SELECT
                    c.id AS course_id, c.course_name, d.name AS department_name,
                    t.username AS teacher_name, c.credits, c.week_time, c.location,
                    c.capacity, (SELECT COUNT(*) FROM select_courses sc WHERE sc.course_id = c.id) AS current_enrollment,
                    c.semester, c.start_date, c.end_date, c.status, c.course_type, c.description
                FROM course c
                JOIN department d ON c.department_id = d.id
                LEFT JOIN users t ON c.teacher_id = t.user_id
                WHERE 1=1
            """
            params = []

            if department_id is not None: sql_query += " AND c.department_id = %s"; params.append(department_id)
            if semester: sql_query += " AND c.semester ILIKE %s"; params.append(f"%{semester}%")
            if status: sql_query += " AND c.status ILIKE %s"; params.append(f"%{status}%")
            if query_str:
                 sql_query += " AND (c.course_name ILIKE %s OR c.description ILIKE %s)"
                 params.append(f"%{query_str}%")
                 params.append(f"%{query_str}%")

            sql_query += " ORDER BY c.semester DESC, c.start_date ASC, c.course_name ASC"
            sql_query += " LIMIT %s OFFSET %s;"
            params.append(limit)
            params.append(offset)

            cursor.execute(sql_query, params)
            courses = cursor.fetchall()

            # Get total count for pagination
            count_query = f"""
                SELECT COUNT(*) FROM course c
                JOIN department d ON c.department_id = d.id
                LEFT JOIN users t ON c.teacher_id = t.user_id
                WHERE 1=1
                {' AND c.department_id = %s' if department_id is not None else ''}
                {' AND c.semester ILIKE %s' if semester else ''}
                {' AND c.status ILIKE %s' if status else ''}
                {' AND (c.course_name ILIKE %s OR c.description ILIKE %s)' if query_str else ''}
            """
            count_params = []
            if department_id is not None: count_params.append(department_id)
            if semester: count_params.append(f"%{semester}%")
            if status: count_params.append(f"%{status}%")
            if query_str:
                 count_params.append(f"%{query_str}%")
                 count_params.append(f"%{query_str}%")

            cursor.execute(count_query, count_params)
            total_courses = cursor.fetchone()[0]

            return success_response({
                "courses": courses,
                "pagination": {
                    "total_items": total_courses,
                    "current_page": page,
                    "items_per_page": limit,
                    "total_pages": (total_courses + limit - 1) // limit if limit > 0 else 0
                }
            })

        except Exception as e:
            print(f"List courses error: {e}")
            return error_response("Internal server error fetching courses", 500)

@app.route('/api/courses/search', methods=['GET'], endpoint='course_search')
@jwt_required()
def search_courses():
     # Just call the list_courses function, it handles the 'q' parameter
     # Note: The endpoint names course_list and course_search must be unique
     return list_courses()

@app.route('/api/courses/<int:course_id>', methods=['GET'], endpoint='course_details')
@jwt_required()
def get_course_details(course_id):
    with DatabaseConnection() as (conn, cursor):
        try:
            query = """
                SELECT
                    c.id AS course_id, c.course_name, d.name AS department_name,
                    t.username AS teacher_name, t.email AS teacher_email, t.phone_number AS teacher_phone,
                    c.credits, c.week_time, c.location, c.capacity,
                    (SELECT COUNT(*) FROM select_courses sc WHERE sc.course_id = c.id) AS current_enrollment,
                    c.description, c.semester, c.start_date, c.end_date, c.status, c.course_type
                FROM course c
                JOIN department d ON c.department_id = d.id
                LEFT JOIN users t ON c.teacher_id = t.user_id
                WHERE c.id = %s;
            """
            cursor.execute(query, (course_id,))
            course_details = cursor.fetchone()
            if course_details is None: return error_response("Course not found", 404)
            return success_response(course_details)
        except Exception as e:
            print(f"Get course details error: {e}")
            return error_response("Internal server error fetching course details", 500)


# --- Department Browsing ---
@app.route('/api/departments', methods=['GET'], endpoint='department_list')
# @jwt_required() # Decide if listing departments requires authentication
def list_departments():
    with DatabaseConnection() as (conn, cursor):
        try:
            cursor.execute("SELECT id AS department_id, name AS department_name, office_location, phone_number FROM department;")
            departments = cursor.fetchall()
            return success_response({"departments": departments})
        except Exception as e:
            print(f"List departments error: {e}")
            return error_response("Internal server error fetching departments", 500)

@app.route('/api/departments/<int:dept_id>/courses', methods=['GET'], endpoint='department_courses')
@jwt_required()
def list_courses_by_department(dept_id):
    with DatabaseConnection() as (conn, cursor):
        try:
            cursor.execute("SELECT 1 FROM department WHERE id = %s;", (dept_id,))
            if cursor.fetchone() is None: return error_response("Department not found", 404)
            query = """
                SELECT
                    c.id AS course_id, c.course_name, d.name AS department_name,
                    t.username AS teacher_name, c.credits, c.week_time, c.location,
                    c.capacity, (SELECT COUNT(*) FROM select_courses sc WHERE sc.course_id = c.id) AS current_enrollment,
                    c.semester, c.start_date, c.end_date, c.status, c.course_type, c.description
                FROM course c
                JOIN department d ON c.department_id = d.id
                LEFT JOIN users t ON c.teacher_id = t.user_id
                WHERE c.department_id = %s
                ORDER BY c.semester DESC, c.start_date ASC, c.course_name ASC;
            """
            cursor.execute(query, (dept_id,))
            courses = cursor.fetchall()
            return success_response({"department_id": dept_id, "courses": courses})
        except Exception as e:
            print(f"List courses by department error: {e}")
            return error_response("Internal server error fetching courses by department", 500)

# --- Course Enrollment ---
@app.route('/api/students/courses/enroll', methods=['POST'], endpoint='student_enroll_course')
@student_required()
def enroll_course():
    user_data = get_current_user()
    user_id = user_data['user_id']
    data = request.get_json()
    course_id_raw = data.get('course_id')
    if course_id_raw is None: return error_response("Missing course_id", 400)
    try: course_id = int(course_id_raw)
    except (ValueError, TypeError): return error_response("Invalid course_id format", 400)
    with DatabaseConnection() as (conn, cursor):
        try:
            cursor.execute("""
                SELECT c.id, c.capacity, (SELECT COUNT(*) FROM select_courses sc WHERE sc.course_id = c.id) AS current_enrollment
                FROM course c WHERE c.id = %s;
            """, (course_id,))
            course_info = cursor.fetchone()
            if course_info is None: return error_response("Course not found", 404, "COURSE_NOT_FOUND")
            cursor.execute("SELECT 1 FROM select_courses WHERE user_id = %s AND course_id = %s;", (user_id, course_id))
            if cursor.fetchone(): return error_response("Already enrolled in this course", 409, "ALREADY_ENROLLED")
            if course_info['current_enrollment'] >= course_info['capacity']:
                return error_response("Course is full", 409, "COURSE_FULL")
            cursor.execute("""
                INSERT INTO select_courses (user_id, course_id, status)
                VALUES (%s, %s, %s)
                RETURNING user_id, course_id, select_time, status;
            """, (user_id, course_id, 'enrolled'))
            enrollment_details = cursor.fetchone()
            cursor.execute("SELECT course_name FROM course WHERE id = %s;", (course_id,))
            course_name = cursor.fetchone()['course_name']
            response_data = dict(enrollment_details)
            response_data['course_name'] = course_name
            return success_response({"enrollment": response_data}, message="Successfully enrolled in course", status_code=201)
        except Exception as e:
            print(f"Enrollment error: {e}")
            return error_response("Internal server error during enrollment", 500)

@app.route('/api/students/courses/<int:course_id>/drop', methods=['DELETE'], endpoint='student_drop_course')
@student_required()
def drop_course(course_id):
    user_data = get_current_user()
    user_id = user_data['user_id']
    with DatabaseConnection() as (conn, cursor):
        try:
            cursor.execute("SELECT 1 FROM select_courses WHERE user_id = %s AND course_id = %s;", (user_id, course_id))
            if cursor.fetchone() is None: return error_response("Not enrolled in this course", 404, "NOT_ENROLLED")
            cursor.execute("DELETE FROM select_courses WHERE user_id = %s AND course_id = %s;", (user_id, course_id))
            return success_response(message="Course dropped successfully")
        except Exception as e:
            print(f"Drop course error: {e}")
            return error_response("Internal server error during course drop", 500)

@app.route('/api/students/courses/enrolled', methods=['GET'], endpoint='student_enrolled_courses')
@student_required()
def get_enrolled_courses():
    user_data = get_current_user()
    user_id = user_data['user_id']
    semester_filter = request.args.get('semester')
    with DatabaseConnection() as (conn, cursor):
        try:
            query = """
                SELECT
                    sc.course_id, c.course_name, d.name AS department_name,
                    t.username AS teacher_name, c.credits, c.week_time, c.location,
                    sc.grade, sc.status, sc.select_time
                FROM select_courses sc
                JOIN course c ON sc.course_id = c.id
                JOIN department d ON c.department_id = d.id
                LEFT JOIN users t ON c.teacher_id = t.user_id
                WHERE sc.user_id = %s
            """
            params = [user_id]
            if semester_filter: query += " AND c.semester = %s"; params.append(semester_filter)
            query += " ORDER BY c.semester, c.start_date, c.course_name;"
            cursor.execute(query, params)
            enrolled_courses = cursor.fetchall()
            total_credits = sum(course['credits'] for course in enrolled_courses if course['status'] == 'enrolled')
            return success_response({
                "courses": enrolled_courses,
                "total_credits": total_credits
            })
        except Exception as e:
            print(f"Get enrolled courses error: {e}")
            return error_response("Internal server error fetching enrolled courses", 500)

@app.route('/api/students/courses/available', methods=['GET'], endpoint='student_available_courses')
@student_required()
def get_available_courses():
    user_data = get_current_user()
    user_id = user_data['user_id']
    with DatabaseConnection() as (conn, cursor):
        try:
            query = """
                SELECT
                    c.id AS course_id, c.course_name, d.name AS department_name,
                    t.username AS teacher_name, c.credits, c.week_time, c.location,
                    c.capacity, (SELECT COUNT(*) FROM select_courses sc WHERE sc.course_id = c.id) AS current_enrollment,
                    c.semester, c.status
                FROM course c
                JOIN department d ON c.department_id = d.id
                LEFT JOIN users t ON c.teacher_id = t.user_id
                WHERE c.status IN ('active', 'open')
                AND NOT EXISTS (
                    SELECT 1 FROM select_courses sc WHERE sc.user_id = %s AND sc.course_id = c.id
                )
                AND (SELECT COUNT(*) FROM select_courses sc WHERE sc.course_id = c.id) < c.capacity
                ORDER BY c.semester, c.start_date, c.course_name;
            """
            cursor.execute(query, (user_id,))
            available_courses = cursor.fetchall()
            return success_response({"courses": available_courses})
        except Exception as e:
            print(f"Get available courses error: {e}")
            return error_response("Internal server error fetching available courses", 500)

# --- Grades & Academic Records ---
@app.route('/api/students/grades', methods=['GET'], endpoint='student_grades')
@student_required()
def get_grades():
    user_data = get_current_user()
    user_id = user_data['user_id']
    semester_filter = request.args.get('semester')
    with DatabaseConnection() as (conn, cursor):
        try:
            query = """
                SELECT
                    sc.course_id, c.course_name, d.name AS department_name,
                    c.semester, c.credits, sc.grade, sc.status
                FROM select_courses sc
                JOIN course c ON sc.course_id = c.id
                JOIN department d ON c.department_id = d.id
                WHERE sc.user_id = %s AND sc.grade IS NOT NULL
            """
            params = [user_id]
            if semester_filter: query += " AND c.semester = %s"; params.append(semester_filter)
            query += " ORDER BY c.semester, c.start_date, c.course_name;"
            cursor.execute(query, params)
            graded_courses = cursor.fetchall()
            return success_response({"grades": graded_courses})
        except Exception as e:
            print(f"Get grades error: {e}")
            return error_response("Internal server error fetching grades", 500)

@app.route('/api/students/grades/<int:course_id>', methods=['GET'], endpoint='student_course_grade')
@student_required()
def get_grade_for_course(course_id):
    user_data = get_current_user()
    user_id = user_data['user_id']
    with DatabaseConnection() as (conn, cursor):
        try:
            query = """
                SELECT
                    sc.course_id, c.course_name, d.name AS department_name,
                    c.semester, c.credits, sc.grade, sc.status, sc.select_time
                FROM select_courses sc
                JOIN course c ON sc.course_id = c.id
                JOIN department d ON c.department_id = d.id
                WHERE sc.user_id = %s AND sc.course_id = %s;
            """
            cursor.execute(query, (user_id, course_id))
            grade_info = cursor.fetchone()
            if grade_info is None: return error_response("Course not found in your records", 404, "COURSE_RECORD_NOT_FOUND")
            return success_response(grade_info)
        except Exception as e:
            print(f"Get grade for course error: {e}")
            return error_response("Internal server error fetching grade for course", 500)

@app.route('/api/students/transcript', methods=['GET'], endpoint='student_transcript')
@student_required()
def get_transcript():
    user_data = get_current_user()
    user_id = user_data['user_id']
    with DatabaseConnection() as (conn, cursor):
        try:
            query = """
                SELECT
                    sc.course_id, c.course_name, d.name AS department_name,
                    c.semester, c.credits, sc.grade
                FROM select_courses sc
                JOIN course c ON sc.course_id = c.id
                JOIN department d ON c.department_id = d.id
                WHERE sc.user_id = %s AND sc.grade IS NOT NULL
                ORDER BY c.semester, c.start_date, c.course_name;
            """
            cursor.execute(query, (user_id,))
            graded_courses = cursor.fetchall()
            total_grade_points = 0
            total_credits_graded = 0
            for course in graded_courses:
                if course['grade'] is not None and course['credits'] is not None:
                    total_grade_points += course['grade'] * course['credits']
                    total_credits_graded += course['credits']
            gpa = (total_grade_points / total_credits_graded) if total_credits_graded > 0 else 0
            return success_response({
                "transcript": graded_courses,
                "gpa": round(gpa, 2)
            })
        except Exception as e:
            print(f"Get transcript error: {e}")
            return error_response("Internal server error fetching transcript", 500)

# --- Basic Root ---
@app.route('/', endpoint='index')
def index():
    return jsonify({"message": "Student API (Simplified Version)"})

# --- Run App ---
if __name__ == '__main__':
    # --- IMPORTANT ---
    # Call the function to create default users BEFORE running the app
    create_default_users()
    # -------------

    # debug=True is suitable for personal development
    app.run(debug=True, port=5000)
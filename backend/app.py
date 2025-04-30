from flask import Flask, jsonify
from flask_cors import CORS
from app.db.q_course import CourseDB

app = Flask(__name__)
CORS(app)

@app.route("/")
def hello():
    return jsonify({"message": "Hello from Flask with Conda!"})

@app.route("/api/courses/semester/<semester>")
def get_courses_by_semester(semester):
    db = CourseDB()
    results = db.get_courses_by_semester(semester)
    if results is None:     
        return jsonify({"error": "Failed to fetch courses"}), 500
    return jsonify(results)

if __name__ == "__main__":
    app.run(debug=True)
import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from .conn import get_connection

class CourseDB:
    def __init__(self):
        self.db = 'course'

    def get_all_tables(self):
        conn = get_connection(self.db)
        if not conn:
            return None
        try:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT table_name FROM information_schema.tables
                WHERE table_schema = 'public' AND table_catalog = %s;
            """, (self.db,))
            tables = [row[0] for row in cursor.fetchall()]
            cursor.close()
            conn.close()
            return tables
        except Exception as e:
            print(f"Error fetching tables: {e}")
            return None


    def get_courses_by_semester(self, semester):
        conn = get_connection(self.db)
        if not conn:
            return None
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM courses WHERE semester = %s;", (semester,))
            results = cursor.fetchall()
            cursor.close()
            conn.close()
            return results
        except Exception as e:
            print(f"Error fetching courses by semester: {e}")
            return None

    
if __name__ == "__main__":
    db = CourseDB()
    tables = db.get_all_tables()
    print("Tables in database 'course':", tables)

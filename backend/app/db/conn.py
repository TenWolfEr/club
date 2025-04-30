import psycopg2
import dotenv
import os
from psycopg2 import OperationalError

# Load environment variables from .env file
dotenv.load_dotenv()

def get_connection(db_name):
    """
    Establish Connection with PostgreSQL DB
    params:
        db_name     - postgres
    return:
        `connection` for success | `None and exception` for failed 。
    """
    connection = None
    try:
        connection = psycopg2.connect(
            database=db_name,
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            host=os.getenv("DB_HOST", "localhost"),
            port=os.getenv("DB_PORT", "5432")
        )
        print("Connected successful")
        return connection
    except OperationalError as e:
        print(f"Fail Connected | due to：{e}")
        return None


# For testing
if __name__ == "__main__":
    conn = get_connection(os.getenv("DB_NAME", "postgres"))
    if conn:
        # 執行SQL操作
        cursor = conn.cursor()
        cursor.execute("SELECT version();")
        version = cursor.fetchone()
        if version is not None:
            print(f"db Version: {version[0]}")
        else:
            print("No version information returned from database.")

        # close db
        cursor.close()
        conn.close()
        print("close")
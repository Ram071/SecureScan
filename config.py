import os

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.dirname(
os.path.abspath(file)
)

DATABASE_PATH = os.path.join(
BASE_DIR,
"securescan.db"
)

UPLOAD_FOLDER = os.path.join(
BASE_DIR,
"uploads"
)

REPORT_FOLDER = os.path.join(
BASE_DIR,
"reports"
)

SECRET_KEY = os.getenv(
"SECRET_KEY",
"development-secret"
)

VIRUSTOTAL_API_KEY = os.getenv(
"VIRUSTOTAL_API_KEY",
""
)

MAX_FILE_SIZE = 10 * 1024 * 1024

ALLOWED_EXTENSIONS = {
"txt",
"pdf",
"doc",
"docx",
"xls",
"xlsx",
"jpg",
"jpeg",
"png",
"zip"
}

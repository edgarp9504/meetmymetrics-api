import psycopg2
from app.core.config import settings

def get_connection():
    return psycopg2.connect(settings.database_url)

import sys
import os

# Add root directory to path for imports on Vercel serverless
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import app

# Vercel WSGI entry point
# Exports 'app' as the WSGI callable

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file
import firebase_admin
from firebase_admin import credentials, auth, firestore, db as rtdb
from functools import wraps
import os
from dotenv import load_dotenv
from datetime import datetime, timedelta
from flask_caching import Cache
import json
import requests

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'dev-secret-key')
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)  # Set session to expire in 7 days
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

# Add cache-busting headers
@app.after_request
def add_cache_control_headers(response):
    """Add cache control headers to prevent caching"""
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    # Also clear session cookies if not needed
    if request.endpoint in ['index', 'login', 'register', 'about', 'public_events']:
        if 'session' in request.cookies:
            response.set_cookie('session', '', expires=0, path='/')
    return response

# Configure Flask-Caching
cache = Cache(app, config={
    'CACHE_TYPE': 'simple',
    'CACHE_DEFAULT_TIMEOUT': 300  # 5 minutes cache timeout
})

# Function to find Firebase credentials file
def find_firebase_credentials():
    """Find Firebase credentials file from current directory or subdirectories."""
    credential_filename = "nivs-fbaa6-firebase-adminsdk-fbsvc-ca0e80cdc7.json"
    
    # Check current directory
    if os.path.exists(credential_filename):
        return credential_filename
    
    # Check TRY subdirectory
    try_path = os.path.join("TRY", credential_filename)
    if os.path.exists(try_path):
        return try_path
    
    # Walk through subdirectories to find the file
    for root, dirs, files in os.walk("."):
        if credential_filename in files:
            return os.path.join(root, credential_filename)
    
    # If not found, raise an error
    raise FileNotFoundError(f"Firebase credentials file '{credential_filename}' not found in current directory or subdirectories")

# Initialize Firebase with Windows-compatible settings
firebase_cred_path = find_firebase_credentials()
print(f"Using Firebase credentials from: {firebase_cred_path}")
cred = credentials.Certificate(firebase_cred_path)
firebase_admin.initialize_app(cred, {
    'databaseURL': os.getenv('FIREBASE_DATABASE_URL'),
    'projectId': os.getenv('FIREBASE_PROJECT_ID'),
    'storageBucket': os.getenv('FIREBASE_STORAGE_BUCKET')
})

# Initialize Firestore
db = firestore.client()

def verify_token():
    auth_header = request.headers.get('Authorization', None)
    print(f"[verify_token] Authorization header: {auth_header}")
    
    try:
        # For API requests, require token
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            if not auth_header or not auth_header.startswith('Bearer '):
                print('[verify_token] API request missing Bearer token')
                return None
            
        # If we have a token, verify it first (Firebase account verification)
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split('Bearer ')[1]
            print(f"[verify_token] Verifying Firebase token: {token[:10]}...")
            try:
                # STEP 1: Verify Firebase account exists and token is valid
                decoded_token = auth.verify_id_token(token)
                uid = decoded_token.get('uid')
                email = decoded_token.get('email')
                
                # STEP 2: Verify Firebase user record exists
                try:
                    firebase_user = auth.get_user(uid)
                    print(f"[verify_token] Firebase user verified - UID: {uid}, Email: {email}")
                    
                    # Check if account is disabled
                    if firebase_user.disabled:
                        print(f"[verify_token] Firebase account is disabled for UID: {uid}")
                        return None
                        
                    # Check if email is verified (optional, depending on requirements)
                    if not firebase_user.email_verified:
                        print(f"[verify_token] Firebase email not verified for UID: {uid}")
                        # You can choose to return None here if email verification is required
                        # return None
                    
                    print(f"[verify_token] Firebase account validation successful")
                    return decoded_token
                    
                except auth.UserNotFoundError:
                    print(f"[verify_token] Firebase user not found for UID: {uid}")
                    return None
                except Exception as firebase_error:
                    print(f"[verify_token] Firebase user verification failed: {firebase_error}")
                    return None
                    
            except auth.InvalidIdTokenError as e:
                print(f"[verify_token] Invalid token: {e}")
                return None
            except auth.ExpiredIdTokenError:
                print("[verify_token] Token has expired")
                return None
            except auth.RevokedIdTokenError:
                print("[verify_token] Token has been revoked")
                return None
            except Exception as e:
                print(f"[verify_token] Token verification failed: {e}")
                return None
            
        # If we have a valid session, verify the Firebase account still exists
        if session.get('user_id'):
            uid = session.get('user_id')
            print(f"[verify_token] Using session data for user_id: {uid}")
            
            # Verify Firebase account still exists for session-based auth
            try:
                firebase_user = auth.get_user(uid)
                if firebase_user.disabled:
                    print(f"[verify_token] Session user Firebase account is disabled: {uid}")
                    session.clear()  # Clear invalid session
                    return None
                    
                return {
                    'user_id': uid,
                    'email': session.get('email') or firebase_user.email,
                    'role': session.get('user_role')
                }
            except auth.UserNotFoundError:
                print(f"[verify_token] Session user not found in Firebase: {uid}")
                session.clear()  # Clear invalid session
                return None
            except Exception as firebase_error:
                print(f"[verify_token] Session Firebase verification failed: {firebase_error}")
                return None
            
        print('[verify_token] No valid authentication found')
        return None
            
    except Exception as e:
        print(f"[verify_token] Token verification failed: {e}")
        return None

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token_data = verify_token()
        if not token_data:
            return jsonify({'error': 'No valid authentication token provided'}), 401
            
        user_doc = db.collection('users').document(token_data['user_id']).get()
        if not user_doc.exists:
            return jsonify({'error': 'User not found'}), 404
            
        user_data = user_doc.to_dict()
        if user_data.get('role') != 'admin' or not user_data.get('is_approved', False):
            return jsonify({'error': 'Admin authentication required'}), 403
            
        return f(*args, **kwargs)
    return decorated_function

def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            print(f'[role_required] Checking roles {roles} for path {request.path}')
            
            # First check session
            if session.get('user_id'):
                print('[role_required] Using session-based auth')
                user_id = session.get('user_id')
                user_doc = db.collection('users').document(user_id).get()
                if user_doc.exists:
                    user_data = user_doc.to_dict()
                    print(f'[role_required] User data from session: {user_data}')
                    if user_data.get('role') in roles:
                        if user_data.get('is_banned'):
                            print('[role_required] User is banned')
                            return jsonify({'error': 'Account has been banned'}), 403
                        if user_data.get('role') == 'admin' and not user_data.get('is_approved'):
                            print('[role_required] Admin not approved')
                            return redirect(url_for('admin_pending'))
                        return f(*args, **kwargs)
                    else:
                        print(f'[role_required] User role {user_data.get("role")} not in {roles}')
                        return jsonify({'error': 'Insufficient permissions'}), 403
            
            # If no session, try token
            if request.headers.get('Authorization'):
                print('[role_required] Using token-based auth')
                token_data = verify_token()
                if not token_data:
                    print('[role_required] Invalid token')
                    return jsonify({'error': 'Invalid authentication token'}), 401
                user_id = token_data['user_id']
                user_doc = db.collection('users').document(user_id).get()
                if not user_doc.exists:
                    print('[role_required] User not found')
                    return jsonify({'error': 'User not found'}), 404
                user_data = user_doc.to_dict()
                print(f'[role_required] User data from token: {user_data}')
                if user_data.get('role') not in roles:
                    print(f'[role_required] User role {user_data.get("role")} not in {roles}')
                    return jsonify({'error': f'Required role: {", ".join(roles)}'}), 403
                if user_data.get('is_banned'):
                    print('[role_required] User is banned')
                    return jsonify({'error': 'Account has been banned'}), 403
                if user_data.get('role') == 'admin' and not user_data.get('is_approved'):
                    print('[role_required] Admin not approved')
                    return redirect(url_for('admin_pending'))
                return f(*args, **kwargs)
            
            # If no valid authentication found, return 401 for API requests
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({'error': 'Authentication required'}), 401
                
            # For regular requests, redirect to login
            print('[role_required] No valid authentication found')
            return redirect(url_for('login'))
            
        return decorated_function
    return decorator

@app.route('/api/firebase-config')
def get_firebase_config():
    """Serve Firebase configuration from environment variables."""
    return jsonify({
        'apiKey': os.getenv('FIREBASE_API_KEY'),
        'authDomain': os.getenv('FIREBASE_AUTH_DOMAIN'),
        'projectId': os.getenv('FIREBASE_PROJECT_ID'),
        'storageBucket': os.getenv('FIREBASE_STORAGE_BUCKET'),
        'messagingSenderId': os.getenv('FIREBASE_MESSAGING_SENDER_ID'),
        'appId': os.getenv('FIREBASE_APP_ID'),
        'measurementId': os.getenv('FIREBASE_MEASUREMENT_ID'),
        'databaseURL': os.getenv('FIREBASE_DATABASE_URL')
    })

@app.route('/clear-session')
def clear_session():
    """Endpoint to manually clear session data"""
    session.clear()
    session.permanent = False
    return jsonify({'message': 'Session cleared successfully'})

@app.route('/force-clear')
def force_clear():
    """Force clear all session and cookie data"""
    session.clear()
    session.permanent = False
    response = jsonify({'message': 'All data cleared successfully'})
    # Clear all cookies
    for cookie_name in request.cookies:
        response.set_cookie(cookie_name, '', expires=0, path='/')
    return response

@app.route('/')
def index():
    # Clear any existing session data on homepage visit
    session.clear()
    session.permanent = False
    print(f"[DEBUG] Session cleared and reset")
    print(f"[DEBUG] Session data after clear: {dict(session)}")
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/public-events')
def public_events():
    return render_template('events.html')

@app.route('/api/events')
def get_public_events():
    # Get all events that are happening now or in the future
    current_time = datetime.utcnow().isoformat()
    events_ref = db.collection('events')
    events = events_ref.where('date', '>=', current_time).stream()
    
    # Get current user info if logged in
    token_data = verify_token()
    current_user_id = token_data['user_id'] if token_data else None
    user_role = None
    
    if current_user_id:
        user_doc = db.collection('users').document(current_user_id).get()
        if user_doc.exists:
            user_data = user_doc.to_dict()
            user_role = user_data.get('role')
    
    events_list = []
    for event in events:
        event_data = event.to_dict()
        event_data['id'] = event.id
        
        # Add creator information
        creator_id = event_data.get('creator_id')
        if creator_id:
            creator_doc = db.collection('users').document(creator_id).get()
            if creator_doc.exists:
                creator_data = creator_doc.to_dict()
                event_data['creator'] = {
                    'id': creator_id,
                    'username': creator_data.get('username', 'Unknown'),
                    'email': creator_data.get('email', '')
                }
        
        # Check if current user is enrolled
        event_data['currentUserEnrolled'] = False
        if current_user_id and 'enrollments' in event_data:
            enrollments = event_data['enrollments']
            event_data['currentUserEnrolled'] = any(
                e['user_id'] == current_user_id for e in enrollments
            )
            # For admin view, check if they are the creator
            if user_role == 'admin':
                event_data['isCreator'] = event_data.get('creator_id') == current_user_id
                # Keep the full enrollments array for admin users
                event_data['enrollments'] = enrollments
            else:
                # For non-admin users, just send the count
                event_data['enrollments'] = len(enrollments)
        else:
            event_data['enrollments'] = 0
        
        events_list.append(event_data)
    
    return jsonify(events_list)

@app.route('/api/events/enroll', methods=['POST', 'DELETE'])
def enroll_in_event():
    data = request.json
    event_id = data.get('eventId')
    email = data.get('email')
    
    if not all([event_id, email]):
        return jsonify({'error': 'Missing required fields'}), 400
    
    try:
        event_ref = db.collection('events').document(event_id)
        event = event_ref.get()
        
        if not event.exists:
            return jsonify({'error': 'Event not found'}), 404
        
        event_data = event.to_dict()
        
        if request.method == 'DELETE':
            # Unenroll logic
            enrollments = event_data.get('enrollments', [])
            enrollments = [e for e in enrollments if e['email'] != email]
            event_ref.update({'enrollments': enrollments})
            return jsonify({'message': 'Successfully unenrolled from the event'})
        
        # Enroll logic
        # Check if event date has passed
        event_date = datetime.fromisoformat(event_data['date'])
        if event_date < datetime.utcnow():
            return jsonify({'error': 'Event has already passed'}), 400
        
        # Check if user is already enrolled
        enrollments = event_data.get('enrollments', [])
        if any(e['email'] == email for e in enrollments):
            return jsonify({'error': 'Already enrolled in this event'}), 400
        
        # Add enrollment
        enrollment = {
            'name': data.get('name'),
            'email': email,
            'enrollmentDate': datetime.utcnow().isoformat()
        }
        enrollments.append(enrollment)
        event_ref.update({'enrollments': enrollments})
        
        return jsonify({'message': 'Successfully enrolled in the event'})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        # Clear session on login page visit
        session.clear()
        session.permanent = False
        return render_template('login.html')

    # For API requests, always return JSON
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        try:
            print(f'[login] Received AJAX POST request to /login')
            print(f'[login] Request Headers: {request.headers}')
            print(f'[login] Request Data: {request.get_data()}') # Log raw request data

            # STEP 1: Verify Firebase token and account exists
            token_data = verify_token()
            if not token_data:
                print('[login] Invalid Credentials - Firebase authentication failed')
                return jsonify({'error': 'Invalid Credentials - Account not found or disabled'}), 401

            uid = token_data.get('user_id') or token_data.get('uid')
            email = token_data.get('email')

            print(f'[login] Firebase Account Verified - UID: {uid}, Email: {email}')

            if not uid:
                 print('[login] Invalid Credentials - Missing UID in token_data')
                 return jsonify({'error': 'Invalid Credentials'}), 401

            # STEP 2: Check if user document exists in Firestore
            user_doc = db.collection('users').document(uid).get()

            if not user_doc.exists:
                print(f'[login] User document not found in Firestore for UID: {uid}')
                # Firebase account exists but no Firestore profile - redirect to registration
                return jsonify({
                    'error': 'Account found but profile incomplete. Please complete registration.',
                    'redirect': url_for('register'),
                    'action': 'register'
                }), 404

            # STEP 3: Validate user data and status
            user_data = user_doc.to_dict()
            print(f'[login] Found user document in Firestore: {user_data}')

            # Check if user is banned
            if user_data.get('is_banned'):
                print('[login] Account has been banned')
                return jsonify({'error': 'Account has been banned'}), 403

            # Check admin approval status
            if user_data.get('role') == 'admin' and not user_data.get('is_approved', False):
                print('[login] Admin account pending approval')
                return jsonify({
                    'error': 'Admin account pending approval',
                    'redirect': url_for('admin_pending')
                }), 403

            # STEP 4: Set session data for successful login
            session.clear()
            session.permanent = True
            session['user_id'] = uid
            session['email'] = email
            session['username'] = user_data.get('username', '')
            session['user_role'] = user_data.get('role', 'user')
            session['is_approved'] = user_data.get('is_approved', True)

            # STEP 5: Determine redirect URL based on role
            user_role = user_data.get('role', 'user')
            redirect_url = {
                'dev': '/dev/dashboard',
                'admin': url_for('dashboard'),
                'user': url_for('public_events')
            }.get(user_role, url_for('public_events'))

            print(f'[login] Login successful for UID {uid}, role {user_role}, redirecting to {redirect_url}')
            return jsonify({'redirect': redirect_url})

        except Exception as e:
            print(f'[login] Login error: {str(e)}')
            return jsonify({'error': 'Authentication failed'}), 401

    # For non-AJAX POST requests to /login, which are not expected with token-based auth
    print('[login] Received non-AJAX POST request.')
    return jsonify({'error': 'Method Not Allowed for non-AJAX request to /login'}), 405

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        # Force clear all session data on GET to prevent stale session data
        session.clear()
        session.permanent = False
        return render_template('register.html')
    
    elif request.method == 'POST':
        # Handle POST registration requests
        print('[register] Received POST request')
        
        # Verify the request has proper authentication
        token_data = verify_token()
        if not token_data:
            print('[register] No valid token provided')
            return jsonify({'error': 'Authentication required'}), 401
            
        try:
            data = request.json
            username = data.get('username')
            role = data.get('role', 'user')
            dev_code = data.get('dev_code')
            
            # Get user info from token
            uid = token_data['user_id']
            email = token_data.get('email')
            
            if not all([username, uid, email]):
                print('[register] Missing required fields')
                return jsonify({'error': 'Missing required fields'}), 400
                
            print(f'[register] Processing registration for UID: {uid}, Email: {email}, Role: {role}')
            
            # Developer Code Validation (only for dev role)
            if role == 'dev':
                valid_dev_code = os.getenv('DEV_REGISTRATION_CODE', '22127022')
                if not dev_code or dev_code != valid_dev_code:
                    print('[register] Invalid developer registration code provided')
                    return jsonify({'error': 'Invalid developer registration code'}), 403
                print('[register] Developer code validated successfully.')
            
            # Check if user already exists in Firestore
            user_doc = db.collection('users').document(uid).get()
            if user_doc.exists:
                print(f'[register] User already exists in Firestore for UID: {uid}')
                return jsonify({'error': 'User already registered'}), 409
                
            # Determine approval status based on role
            is_approved = role != 'admin'  # Only admin needs approval
            
            # Create user document in Firestore
            print(f'[register] Creating user document in Firestore for UID: {uid}')
            user_data = {
                'user_id': uid,
                'username': username,
                'email': email,
                'role': role,
                'is_approved': is_approved,
                'is_banned': False,
                'created_at': datetime.utcnow().isoformat()
            }
            db.collection('users').document(uid).set(user_data)
            print(f'[register] User document created successfully for UID: {uid}')
              # Set session data
            session['user_id'] = uid
            session['email'] = email
            session['username'] = username
            session['user_role'] = role
            session['is_approved'] = is_approved
              # Determine redirect URL
            redirect_url = {
                'admin': url_for('admin_pending') if not is_approved else url_for('dashboard'),
                'dev': '/dev/dashboard',
                'user': url_for('public_events')
            }.get(role, url_for('public_events'))
            
            print(f'[register] Registration successful, redirecting to: {redirect_url}')
            return jsonify({
                'message': 'Registration successful',
                'redirect': redirect_url
            }), 201
            
        except Exception as e:
            print(f'[register] Registration error: {str(e)}')
            return jsonify({'error': str(e)}), 500

@app.route('/dashboard')
def dashboard():
    token_data = verify_token()
    if not token_data:
        print("No valid authentication, redirecting to login")
        return redirect(url_for('login'))

    try:
        user_id = token_data.get('user_id')
        user_doc = db.collection('users').document(user_id).get()

        # If user document doesn't exist, clear session and redirect to login
        if not user_doc.exists:
            print(f"No user document found for {user_id}, clearing session")
            session.clear()
            return redirect(url_for('login'))

        current_user_data = user_doc.to_dict()
        role = current_user_data.get('role', 'user')
        print(f"User role: {role}")

        # Check if admin is approved, but only if the role is admin
        if role == 'admin' and not current_user_data.get('is_approved', False):
            print("Admin not approved, redirecting to pending approval page")
            return render_template('admin_pending.html', user=current_user_data)

        # Update session data
        session['user_id'] = user_id
        session['username'] = current_user_data.get('username', '')
        session['user_role'] = role
        session['is_approved'] = current_user_data.get('is_approved', True)

        # Redirect based on role
        if role == 'admin':
            return render_template('admin_dashboard.html', user=current_user_data)
        elif role == 'dev':
            # Dev accounts do not need admin approval check here, they go straight to dev dashboard
            return render_template('dev_dashboard.html',
                                 user=current_user_data,
                                 # Pass necessary stats if dev dashboard needs them
                                 # These stats loading might be slow, consider fetching via API on dev dashboard load
                                 total_users=0, total_admins=0, total_devs=0,
                                 users=[], admins=[], devs=[]
                                )
        else:
            return render_template('dashboard.html', user=current_user_data)

    except Exception as e:
        print(f"Error in dashboard route: {str(e)}")
        session.clear()
        return redirect(url_for('login'))

@app.route('/api/dashboard-data')
@cache.cached(timeout=30)  # Cache for 30 seconds
def dashboard_data():
    token_data = verify_token()
    if not token_data:
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        user_id = token_data.get('user_id')
        user_doc = db.collection('users').document(user_id).get()
        if not user_doc.exists:
            return jsonify({'error': 'User not found'}), 404
            
        user_data = user_doc.to_dict()
        
        # Check if admin is approved
        if user_data.get('role') == 'admin' and not user_data.get('is_approved', False):
            return jsonify({
                'success': True,
                'user': {
                    'id': user_id,
                    'username': user_data.get('username'),
                    'role': user_data.get('role'),
                    'is_approved': False,
                    'status': 'pending_approval'
                }
            })
            
        return jsonify({
            'success': True,
            'user': {
                'id': user_id,
                'username': user_data.get('username'),
                'role': user_data.get('role'),
                'is_approved': user_data.get('is_approved', True)
            }
        })
    except Exception as e:
        print(f"Error in dashboard_data: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/admin_pending')
def admin_pending():
    try:
        # Clear any existing session data
        session.clear()
        session.permanent = False
        
        # Get token from Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return redirect(url_for('login'))
            
        token = auth_header.split('Bearer ')[1]
        token_data = verify_token(token)
        if not token_data:
            return redirect(url_for('login'))
            
        # Get user document
        user_ref = db.collection('users').document(token_data['user_id'])
        user_doc = user_ref.get()
        
        if not user_doc.exists:
            session.clear()
            return redirect(url_for('login'))
            
        user_data = user_doc.to_dict()
        
        # Check if user is an admin
        if user_data.get('role') != 'admin':
            return redirect(url_for('dashboard'))
            
        # Check if admin is already approved
        if user_data.get('approved', False):
            return redirect(url_for('dashboard'))
            
        # If we get here, user is an unapproved admin
        return render_template('admin_pending.html', user=user_data)
        
    except Exception as e:
        print(f"Error in admin_pending: {str(e)}")
        session.clear()
        return redirect(url_for('login'))

@app.route('/events', methods=['GET', 'POST', 'PUT', 'DELETE'])
@admin_required
def manage_events():
    token_data = verify_token()
    current_user_id = token_data['user_id']

    if request.method == 'GET':
        events = db.collection('events').stream()
        events_list = []
        for event in events:
            event_data = event.to_dict()
            event_data['id'] = event.id
            # Only set isCreator if the current user is the creator
            event_data['isCreator'] = event_data.get('creator_id') == current_user_id
            if 'enrollments' in event_data:
                event_data['enrollments'] = len(event_data['enrollments'])
            events_list.append(event_data)
        return jsonify(events_list)
    
    elif request.method == 'POST':
        event_data = request.json
        event_data['creator_id'] = token_data['user_id']
        event_data['created_at'] = datetime.utcnow().isoformat()
        event_data['enrollments'] = []
        
        # Validate required fields
        required_fields = ['title', 'description', 'date', 'location']
        if not all(field in event_data for field in required_fields):
            return jsonify({'error': 'Missing required fields'}), 400
            
        # Create event
        event_ref = db.collection('events').add(event_data)
        return jsonify({
            'message': 'Event created successfully',
            'event_id': event_ref[1].id,
            'event': event_data  # Include the full event data in the response
        })
    elif request.method == 'PUT':
        event_id = request.args.get('id')
        event_data = request.json
        event_ref = db.collection('events').document(event_id)
        event = event_ref.get()
        
        if not event.exists:
            return jsonify({'error': 'Event not found'}), 404
            
        current_event_data = event.to_dict()
        # Verify that the current user is the creator
        if current_event_data.get('creator_id') != current_user_id:
            return jsonify({'error': 'Only the event creator can edit this event'}), 403
        
        # Update event
        event_data['updated_at'] = datetime.utcnow().isoformat()
        # Preserve creator_id and enrollments
        event_data['creator_id'] = current_event_data['creator_id']
        event_data['enrollments'] = current_event_data.get('enrollments', [])
        event_ref.update(event_data)
        return jsonify({
            'message': 'Event updated successfully',
            'event': event_data  # Include the full event data in the response
        })
    
    elif request.method == 'DELETE':
        event_id = request.args.get('id')
        event_ref = db.collection('events').document(event_id)
        event = event_ref.get()
        
        if not event.exists:
            return jsonify({'error': 'Event not found'}), 404
            
        # Verify that the current user is the creator
        if event.to_dict().get('creator_id') != current_user_id:
            return jsonify({'error': 'Only the event creator can delete this event'}), 403
        
        event_ref.delete()
        return jsonify({'message': 'Event deleted successfully'})

@app.route('/admin/events', methods=['GET', 'POST', 'PUT', 'DELETE'])
@admin_required
def admin_manage_events():
    return manage_events()

@app.route('/dev/approve-user', methods=['POST'])
@role_required(['dev'])
def approve_user():
    user_id = request.json.get('user_id')
    action = request.json.get('action')  # 'approve' or 'deny'
    
    user_ref = db.collection('users').document(user_id)
    user = user_ref.get()
    
    if not user.exists:
        return jsonify({'error': 'User not found'}), 404
    
    if action == 'approve':
        user_ref.update({'is_approved': True})
    elif action == 'deny':
        auth.delete_user(user_id)
        user_ref.delete()
    
    return jsonify({'message': f'User {action}d successfully'})

@app.route('/dev/ban-user', methods=['POST'])
@role_required(['dev'])
def ban_user():
    user_id = request.json.get('user_id')
    action = request.json.get('action')  # 'ban' or 'unban'
    
    user_ref = db.collection('users').document(user_id)
    user = user_ref.get()
    
    if not user.exists:
        return jsonify({'error': 'User not found'}), 404
    
    user_ref.update({'is_banned': action == 'ban'})
    return jsonify({'message': f'User {action}ned successfully'})

@app.route('/dev/dashboard')
@role_required(['dev'])
def dev_dashboard():
    try:
        # Get all users grouped by role
        users = []
        admins = []
        devs = []
        
        users_ref = db.collection('users').stream()
        for user in users_ref:
            user_data = user.to_dict()
            user_data['id'] = user.id
            if user_data['role'] == 'user':
                users.append(user_data)
            elif user_data['role'] == 'admin':
                admins.append(user_data)
            elif user_data['role'] == 'dev':
                devs.append(user_data)
        
        return render_template('dev_dashboard.html', 
                             users=users, 
                             admins=admins, 
                             devs=devs,
                             total_users=len(users),
                             total_admins=len(admins),
                             total_devs=len(devs))
    except Exception as e:
        print(f"Error in dev_dashboard: {str(e)}")
        return redirect(url_for('login'))

@app.route('/dev/stats')
@role_required(['dev'])
@cache.cached(timeout=60)  # Cache for 1 minute
def dev_stats():
    try:
        users_ref = db.collection('users').stream()
        stats = {
            'total_users': 0,
            'pending_admins': 0,
            'banned_users': 0
        }
        
        for user in users_ref:
            user_data = user.to_dict()
            if user_data['role'] != 'dev':  # Don't count devs in total users
                stats['total_users'] += 1
            if user_data['role'] == 'admin' and not user_data.get('is_approved', False):
                stats['pending_admins'] += 1
            if user_data.get('is_banned', False):
                stats['banned_users'] += 1
        
        return jsonify(stats)
    except Exception as e:
        print(f"Error in dev_stats: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500
    
@app.route('/dev/approve-admin', methods=['POST'])
@role_required(['dev'])
def approve_admin():
    data = request.json
    token_data = verify_token()
    admin_id = data.get('admin_id')
    action = data.get('action')  # 'approve' or 'deny'
    
    if not admin_id or not action:
        return jsonify({'error': 'Missing required fields'}), 400
    
    try:
        admin_ref = db.collection('users').document(admin_id)
        admin_doc = admin_ref.get()
        
        if not admin_doc.exists:
            return jsonify({'error': 'Admin not found'}), 404
            
        admin_data = admin_doc.to_dict()
        if admin_data.get('role') != 'admin':
            return jsonify({'error': 'User is not an admin'}), 400
            
        if action == 'approve':
            admin_ref.update({
                'is_approved': True,
                'approved_at': datetime.utcnow().isoformat(),
                'approved_by': token_data['user_id']
            })
        elif action == 'deny':
            # Delete the user from Firebase Auth
            auth.delete_user(admin_id)
            # Delete from Firestore
            admin_ref.delete()
        
        return jsonify({'message': f'Admin {action}d successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/dev/user/status', methods=['POST'])
@role_required(['dev'])
def update_user_status():
    data = request.json
    user_id = data.get('userId')
    is_banned = data.get('is_banned')
    
    if user_id is None or is_banned is None:
        return jsonify({'error': 'Missing required fields'}), 400
    
    try:
        user_ref = db.collection('users').document(user_id)
        user = user_ref.get()
        
        if not user.exists:
            return jsonify({'error': 'User not found'}), 404
        
        user_data = user.to_dict()
        if user_data.get('role') == 'dev':
            return jsonify({'error': 'Cannot modify dev user status'}), 403
        
        user_ref.update({'is_banned': is_banned})
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/dev/admin/approve', methods=['POST'])
@role_required(['dev'])
def handle_admin_approval():
    data = request.json
    token_data = verify_token()
    admin_id = data.get('adminId')
    approve = data.get('approve')
    
    if admin_id is None or approve is None:
        return jsonify({'error': 'Missing required fields'}), 400
    
    try:
        admin_ref = db.collection('users').document(admin_id)
        admin = admin_ref.get()
        
        if not admin.exists:
            return jsonify({'error': 'Admin not found'}), 404
        
        admin_data = admin.to_dict()
        if admin_data.get('role') != 'admin':
            return jsonify({'error': 'User is not an admin'}), 403
        
        if not approve:
            # If denying admin access, delete from Firebase Auth and Firestore
            auth.delete_user(admin_id)
            admin_ref.delete()
        else:
            # Update approval status and add metadata
            admin_ref.update({
                'is_approved': True,
                'approved_at': datetime.utcnow().isoformat(),
                'approved_by': token_data['user_id']
            })
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    try:
        # Clear all session data
        session.clear()
        # Set session to expire immediately
        session.permanent = False
        
        # For AJAX requests, return JSON response
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({
                'success': True,
                'redirect': url_for('login', _t=datetime.utcnow().timestamp())
            })
        
        # For regular requests, redirect to login page with timestamp
        return redirect(url_for('login', _t=datetime.utcnow().timestamp()))
    except Exception as e:
        print(f"Error during logout: {str(e)}")
        # Even if there's an error, try to redirect to login
        return redirect(url_for('login', _t=datetime.utcnow().timestamp()))

@app.route('/firebase-cors.json')
def serve_cors_json():
    return send_file('cors.json', mimetype='application/json')

# Example function to store image as base64 in Realtime Database

def save_image_to_realtime_db(image_base64, image_name):
    ref = rtdb.reference('images')
    new_image_ref = ref.push({
        'name': image_name,
        'data': image_base64,
        'uploaded_at': datetime.utcnow().isoformat()
    })
    return new_image_ref.key

@app.route('/api/upload-image', methods=['POST'])
def upload_image():
    data = request.json
    image_base64 = data.get('image_base64')
    image_name = data.get('image_name')
    if not image_base64 or not image_name:
        return jsonify({'error': 'Missing image data'}), 400
    try:
        key = save_image_to_realtime_db(image_base64, image_name)
        return jsonify({'success': True, 'key': key})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/events/stats/<event_id>', methods=['GET'])
@admin_required
def get_event_stats(event_id):
    try:
        # Get the current admin's ID
        token_data = verify_token()
        current_admin_id = token_data['user_id']
        
        event_ref = db.collection('events').document(event_id)
        event = event_ref.get()
        
        if not event.exists:
            return jsonify({'error': 'Event not found'}), 404
            
        event_data = event.to_dict()
        enrollments = event_data.get('enrollments', [])
        
        # Get creator information
        creator_id = event_data.get('creator_id')
        creator_info = None
        if creator_id:
            creator_doc = db.collection('users').document(creator_id).get()
            if creator_doc.exists:
                creator_data = creator_doc.to_dict()
                creator_info = {
                    'id': creator_id,
                    'username': creator_data.get('username', 'Unknown'),
                    'email': creator_data.get('email')
                }
        
        # Check if current admin is the creator
        is_creator = event_data.get('creator_id') == current_admin_id
        
        stats = {
            'total_enrollments': len(enrollments),
            'users': [{'username': e.get('username'), 'email': e.get('email')} for e in enrollments],
            'isCreator': is_creator,
            'creator': creator_info,
            'event_details': {
                'title': event_data.get('title'),
                'date': event_data.get('date'),
                'location': event_data.get('location'),
                'description': event_data.get('description')
            }
        }
        
        return jsonify(stats)
    except Exception as e:
        print(f"Error in get_event_stats: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/events/<event_id>/enroll', methods=['POST'])
def enroll_event(event_id):
    token_data = verify_token()
    if not token_data:
        return jsonify({'error': 'Authentication required'}), 401
        
    try:
        event_ref = db.collection('events').document(event_id)
        event = event_ref.get()
        
        if not event.exists:
            return jsonify({'error': 'Event not found'}), 404
        
        event_data = event.to_dict()
        
        # Check if event date has passed
        event_date = datetime.fromisoformat(event_data['date'])
        if event_date < datetime.utcnow():
            return jsonify({'error': 'Event has already passed'}), 400
            
        # Get user data and verify not already enrolled
        user_id = token_data['user_id']
        enrollments = event_data.get('enrollments', [])
        if any(e.get('user_id') == user_id for e in enrollments):
            return jsonify({'error': 'Already enrolled in this event'}), 400
            
        # Get user info
        user_doc = db.collection('users').document(user_id).get()
        if not user_doc.exists:
            return jsonify({'error': 'User not found'}), 404
            
        user_data = user_doc.to_dict()
        
        # Add enrollment
        enrollment = {
            'user_id': user_id,
            'username': user_data.get('username', 'Unknown'),
            'email': user_data.get('email'),
            'enrollmentDate': datetime.utcnow().isoformat()
        }
        enrollments.append(enrollment)
        
        # Update event with new enrollment
        event_ref.update({'enrollments': enrollments})
        
        return jsonify({
            'message': 'Successfully enrolled in event',
            'enrollment': enrollment
        })
        
    except Exception as e:
        print(f"Error in enroll_event: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/events/<event_id>/unenroll', methods=['POST'])
def unenroll_event(event_id):
    token_data = verify_token()
    if not token_data:
        return jsonify({'error': 'Authentication required'}), 401

    try:
        event_ref = db.collection('events').document(event_id)
        event = event_ref.get()
        
        if not event.exists:
            return jsonify({'error': 'Event not found'}), 404
            
        event_data = event.to_dict()
        user_id = token_data['user_id']
        
        # Find and remove the enrollment
        enrollments = event_data.get('enrollments', [])
        new_enrollments = [e for e in enrollments if e.get('user_id') != user_id]
        
        if len(new_enrollments) == len(enrollments):
            return jsonify({'error': 'Not enrolled in this event'}), 400
            
        # Update event with new enrollments
        event_ref.update({'enrollments': new_enrollments})
        
        return jsonify({'message': 'Successfully unenrolled from event'})
        
    except Exception as e:
        print(f"Error in unenroll_event: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/refresh-token', methods=['POST'])
def refresh_token():
    token_data = verify_token()
    if not token_data:
        return jsonify({'error': 'Invalid or expired token'}), 401
        
    try:
        # Get fresh user data
        user_id = token_data['user_id']
        user_doc = db.collection('users').document(user_id).get()
        
        if not user_doc.exists:
            return jsonify({'error': 'User not found'}), 404
            
        user_data = user_doc.to_dict()
        
        # Check user status
        if user_data.get('is_banned'):
            return jsonify({'error': 'Account has been banned'}), 403
            
        if user_data.get('role') == 'admin' and not user_data.get('is_approved'):
            return jsonify({
                'error': 'Admin account pending approval',
                'redirect': url_for('admin_pending')
            }), 403
            
        # Update session data
        session['user_id'] = user_id
        session['username'] = user_data.get('username', '')
        session['user_role'] = user_data.get('role', 'user')
        session['is_approved'] = user_data.get('is_approved', True)
        
        return jsonify({
            'success': True,
            'user': {
                'id': user_id,
                'username': user_data.get('username'),
                'role': user_data.get('role'),
                'is_approved': user_data.get('is_approved', True)
            }
        })
        
    except Exception as e:
        print(f"Error in refresh_token: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/validate-session', methods=['GET'])
def validate_session():
    token_data = verify_token()
    if not token_data:
        return jsonify({'error': 'Invalid or expired session'}), 401
        
    try:
        # Get fresh user data
        user_id = token_data['user_id']
        user_doc = db.collection('users').document(user_id).get()
        
        if not user_doc.exists:
            return jsonify({'error': 'User not found'}), 404
            
        user_data = user_doc.to_dict()
        
        # Check user status
        if user_data.get('is_banned'):
            return jsonify({'error': 'Account has been banned'}), 403
            
        if user_data.get('role') == 'admin' and not user_data.get('is_approved'):
            return jsonify({
                'error': 'Admin account pending approval',
                'redirect': url_for('admin_pending')
            }), 403
            
        return jsonify({
            'valid': True,
            'user': {
                'id': user_id,
                'username': user_data.get('username'),
                'role': user_data.get('role'),
                'is_approved': user_data.get('is_approved', True)
            }
        })
        
    except Exception as e:
        print(f"Error in validate_session: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@app.route('/api/validate-dev-code', methods=['POST'])
def validate_dev_code():
    try:
        data = request.json
        dev_code_attempt = data.get('dev_code')

        if not dev_code_attempt:
            return jsonify({'valid': False, 'error': 'Developer code is required'}), 400

        valid_dev_code = os.getenv('DEV_REGISTRATION_CODE', '22127022')

        if dev_code_attempt == valid_dev_code:
            print('[validate_dev_code] Developer code is valid.')
            return jsonify({'valid': True}), 200
        else:
            print('[validate_dev_code] Invalid developer code entered.')
            return jsonify({'valid': False, 'error': 'Invalid developer registration code'}), 403

    except Exception as e:
        print(f'[validate_dev_code] Error: {str(e)}')
        return jsonify({'valid': False, 'error': 'Internal server error'}), 500

# New endpoint for complete registration
@app.route('/complete-registration', methods=['POST'])
def complete_registration():
    print('[complete-registration] Received request')
    try:
        data = request.json
        email = data.get('email')
        password = data.get('password')
        username = data.get('username')
        role = data.get('role', 'user')
        dev_code = data.get('dev_code')

        if not all([email, password, username]):
            print('[complete-registration] Missing required fields')
            return jsonify({'error': 'Missing required fields'}), 400

        # Backend Email Length Validation
        if len(email) < 5:
            print(f'[complete-registration] Email {email} is too short')
            return jsonify({'error': 'Email must be at least 5 characters long'}), 400

        # Developer Code Validation (only for dev role)
        if role == 'dev':
            valid_dev_code = os.getenv('DEV_REGISTRATION_CODE', '22127022')
            if not dev_code or dev_code != valid_dev_code:
                print('[complete-registration] Invalid developer registration code provided')
                return jsonify({'error': 'Invalid developer registration code'}), 403
            print('[complete-registration] Developer code validated successfully.')

        # Check if user already exists by email in Firebase Auth
        try:
            auth.get_user_by_email(email)
            print(f'[complete-registration] Attempted registration for existing email: {email}')
            return jsonify({'error': 'An account with this email already exists.', 'action': 'login'}), 409
        except auth.UserNotFoundError:
            pass # User does not exist, proceed with creation

        # Determine approval status based on role
        is_approved = role != 'admin' # Only admin needs approval

        # Create user in Firebase Auth using Admin SDK
        print(f'[complete-registration] Creating user in Firebase Auth for email: {email}')
        user = auth.create_user(email=email, password=password)
        uid = user.uid
        print(f'[complete-registration] Firebase user created with UID: {uid}')

        # Create user document in Firestore
        print(f'[complete-registration] Creating user document in Firestore for UID: {uid}')
        user_data = {
            'user_id': uid,
            'username': username,
            'email': email,
            'role': role,
            'is_approved': is_approved,
            'is_banned': False,
            'created_at': datetime.utcnow().isoformat()
        }
        db.collection('users').document(uid).set(user_data)
        print(f'[complete-registration] User document created successfully for UID: {uid}')

        # Optionally, generate a custom token for the frontend to sign in
        custom_token = auth.create_custom_token(uid)
        print('[complete-registration] Custom token generated.')

        redirect_url = {
            'admin': url_for('admin_pending') if not is_approved else url_for('dashboard'),
            'dev': url_for('dev_dashboard'),
            'user': url_for('public_events')
        }.get(role, url_for('public_events'))

        print(f'[complete-registration] Registration successful, redirecting to: {redirect_url}')
        return jsonify({'message': 'Registration successful', 'redirect': redirect_url, 'token': custom_token.decode('utf-8')}), 201

    except Exception as e:
        print(f'[complete-registration] Registration error: {str(e)}')
        # Clean up Firebase Auth user if created but Firestore failed
        if 'uid' in locals():
            try:
                auth.delete_user(uid)
                print(f'[complete-registration] Deleted Firebase user {uid} due to backend error.')
            except Exception as delete_error:
                print(f'[complete-registration] Error deleting Firebase user {uid}: {str(delete_error)}')
        return jsonify({'error': str(e)}), 400

@app.route('/api/events/<event_id>')
def get_single_event(event_id):
    """Get a single event by ID"""
    try:
        token_data = verify_token()
        if not token_data:
            return jsonify({'error': 'Authentication required'}), 401
            
        current_user_id = token_data['user_id']
        
        # Get the event document
        event_doc = db.collection('events').document(event_id).get()
        if not event_doc.exists:
            return jsonify({'error': 'Event not found'}), 404
            
        event_data = event_doc.to_dict()
        event_data['id'] = event_doc.id
        
        # Check if current user is the creator (for edit permissions)
        event_data['isCreator'] = event_data.get('creator_id') == current_user_id
        
        # Add creator information
        creator_id = event_data.get('creator_id')
        if creator_id:
            creator_doc = db.collection('users').document(creator_id).get()
            if creator_doc.exists:
                creator_data = creator_doc.to_dict()
                event_data['creator'] = {
                    'id': creator_id,
                    'username': creator_data.get('username', 'Unknown'),
                    'email': creator_data.get('email', '')
                }
        
        return jsonify(event_data)
        
    except Exception as e:
        print(f'Error fetching event {event_id}: {str(e)}')
        return jsonify({'error': 'Failed to fetch event'}), 500

if __name__ == '__main__':
    app.run(debug=True)

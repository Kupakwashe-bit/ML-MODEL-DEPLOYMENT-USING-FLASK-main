

from flask import Flask, request, render_template, flash, redirect, url_for
from flask_login import UserMixin, LoginManager, login_user, login_required, logout_user, current_user
import joblib
import pandas as pd
import psycopg2
import re
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from functools import wraps
from flask import jsonify



app = Flask(__name__)

app.secret_key = 'your_secret_key_here'  # Needed for flash messages
csrf = CSRFProtect(app)

# Database configuration (same as your db.py)
DB_NAME = "diabetes1"
DB_USER = "postgres"
DB_PW = "test1234"
DB_HOST = "localhost"


def get_db_connection():
    try:
        conn = psycopg2.connect(
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PW,
            host=DB_HOST
        )
        print("\033[92m✓ Database connection successful!\033[0m")  # Green checkmark
        print(f"Connected to: {DB_NAME} on {DB_HOST} as {DB_USER}")
        return conn
    except Exception as e:
        print("\033[91m✗ Database connection failed!\033[0m")  # Red X
        print(f"Error: {str(e)}")
        raise e




@app.route("/")
@login_required
def home():
    return render_template("index.html")


# @app.route("/home")
# def index():
#     return render_template("index.html")



@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get form data
        form_data = {
            'first_name': request.form.get('first_name', '').strip(),
            'last_name': request.form.get('last_name', '').strip(),
            'email': request.form.get('email', '').strip(),
            'user_name': request.form.get('user_name', '').strip(),
            'password': request.form.get('password', ''),
            'role': request.form.get('role', '')
        }

        # Validate form data
        errors = {}

        # Check for empty fields
        for field in form_data:
            if not form_data[field]:
                errors[field] = 'This field is required'

        # Validate email format
        if 'email' not in errors and not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', form_data['email']):
            errors['email'] = 'Invalid email format'

        # Validate password length
        if 'password' not in errors and len(form_data['password']) < 8:
            errors['password'] = 'Password must be at least 8 characters'

        # Check username availability
        if 'user_name' not in errors:
            try:
                conn = get_db_connection()
                with conn.cursor() as cur:
                    cur.execute('SELECT 1 FROM public.users WHERE "userName" = %s',
                                (form_data['user_name'],))
                    if cur.fetchone():
                        errors['user_name'] = 'Username already taken'
            except Exception as e:
                errors['user_name'] = 'Error checking username availability'
                app.logger.error(f"Username check error: {str(e)}")
            finally:
                if 'conn' in locals(): conn.close()

        if errors:
            # Render form with errors and preserve input
            return render_template('register.html',
                                   form_data=form_data,
                                   errors=errors)

        # If validation passes, proceed with registration
        try:
            conn = get_db_connection()
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO public.users
                    ("firstName", surname, email, "userName", password, "isActive", role)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """,
                            (form_data['first_name'],
                             form_data['last_name'],
                             form_data['email'],
                             form_data['user_name'],
                             generate_password_hash(form_data['password']),
                             False,
                             form_data['role'])
                            )
                conn.commit()

            flash('Registration successful! Your account is pending admin approval.', 'success')
            return redirect(url_for('login'))

        except psycopg2.IntegrityError as e:
            conn.rollback()
            if 'users_email_key' in str(e):
                errors['email'] = 'Email already registered'
            else:
                errors['general'] = 'Registration failed due to database constraints'
            return render_template('register.html',
                                   form_data=form_data,
                                   errors=errors)

        except Exception as e:
            conn.rollback()
            app.logger.error(f"Registration error: {str(e)}")
            errors['general'] = 'Registration failed. Please try again.'
            return render_template('register.html',
                                   form_data=form_data,
                                   errors=errors)

    # GET request - show empty registration form
    return render_template('register.html')





class User(UserMixin):
    def __init__(self, id, first_name, last_name, email, username, role):
        self.id = id
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.username = username
        self.role = role

    def get_id(self):
        return str(self.id)




login_manager = LoginManager()
login_manager.login_view = 'login'  # The route name of your login page
login_manager.init_app(app)





@login_manager.user_loader
def load_user(user_id):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('''
            SELECT id, "firstName", surname, email, "userName", role
            FROM public.users
            WHERE id = %s
        ''', (user_id,))
        user = cur.fetchone()

        if user:
            return User(id=user[0], first_name=user[1], last_name=user[2],
                        email=user[3], username=user[4], role=user[5])
        return None
    except Exception as e:
        print(f"Error loading user: {str(e)}")
        return None
    finally:
        if 'cur' in locals(): cur.close()
        if 'conn' in locals(): conn.close()



@login_manager.user_loader
def load_user(user_id):
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            cur.execute('SELECT id, "firstName", surname, email, "userName", role FROM public.users WHERE id = %s', (user_id,))
            user_data = cur.fetchone()
            if user_data:
                return User(id=user_data[0], first_name=user_data[1], last_name=user_data[2], 
                          email=user_data[3], username=user_data[4], role=user_data[5])
    except Exception as e:
        print(f"Error loading user: {str(e)}")
    finally:
        if 'conn' in locals(): conn.close()
    return None




@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['user_name']
        password = request.form['password']
        remember = True if request.form.get('remember') else False

        try:
            conn = get_db_connection()
            cur = conn.cursor()

            # Query the user by username with explicit column selection
            cur.execute('''
                SELECT id, "firstName", surname, email, "userName", password, "isActive", role
                FROM public.users
                WHERE "userName" = %s
            ''', (username,))
            user = cur.fetchone()

            if user is None:
                flash('Invalid username or password', 'error')
                return redirect(url_for('login'))

            # Check if account is active
            if not user[6]:  # "isActive" is the 7th column
                flash('Your account is not yet activated. Please wait for admin approval.', 'warning')
                return redirect(url_for('login'))

            # Verify password
            if check_password_hash(user[5], password):
                # Create User object and log them in
                user_obj = User(id=user[0], first_name=user[1], last_name=user[2],
                               email=user[3], username=user[4], role=user[7])
                login_user(user_obj, remember=remember)

                flash(f'Welcome back, {user[1]}!', 'success')

                # Redirect based on role
                if user[7] == 'admin':
                    return redirect(url_for('users'))
                elif user[7] == 'doctor':
                    return redirect(url_for('predict'))
                elif user[7] == 'nurse':
                    return redirect(url_for('predict'))
                else:
                    return redirect(url_for('home'))
            else:
                flash('Invalid username or password', 'error')
                return redirect(url_for('login'))

        except Exception as e:
            print(f"Login error: {str(e)}")
            flash('Login failed. Please try again.', 'error')
            return redirect(url_for('login'))

        finally:
            if 'cur' in locals(): cur.close()
            if 'conn' in locals(): conn.close()

    return render_template('login.html')


# Load model and scaler
try:
    model = joblib.load("diabetes_prediction_model.sav")
    scaler = joblib.load("scaler.sav")
except Exception as e:
    print(f"Error loading model/scaler: {str(e)}")
    exit()




@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))




def role_required(role_name):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('login'))

            if current_user.role != role_name:
                flash('You do not have permission to access this page.', 'error')
                return redirect(url_for('login'))

            return f(*args, **kwargs)

        return decorated_function

    return decorator





@app.route("/predict", methods=["POST","GET"])
@role_required('doctor')
@login_required  # This is actually redundant now since role_required checks authentication
def predict():
    result = None
    confidence = None
    result_class = None
    form_data = {}  # To preserve user input
    
    try:
        # Store form data for repopulation
        form_data = {
            'age': request.form.get('age', ''),
            'hypertension': request.form.get('hypertension', ''),
            'heart_disease': request.form.get('heart_disease', ''),
            'bmi': request.form.get('bmi', ''),
            'HbA1c_level': request.form.get('HbA1c_level', ''),
            'blood_glucose_level': request.form.get('blood_glucose_level', ''),
            'smoking_history': request.form.get('smoking_history', ''),
            'gender': request.form.get('gender', '')
        }

        # Create dictionary for model prediction
        feature_dict = {
            'age': float(form_data['age']),
            'hypertension': float(form_data['hypertension']),
            'heart_disease': float(form_data['heart_disease']),
            'bmi': float(form_data['bmi']),
            'HbA1c_level': float(form_data['HbA1c_level']),
            'blood_glucose_level': float(form_data['blood_glucose_level']),
            'smoking_history_encoded': float(form_data['smoking_history']),
            'gender_encoded': float(form_data['gender'])
        }
        
        FEATURE_NAMES = [
            'age', 'hypertension', 'heart_disease', 'bmi',
            'HbA1c_level', 'blood_glucose_level',
            'smoking_history_encoded', 'gender_encoded'
        ]
        
        features_df = pd.DataFrame([feature_dict], columns=FEATURE_NAMES)
        scaled_features = scaler.transform(features_df)
        
        prediction = model.predict(scaled_features)
        confidence = np.max(model.predict_proba(scaled_features)) * 100
        result = "Diabetic" if prediction[0] == 1 else "Non-Diabetic"
        result_class = "diabetic" if prediction[0] == 1 else "non-diabetic"

    except ValueError as ve:
        result = f"Invalid input: Please check all fields contain valid numbers"
        result_class = "error"
    except Exception as e:
        result = f"System error: {str(e)}"
        result_class = "error"
    
    return render_template("prediction.html",
                        prediction_text=result,
                        result_class=result_class,
                        confidence=confidence,
                        show_result=True,
                        form_data=form_data)  # Pass form data back to template




def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please login to access this page.', 'warning')
            return redirect(url_for('login'))
        if current_user.role != 'admin':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('home'))  # or abort(403)
        return f(*args, **kwargs)
    return decorated_function



@app.route('/users', methods=['GET'])
@login_required
@admin_required
def users():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('''
            SELECT id, "firstName", surname, email, "userName", "isActive", role
            FROM public.users
            ORDER BY id
        ''')
        columns = [desc[0] for desc in cur.description]
        users1 = [dict(zip(columns, row)) for row in cur.fetchall()]
        return render_template('users.html', users=users1)

    except Exception as e:
        print("Error:", str(e))
        flash(f'Error fetching users: {str(e)}', 'danger')
        return render_template('users.html', users=[])
    finally:
        if 'cur' in locals(): cur.close()
        if 'conn' in locals(): conn.close()


@app.route('/toggle_user_status/<int:user_id>', methods=['POST'])
@login_required  
def toggle_user_status(user_id):
    if not current_user.is_authenticated or current_user.role != 'admin':
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # First check if user is admin
        cur.execute('SELECT role FROM public.users WHERE id = %s', (user_id,))
        user = cur.fetchone()

        if not user:
            return jsonify({'success': False, 'error': 'User not found'}), 404

        if user[0] == 'admin':
            return jsonify({'success': False, 'error': 'Cannot modify admin status'}), 400

        # Get current status
        cur.execute('SELECT "isActive" FROM public.users WHERE id = %s', (user_id,))
        result = cur.fetchone()
        current_status = result[0]
        new_status = not current_status

        # Update status
        cur.execute('UPDATE public.users SET "isActive" = %s WHERE id = %s',
                    (new_status, user_id))
        conn.commit()

        return jsonify({
            'success': True,
            'new_status': new_status,
            'new_status_text': 'Active' if new_status else 'Inactive',
            'new_badge_class': 'bg-success' if new_status else 'bg-secondary'
        })

    except Exception as e:
        if conn: conn.rollback()
        print("Error:", str(e))
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur: cur.close()
        if conn: conn.close()





@app.route('/delete_user/<int:user_id>', methods=['POST'])
@login_required  
def delete_user(user_id):
    if not current_user.is_authenticated or current_user.role != 'admin':
        return jsonify({'success': False, 'error': 'Unauthorized'}), 403

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        # First check if user exists
        cur.execute('SELECT id FROM public.users WHERE id = %s', (user_id,))
        if not cur.fetchone():
            return jsonify({'success': False, 'error': 'User not found'}), 404

        # Delete the user
        cur.execute('DELETE FROM public.users WHERE id = %s', (user_id,))
        conn.commit()

        return jsonify({
            'success': True,
            'message': 'User deleted successfully',
            'user_id': user_id
        })

    except Exception as e:
        if conn: conn.rollback()
        print("Error:", str(e))
        return jsonify({'success': False, 'error': str(e)}), 500
    finally:
        if cur: cur.close()
        if conn: conn.close()







if __name__ == "__main__":

    print("\n\033[1mAttempting to connect to database...\033[0m")
    try:
        # Test connection
        test_conn = get_db_connection()
        test_conn.close()

        # Start Flask app
        print("\n\033[1mStarting Flask application...\033[0m")
        # app.run(debug=True)
        app.run(host='0.0.0.0', debug=True)
    except Exception as e:
        print("\n\033[91mFailed to start application due to database connection error\033[0m")


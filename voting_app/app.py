import os
from datetime import datetime, timezone, timedelta
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import pytz

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev')  # Use environment variable in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///voting.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Add context processor to make 'now' available to all templates
@app.context_processor
def inject_now():
    return {'now': datetime.now(timezone.utc)}

# --- Models ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    role = db.Column(db.String(10), default='user')  # 'admin' or 'user'
    votes = db.relationship('Vote', backref='user', lazy=True)

class VotingEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    is_closed = db.Column(db.Boolean, default=False)
    options = db.relationship('Option', backref='event', lazy=True)
    votes = db.relationship('Vote', backref='event', lazy=True)

    def get_total_votes(self):
        return sum(option.votes for option in self.options)

class Option(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('voting_event.id'), nullable=False)
    option_text = db.Column(db.String(150), nullable=False)
    votes = db.Column(db.Integer, default=0)
    vote_records = db.relationship('Vote', backref='option', lazy=True)

class Vote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('voting_event.id'), nullable=False)
    option_id = db.Column(db.Integer, db.ForeignKey('option.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

# --- User Loader ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def init_db():
    with app.app_context():
        # Drop all tables
        db.drop_all()
        # Create all tables
        db.create_all()
        # Create a default admin if one doesn't exist
        if not User.query.filter_by(username="admin").first():
            admin = User(username="admin", password=generate_password_hash("adminpass"), role="admin")
            db.session.add(admin)
            db.session.commit()
            print("Created default admin user")
        print("Database initialized successfully")

def get_current_time():
    """Get current time in UTC"""
    return datetime.now(timezone.utc)

def make_timezone_aware(dt):
    """Convert naive datetime to UTC timezone-aware datetime"""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt

def convert_to_local(dt):
    """Convert UTC datetime to local time (UTC-5)"""
    if dt is None:
        return None
    local_tz = timezone(timedelta(hours=-5))
    return dt.astimezone(local_tz)

# --- Routes ---
@app.route('/')
def index():
    events = VotingEvent.query.all()
    now = get_current_time()
    # Make sure all event times are timezone-aware
    for event in events:
        event.created_at = make_timezone_aware(event.created_at)
    return render_template('index.html', events=events, now=now)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if len(username) < 3:
            flash('Username must be at least 3 characters long.')
            return redirect(url_for('register'))
        if len(password) < 6:
            flash('Password must be at least 6 characters long.')
            return redirect(url_for('register'))
        if User.query.filter_by(username=username).first():
            flash('Username already exists.')
            return redirect(url_for('register'))
        new_user = User(username=username, password=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            flash('Logged in successfully.')
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials.')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out.')
    return redirect(url_for('index'))

# --- Admin Routes ---
@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        flash('Access denied.')
        return redirect(url_for('index'))
    events = VotingEvent.query.all()
    now = get_current_time()
    # Make sure all event times are timezone-aware
    for event in events:
        event.created_at = make_timezone_aware(event.created_at)
    return render_template('admin_dashboard.html', events=events, now=now)

@app.route('/admin/create', methods=['GET', 'POST'])
@login_required
def create_event():
    if current_user.role != 'admin':
        flash('Access denied.')
        return redirect(url_for('index'))
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        
        options_text = request.form['options']
        if not options_text.strip():
            flash('Please provide at least one option.')
            return redirect(url_for('create_event'))
        
        event = VotingEvent(
            title=title,
            description=description
        )
        db.session.add(event)
        db.session.commit()
        
        # Add each option
        for opt in options_text.split(','):
            if opt.strip():
                option = Option(event_id=event.id, option_text=opt.strip())
                db.session.add(option)
        db.session.commit()
        
        flash('Event created successfully.')
        return redirect(url_for('admin_dashboard'))
    return render_template('create_event.html')

@app.route('/admin/close/<int:event_id>', methods=['POST'])
@login_required
def close_event(event_id):
    if current_user.role != 'admin':
        flash('Access denied.')
        return redirect(url_for('index'))
    event = VotingEvent.query.get_or_404(event_id)
    event.is_closed = True
    db.session.commit()
    flash('Event closed.')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/delete/<int:event_id>', methods=['POST'])
@login_required
def delete_event(event_id):
    if current_user.role != 'admin':
        flash('Access denied.')
        return redirect(url_for('index'))
    
    event = VotingEvent.query.get_or_404(event_id)
    
    # Delete all votes associated with this event
    Vote.query.filter_by(event_id=event_id).delete()
    
    # Delete all options associated with this event
    Option.query.filter_by(event_id=event_id).delete()
    
    # Delete the event itself
    db.session.delete(event)
    db.session.commit()
    
    flash('Event deleted successfully.')
    return redirect(url_for('admin_dashboard'))

# --- User Voting & Results ---
@app.route('/event/<int:event_id>')
@login_required
def event_detail(event_id):
    event = VotingEvent.query.get_or_404(event_id)
    
    # Check if voting is allowed (event is not closed)
    can_vote = not event.is_closed
    
    # Check if user has already voted
    voted = Vote.query.filter_by(event_id=event.id, user_id=current_user.id).first() is not None
    
    print(f"\nVoting Status:")
    print(f"  Event ID: {event_id}")
    print(f"  Event Title: {event.title}")
    print(f"  Event closed: {event.is_closed}")
    print(f"  Can vote: {can_vote}")
    print(f"  User voted: {voted}")
    print(f"  Current user: {current_user.id} ({current_user.username})")
    print("=====================================\n")
    
    return render_template('vote.html', 
                         event=event, 
                         can_vote=can_vote, 
                         voted=voted)

@app.route('/vote/<int:event_id>', methods=['POST'])
@login_required
def vote(event_id):
    event = VotingEvent.query.get_or_404(event_id)
    
    # Check if voting is allowed
    if event.is_closed:
        print("Vote attempt - Failed: Event is closed")
        flash('This event is closed for voting.', 'error')
        return redirect(url_for('event_detail', event_id=event_id))
    
    # Check if user has already voted
    existing_vote = Vote.query.filter_by(event_id=event_id, user_id=current_user.id).first()
    if existing_vote:
        print(f"Vote attempt - Failed: User {current_user.id} has already voted")
        flash('You have already voted in this event.', 'error')
        return redirect(url_for('event_detail', event_id=event_id))
    
    # Get the selected option from the form
    selected_option_id = request.form.get('option_id')
    print(f"Vote attempt - Selected option ID: {selected_option_id}")
    
    if not selected_option_id:
        print("Vote attempt - Failed: No option selected")
        flash('Please select an option to vote.', 'error')
        return redirect(url_for('event_detail', event_id=event_id))
    
    # Verify the selected option belongs to this event
    option = Option.query.filter_by(id=selected_option_id, event_id=event_id).first()
    if not option:
        print(f"Vote attempt - Failed: Invalid option {selected_option_id} for event {event_id}")
        flash('Invalid option selected.', 'error')
        return redirect(url_for('event_detail', event_id=event_id))
    
    try:
        # Record vote with UTC timestamp
        vote = Vote(
            user_id=current_user.id,
            event_id=event_id,
            option_id=selected_option_id,
            timestamp=datetime.now(timezone.utc)
        )
        db.session.add(vote)
        # Increment vote count
        option.votes += 1
        db.session.commit()
        print(f"Vote attempt - Success: User {current_user.id} voted for option {selected_option_id}")
        flash('Your vote has been recorded successfully.', 'success')
    except Exception as e:
        db.session.rollback()
        print(f"Vote attempt - Error: {str(e)}")
        flash('An error occurred while recording your vote. Please try again.', 'error')
    
    return redirect(url_for('event_detail', event_id=event_id))

@app.route('/results/<int:event_id>')
@login_required
def results(event_id):
    event = VotingEvent.query.get_or_404(event_id)
    
    # Results are viewable only if event is closed
    if not event.is_closed:
        flash('Results are not available until the event is closed.')
        return redirect(url_for('event_detail', event_id=event_id))
    
    # Sort options by vote count in descending order
    sorted_options = sorted(event.options, key=lambda x: x.votes, reverse=True)
    total_votes = event.get_total_votes()
    
    return render_template('results.html', event=event, sorted_options=sorted_options, total_votes=total_votes)

if __name__ == '__main__':
    init_db()  # Initialize the database
    app.run(debug=True)

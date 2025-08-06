import os # Make sure os is imported
from dotenv import load_dotenv
load_dotenv()
from flask import Flask, request, render_template, send_from_directory, flash, redirect
from werkzeug.utils import secure_filename

# Import our main processing function from our logic file
# We give it an alias to make it clear what it does
from reddact import process_file as process_redaction_file

# --- Flask App Configuration ---
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'docx', 'json', 'xml'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# A secret key is required by Flask to show user messages ("flashing")
app.secret_key = os.environ.get('FLASK_SECRET_KEY')

def allowed_file(filename):
    """Checks if the uploaded file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# --- Web Page Routes ---
@app.route('/')
def index():
    """This function runs when a user visits the main page. It just shows the HTML."""
    return render_template('index.html')

@app.route('/process', methods=['POST'])
def process_upload():
    if 'file' not in request.files:
        flash('No file part in the request. Please try again.', 'error')
        return redirect('/')
        
    file = request.files['file']
    
    if file.filename == '':
        flash('No file selected. Please choose a file to upload.', 'error')
        return redirect('/')
        
    if file and allowed_file(file.filename):
        redaction_type = request.form.get('redaction_type', 'blackout')
        filename = secure_filename(file.filename)
        upload_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(upload_path)
        
        try:
            redacted_filename = process_redaction_file(upload_path, redaction_type)
            return send_from_directory('.', redacted_filename, as_attachment=True)
            
        except Exception as e:
            flash(f'An error occurred during processing: {e}', 'error')
            return redirect('/')
    else:
        flash('File type not allowed. Please upload a supported file.', 'error')
        return redirect('/')

# --- Main Execution Block ---
if __name__ == '__main__':
    # Ensure the upload folder exists before starting the app
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    # Run the Flask web server. debug=True allows it to auto-reload when you save changes.
    app.run(host='0.0.0.0', port=5000, debug=True)
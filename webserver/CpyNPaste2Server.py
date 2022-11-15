import functools
from werkzeug.security import check_password_hash, generate_password_hash




@app.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        age = request.form['age']
        occupation = request.form['occupation']
        zipcode = request.form['zipcode']


        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'
        elif not firstname:
            error = 'First Name is required.'
        elif not lastname:
            error = 'Last Name is required'
        elif not age:
            error = 'Age is required'
        elif not age.isdigit():
            error = 'Age must be an integer'
        elif not occupation:
            error = 'Occupation is required'
        elif not zipcode:
            error = 'Zipcode is required'
        elif not zipcode.isdigit():
            error = 'Zipcode must be an integer'

        if error is None:
            try:
                g.conn.execute(
                    "INSERT INTO user (username, password, firstname, lastname, age, occupation, zipcode) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (username, generate_password_hash(password), firstname, lastname, int(age), occupation, int(zipcode)),
                )
                
            except g.IntegrityError:
                error = f"User {username} is already registered."
            else:
                return redirect(url_for("auth.login"))

        flash(error)

    return render_template('auth/register.html')

@app.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = g.conn.execute(
            'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()

        if user is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))

        flash(error)

    return render_template('auth/login.html') 

@app.before_app_request
def load_logged_in_user():
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = g.conn.execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view
from flask import Flask, render_template, request, url_for, redirect, json, session, g, flash, make_response
import os
import subprocess
import secureCrypt
import hashlib, re, binascii

__author__ = "Andre C (@cyberPh0be)" #My first CTF publishing, please be nice!!! :)
__contact__ = "github: @cyberPhobe"

app = Flask(__name__)
app.secret_key = ' '
#app.debug = True
safe = True

'''         
       _ _,---._
   ,-','       `-.___
  /-;'               `._
 /\/          ._   _,'o \
( /\       _,--'\,','"`. )           Mmmmmm, spaghetti code
 |\      ,'o     \'    //\
 |      \        /   ,--'""`-.
 :       \_    _/ ,-'         `-._
  \        `--'  /                )
   `.  \`._    ,'     ________,','
     .--`     ,'  ,--` __\___,;'
      \`.,-- ,' ,`_)--'  /`.,'
       \( ;  | | )      (`-/
         `--'| |)       |-/
           | | |        | |
           | | |,.,-.   | |_
           | `./ /   )---`  )
          _|  /    ,',   ,-'
         ,'|_(    /-<._,' |--,
         |   .`--'---.     \/ \
         |  o   ,   / \    /\  \
       ,-^---._     |  \  /  \  \
    ,-'        \----'   \/    \--`.
   /            \              \   \
'''

@app.errorhandler(404)
def notFound(e):
    return render_template('not_found.html'), 404

@app.route('/', methods=['GET', 'POST'])
def home():
    output="empty" 
    #On POST, process form
    if request.method == 'POST':
        cmd = request.form['text']
        try:
            output = subprocess.check_output(cmd, shell=safe)
            output = output.decode('utf-8')
        
        except Exception as e:
            output = "Error running command\n" + str(e)
    return render_template('index.html', output=output)

@app.route('/login', methods=['GET','POST'])
def login():
    if session.get('user') and request.method == 'GET':
        return redirect(url_for('loggedin'))

    if request.method == 'POST':
        SITE_ROOT = os.path.realpath(os.path.dirname(__file__))
        jsonObj = os.path.join(SITE_ROOT, "static/docs", "users.json")
        data = json.load(open(jsonObj))
        session.pop('user', None)
        user = request.form['username']
        password = secureCrypt.encrypt(request.form['password'])
        
        for userJson in data:
            if user == userJson['Name'] and secureCrypt.decrypt(userJson['Password']) == secureCrypt.decrypt(password):
                session['user'] = request.form['username']
                return redirect(url_for('loggedin'))
            
        flash("Incorrect username/password combo", 'error')
    return render_template('login.html')

@app.route('/loggedin', methods=['GET','POST'])
def loggedin():
    if request.method == 'POST':
        if not session.get('user'):
            flash('You must be logged in to change your password.', 'error')
            return redirect(url_for('login'))

        else:
            SITE_ROOT = os.path.realpath(os.path.dirname(__file__))
            jsonObj = os.path.join(SITE_ROOT, "static/docs", "users.json")
            data = json.load(open(jsonObj))

            user=session.get('user')
            oldpass = secureCrypt.encrypt(request.form['oldpassword'])

            for userJson in data:
                if user == userJson['Name'] and secureCrypt.decrypt(userJson['Password']) == secureCrypt.decrypt(oldpass):
                    userJson['Password'] = secureCrypt.encrypt(request.form['password'])
                    flash('Password would usually be updated, but this is a CTF!', 'success')
                    break

                else:       
                    #Logic/Indenting is fun. What's the security issue with this?
                    if any (word in userJson['Name'] for word in ['script', 'wctf', 'kernel']):
                        pass
                    else:
                        flash('Error updating password for user: %s' % userJson['Name'])

        return redirect(url_for('login'))
    if g.user:
        return render_template('loggedin.html', user=session['user'])
    return redirect(url_for('login'))

@app.before_request
def before_request():
    g.user = None
    if 'user' in session:
        g.user = session['user']

@app.route('/logout')
def logout():
    session.pop('user', None)
    return render_template('logout.html')

@app.route('/employees')
def employees():
    return render_template('employees.html')

@app.route('/portal')
def ptoAdmin():
    if not session.get('user'):
        flash('You must be logged in to see the portal.', 'error')
        return redirect(url_for('login'))

    SITE_ROOT = os.path.realpath(os.path.dirname(__file__))
    jsonObj = os.path.join(SITE_ROOT, "static/docs", "users.json")
    data = json.load(open(jsonObj))
    
    for userJson in data:
        if userJson.get('Name') == session.get('user'):
            if not userJson.get('userType') == 'employee':
                flash('You must be an employee to access this page', 'error')
                return redirect(url_for('login'))
    
    return render_template('portal.html')

@app.route('/clientMemo')
def customerMemo():
    return render_template('clientMemo.html')

@app.route('/employeeHoliday')
def employeeHoliday():
    return render_template('employeeHoliday.html')

@app.route('/shutdown')
def shutdownStore():
    return render_template('shutdown.html')

@app.route('/w2')
def w2():
    return render_template('w2.html')

@app.route('/ceoMessage')
def ceoMessage():
    return render_template('ceoMessage.html')

@app.route('/covid19')
def covid19():
    panic = True
    return render_template('covid19.html')

@app.route('/flag')
def flag():
    return render_template('flag.html')

@app.route('/flag.html')
def flag2():
    return render_template('flag.html')

@app.route('/flag.php')
def flag3():
    return render_template('php.html')

@app.route('/llehs', methods=['GET', 'POST'])
def llehs():
    out="empty" 
    banned = ["vim", "nano", "pico", "adduser"]
    banned2 = ["flaskApp", "cp", "nc", "mv", "echo", "perl", 'os', 'subprocess',"f*","flask*","*App"]
    #On POST, process form
    if request.method == 'POST':
        llehs = request.form['command']
        if any(x in llehs for x in banned or banned2):
            out="WARNING: you cannot use interactive programs. This will hang your connection!"
        if any(x in llehs for x in banned2):
            out="You're running a command that we're not allowing for this event"
        else:
            try:
                out = subprocess.check_output(llehs, shell=True)
                out = out.decode('utf-8')
            
            except Exception as e:
                out = "Error running command\n" + str(e)
    return render_template('file.html', output=out)

@app.route('/testing')
def testing():
    print(session.get('user'))
    return render_template('testing.html')

@app.route('/bulletin')
def board():
    return render_template('bulletin.html')

@app.route('/better-login-demo', methods=['GET','POST'])
def demoSite():
    if g.user:
        if hashlib.sha256(session.get('user').encode()).hexdigest() != "7840884a738ddbc6229bb42f2780c413823402ec98cb2fa6af5b0228a2b608ec" and hashlib.sha256(session.get('user').encode()).hexdigest() != "c4c2dfe245b0b4ba4e4578da68ae7f92f99cf8d5957e736dc792948919744c9c":
            print("invalid user")
            print(hashlib.sha256(session.get('user').encode()).hexdigest())
            session.pop('user', None)
            return render_template('cookies.html')
        else:
            print("This is the current user session: %s" % (session.get('user')))
            return render_template('cookieViewer.html', user=session['user'])

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_pass = hashlib.sha256(password.encode()).hexdigest()
        hashed_username = hashlib.sha256(username.encode()).hexdigest()

        #step 1
        if hashed_pass == 'f24cff29bd141f5ad4ecd0b389a57c9ed8a350ad94bdbf7b46e3c8f42517831a' and hashed_username == "7840884a738ddbc6229bb42f2780c413823402ec98cb2fa6af5b0228a2b608ec":
            session['user'] = username
            resp = make_response(render_template('cookieWindow.html', user=session['user']))
            resp.set_cookie('authenticated', 'eyJhZG1pblVzZXIiOiJhZG1pbmlzdHJhdG9yRlRXIiwgImVuY29kZWRIYXNoIjoiTW1ReE1XSTRPR0psWlRKaU9HUmpZVGd3TjJFek5qaGxOV1k0T0dKaU1XWXpNVEptT1RVeFpESXlPRGhsWTJRME1qSTBOVE13WkRFd1ltWmhZVEppTUE9PSIsICJoYXNoaW5nQWxnb3IiOiJzaGEyNTYifQ==')
            return resp

        #step 2
        if hashed_pass == '2d11b88bee2b8dca807a368e5f88bb1f312f951d2288ecd4224530d10bfaa2b0' and hashed_username == "c4c2dfe245b0b4ba4e4578da68ae7f92f99cf8d5957e736dc792948919744c9c" or request.cookies.get('adminEscalatedCarryOn'):
            session['user'] = username
            resp = make_response(redirect(url_for('tastyCookie')))
            resp.set_cookie('adminEscalatedCarryOn', 'eyJodW5ncnk0Y29va2llcyI6ImZhbHNlIiwgImFsbW9zdFRhc3R5Q29va2llIjoidHJ1ZSIsICJtYW5pcHVsYXRlZENvb2tpZSI6ImZhbHNlIn0=')
            return resp
        
        else:
            flash("Incorrect username or password combo", 'error')
            return render_template('cookies.html')
    else:
        #change displayed page between the users
        return render_template('cookies.html')

@app.route('/tastyCookie', methods=['GET','POST'])
def tastyCookie():
    try:
        set_name = session.get('user')
        if request.method == 'POST':         
            if set_name == None:
                raise ValueError("Your session is unstable. Please try again")
            if not request.cookies.get('adminEscalatedCarryOn') and hashlib.sha256(set_name.encode()).hexdigest() == 'c4c2dfe245b0b4ba4e4578da68ae7f92f99cf8d5957e736dc792948919744c9c':
                raise ValueError("Cookie is missing ingredients :(")
            cookie =  request.cookies.get('adminEscalatedCarryOn')
            if hashlib.sha256(cookie.encode()).hexdigest() == '36dc926ecf53c8dcd08a3890be817859da58a2f62c7c867406608e8d8924d9c2':
                flash('This cookie is, indeed, delicious!!', 'success')
                flash('The flag is:','success')
                flash('kernel{<2nd user\'s name>_<2nd user\'s password>_<hungry4cookies value>_<manipulatedCookie value>}', 'success')
                flash('REPLACE VALUES ABOVE WITH ANSWERS TO CHALLENGE!','warning') 
                flash('Example, "<2nd user\'s name>" would be "Alice" (no quotes; if it is Alice)', 'warning')
                flash('All words separated by underscore ("_")!!','warning')
                return render_template('cookies_are_tricky.html', name=set_name, success="true")
            else:
                flash('This doesn\'t taste quite right yet...', 'error')
                return redirect(url_for('tastyCookie'))
            return render_template('cookies_are_tricky.html')

        return render_template('cookies_are_tricky.html')
    except ValueError as value_err:
        flash(value_err.args[0], 'error')
        return redirect(url_for('tastyCookie'))
    except Exception as e:
        import traceback
        print(traceback.print_exc())
        flash('Invalid cookie', 'error')
        return redirect(url_for('tastyCookie'))

@app.route('/deleteCookie', methods=['GET','POST'])
def betterLogout():
    if request.method == 'POST':
        resp = make_response(redirect(url_for('demoSite')))
        resp.set_cookie("authenticated", "", expires=0)
        session.pop('user', None)
        return resp
    else:
        return render_template('cookieLogout.html')

@app.route('/deleteTastyCookie', methods=['GET','POST'])
def betterTastyLogout():
    if request.method == 'POST':
        resp = make_response(redirect(url_for('demoSite')))
        resp.set_cookie("adminEscalatedCarryOn", "", expires=0)
        session.pop('user', None)
        return resp
    else:
        return render_template('cookieTastyLogout.html')

@app.route('/checkCookie')
def cookieValue():
    try:
        set_name = session.get('user')
        if set_name == None:
            raise ValueError("Login First")
        if not request.cookies.get('authenticated') and hashlib.sha256(set_name.encode()).hexdigest() == '7840884a738ddbc6229bb42f2780c413823402ec98cb2fa6af5b0228a2b608ec':
            raise ValueError("Cookie is missing ingredients :(")
        if request.cookies.get('adminEscalatedCarryOn') and hashlib.sha256(set_name.encode()).hexdigest() == 'c4c2dfe245b0b4ba4e4578da68ae7f92f99cf8d5957e736dc792948919744c9c':
                raise ValueError("Destroy your session, you went back to step 1 and cannot obtain flag")
        else:
            flash('Still tastes like a cookie!', 'success')
            return render_template('cookieViewer.html', user=set_name)
    
    except ValueError as value_err:
        flash(value_err.args[0], 'error')
        return redirect(url_for('demoSite'))
    except Exception as e:
        import traceback
        print(traceback.print_exc())
        flash('Invalid cookie', 'error')
        return redirect(url_for('demoSite'))

@app.route('/addUser', methods=['GET','POST'])
def addUser():

    if request.method == 'POST':
        #Logic to create user
        SITE_ROOT = os.path.realpath(os.path.dirname(__file__))
        jsonObj = os.path.join(SITE_ROOT, "static/docs", "users.json")
        data = json.load(open(jsonObj))

        newUser = request.form['username']
        newPassword = secureCrypt.encrypt(request.form['password'])
        userType = request.form['usertype']    
        uuid = hashlib.sha1(newUser.lower().encode()).hexdigest()
        hr = request.form['isHR']

        if userType == 'employee':
            vaycay = "50"
        else:
            vaycay = "NaN"

        if 'script' in newUser:
            flash('Hacker no hacking', 'error')
            return render_template('addUser.html')
        
        if userType == '3567':
            isHR = next((item for item in data if item["Name"] == session.get('user')), None)

            #Logic broken down to prevent None-type errors
            if session.get('user') != None:
                if session.get('user') == fdsi(b'ZmxlbmRlcnNvbg==').decode('utf-8') or isHR.get('isHR') == 'true':
                    err = secureCrypt.decrypt(fdsi(b'fTJZRkY4M1o4S1QySUdHVzEwTkk3OEYzRks2MUkwSDkyNUY2M0cxe1FKU1dKUA==').decode())
                    
                    flash('Welcome HR member! Here\'s your reward', 'success')
                    return render_template('addUser.html', err=err)
                else:
                    err= "This is where the flag will be displayed"
                    flash('Keep enumerating users! Only Human Resources can obtain this flag', 'error')
                    return render_template('addUser.html', err=err)
            else:
                err= "This is where the flag will be displayed"
                flash('Keep enumerating users! Only Human Resources can obtain this flag', 'error')
                return render_template('addUser.html', err=err)
        
        if (len(newUser) == 0 or len(newPassword) == 0) and userType != '3567':
            print("%s %s" % (newUser, newPassword))
            flash("Can't create user with blank username or password", 'error')
            return render_template('addUser.html')

        if hr != 'false' and hr != 'true':
            flash("Incorrect status for hr", 'error')
            return render_template('addUser.html')

        for userJson in data:
            if newUser == userJson["Name"]:
                flash('UserID already exists!', 'error')
                return redirect(url_for('addUser'))
        
            if uuid == userJson["uuid"]:
                flash('Unique User ID already assigned!', 'error')
                return redirect(url_for('addUser'))
                    
        userdict = {"Name": newUser, "Password": newPassword, "VacayDays": vaycay, "userType": userType, "uuid": uuid, "isHR": hr.lower()}
        data.append(userdict)

        with open(jsonObj, 'w+') as f:
            json.dump(data, f)
        
        flash('User created', 'success')
        return redirect(url_for('addUser'))
        panic = True
    return render_template('addUser.html')

@app.route('/help')
def help():
    return render_template('help.html')

def fdsi(fdsa, fsd=None, asf=False):
 
    fdsa = _bytes_from_decode_data(fdsa)
    if fsd is not None:
        fsd = _bytes_from_decode_data(fsd)
        assert len(fsd) == 2, repr(fsd)
        fdsa = fdsa.translate(bytes.maketrans(fsd, b'+/'))
    if asf and not re.fullmatch(b'[A-Za-z0-9+/]*={0,2}', fdsa):
        raise binascii.Error('Non-base64 digit found')
    return binascii.a2b_base64(fdsa)

bytes_types = (bytes, bytearray) 

def _bytes_from_decode_data(s):
    if isinstance(s, str):
        try:
            return s.encode('ascii')
        except UnicodeEncodeError:
            raise ValueError('string argument should contain only ASCII characters')
    if isinstance(s, bytes_types):
        return s
    try:
        return memoryview(s).tobytes()
    except TypeError:
        raise TypeError("argument should be a bytes-like object or ASCII "
                        "string, not %r" % s.__class__.__name__) from None

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)

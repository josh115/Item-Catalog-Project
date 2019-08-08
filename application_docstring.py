#!/usr/bin/env python2.7

from flask import (
   Flask,
   render_template,
   request,
   redirect,
   jsonify,
   url_for
)
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Category, Item
from flask import session as login_session
import random
import string
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']

app = Flask(__name__)

# Connect to Database and create database session
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()
categories = session.query(Category).order_by(asc(Category.name))


# User Helper Functions

def createUser(login_session):
    """Creates a new user in database.
    
    Args:
        login_session: session object with user data.

    Returns:
        on found: user.id: Unique id of the new user.
        on not found: None.
    """
    newUser = User(name=login_session['username'],
                   email=login_session['email'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserID(email):
    """Checks if user exists.
    
    Args:
        email: email of the user.

    Returns:
        user.id: Unique id of the new user.
    """
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except Exception as e:
        return None


@app.route('/')
def Main():
    """Displays the home page to the user with the items in the catalog.
    
    Returns:
        on GET: Page displaying latest items.
    """
    items = session.query(Item).order_by(Item.id)
    return render_template('index.html', categories=categories,
                           items=items, user=login_session)

# Show items in a category
@app.route('/catalog/<string:category_name>/items/')
def ShowCategory(category_name):
    """Displays the items in the selected category
    
    Args:
        category_name: The selected category.

    Returns:
        on GET: Page displaying items in that category.
    """
    category_name = category_name.replace("%20", " ")
    category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(Item).filter_by(category_id=category.id).all()
    return render_template('category.html', items=items,
                           category=category, categories=categories,
                           user=login_session)

# CRUD tasks

# Create Item
@app.route('/catalog/add/', methods=['GET', 'POST'])
def AddItem():
    """Adds a new item to the database

    Returns:
        on GET: Page displaying items in that category.
        on POST: Redirect to main page if item is added
        Redirect to login page if user not logged in
    """
    # check if user is logged in
    if 'username' not in login_session:
        return redirect(url_for('Login'))
    elif request.method == 'POST':
        ItemToAdd = Item(
            name=request.form['name'],
            description=request.form['description'],
            category_id=request.form['category'],
            user_id=login_session['user_id']
        )
        session.add(ItemToAdd)
        session.commit()
        return redirect(url_for('Main'))
    return render_template('itemadd.html', categories=categories,
                           user=login_session)

# Read Item
@app.route('/catalog/<string:category_name>/<string:item_name>/')
def ShowItem(item_name, category_name):
    """Display the selected item.
    
    Args:
        category_name: The selected items category.
        item_name: The selected item.

    Returns:
        on GET: Page displaying items data.
    """
    item_name = item_name.replace("%20", " ")
    item = session.query(Item).filter_by(name=item_name).one()
    # check if user is logged in and item belongs to that user
    if 'username' not in login_session:
        return render_template('item.html', item=item, owner=False,
                               user=login_session)
    elif item.user_id != login_session['user_id']:
        return render_template('item.html', item=item, owner=False,
                               user=login_session)
    else:
        return render_template('item.html', item=item, owner=True,
                               user=login_session)

# Update Item
@app.route('/catalog/<string:item_name>/edit/', methods=['GET', 'POST'])
def EditItem(item_name):
    """Edit the selected item.
    
    Args:
        item_name: The selected item.

    Returns:
        on GET: Page to edit item.
        on POST: Redirect to main page if item is added to database.
        Redirect to login page if user not logged in.
        Redirect to main page if user is not owner.
    """
    item_name = item_name.replace("%20", " ")
    item = session.query(Item).filter_by(name=item_name).one()
    # check if user is logged in and item belongs to that user
    if 'username' not in login_session:
        return redirect(url_for('Login'))
    elif item.user_id != login_session['user_id']:
        return redirect(url_for('Main'))
    else:
        if request.method == 'POST':
            if request.form['name']:
                item.name = request.form['name']
            if request.form['description']:
                item.description = request.form['description']
            if request.form['category']:
                item.category_id = request.form['category']
            session.add(item)
            session.commit()
            return redirect(url_for('Main'))
        return render_template('itemedit.html', item=item,
                               categories=categories, user=login_session)

# Delete Item
@app.route('/catalog/<string:item_name>/delete', methods=['GET', 'POST'])
def DeleteItem(item_name):
    """Delete the selected item.
    
    Args:
        item_name: The selected item.

    Returns:
        on GET: Page to delete item.
        on POST: Redirect to main page if item is deleted.
        Redirect to login page if user not logged in.
        Redirect to main page if user is not owner.
    """
    item_name = item_name.replace("%20", " ")
    item = session.query(Item).filter_by(name=item_name).one()
    # check if user is logged in and item belongs to that user
    if 'username' not in login_session:
        return redirect(url_for('Login'))
    elif item.user_id != login_session['user_id']:
        return redirect(url_for('Main'))
    else:
        if request.method == 'POST':
            session.delete(item)
            session.commit()
            return redirect(url_for('Main'))
        return render_template('itemdelete.html', item=item,
                               user=login_session)

# Login user
@app.route('/login')
def Login():
    """Returns page where user can login in via google oauth
    
    Returns:
        on GET: Page to login.
    """
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state, user=login_session)

# Google login
@app.route('/gconnect', methods=['POST'])
def gconnect():
    """Gets user information from google and sets it to login_session
    
    Returns:
        on POST: Return welcome message is successful
        Return error message to page if error.
    """
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
            'Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    return "Welcome, %s" % login_session['username']

# Logout user
@app.route('/logout')
def Logout():
    """Logs the user out.
    
    Returns:
        on GET: Redirect to main page.
    """
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        return redirect(url_for('Main'))
    else:
        return redirect(url_for('Main'))

# DISCONNECT - Revoke a current user's token and reset their login_session

# Google logout
@app.route('/gdisconnect')
def gdisconnect():
    """Logs the user out if logged in with google.
    
    Returns:
        on GET: Error message to page if fails.
        Success message if status is 200.
    """
    # Only disconnect a connected user.
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


# JSON endpoints
# Shows all items in JSON format
@app.route('/catalog.json')
def ShowItemsJSON():
    """Displays all the category and items within in JSON
    
    Returns:
        on GET: JSON data of Category and items.
    """
    categoriesJSON = session.query(Category).order_by(Category.id)
    return jsonify(Category=[category.serializeItems
                   for category in categoriesJSON])

# Shows category and all items in the category in JSON format
@app.route('/catalog/<string:category_name>.json')
def ShowCategoryJSON(category_name):
    category_name = category_name.replace("%20", " ")
    categoryJSON = session.query(Category).filter_by(name=category_name).one()
    return jsonify(categoryJSON.serializeItems)

# Show item in JSON format
@app.route('/catalog/<string:category_name>/<string:item_name>.json')
def ShowItemJSON(category_name, item_name):
    category_name = category_name.replace("%20", " ")
    item_name = item_name.replace("%20", " ")
    itemJSON = session.query(Item).filter_by(name=item_name).one()
    return jsonify(itemJSON.serialize)


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)

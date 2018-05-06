from models import Base, User
from flask import Flask, jsonify, request, url_for, abort, g, render_template
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import create_engine

from flask.ext.httpauth import HTTPBasicAuth
import json

# NEW IMPORTS
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
from flask import make_response
import requests

auth = HTTPBasicAuth()

engine = create_engine('sqlite:///paleKale.db')

Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()
app = Flask(__name__)

CLIENT_ID = json.loads(
	open('client_secrets.json', 'r').read())['web']['client_id']


@auth.verify_password
def verify_password(username_or_token, password):
	# Try to see if it's a token first
	user_id = User.verify_auth_token(username_or_token)
	if user_id:
		user = session.query(User).filter_by(id=user_id).one()
	else:
		user = session.query(User).filter_by(
			username=username_or_token).first()
		if not user or not user.verify_password(password):
			return False
	g.user = user
	return True


@app.route('/clientOAuth')
def start():
	return render_template('clientOAuth.html')


@app.route('/oauth/<provider>', methods=['POST'])
def login(provider):
	# STEP 1 - Parse the auth code
	auth_code = request.json.get('auth_code')
	if provider == "google":
		# STEP 2 - Exchange for a token
		try:
			oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
			oauth_flow.redirect_uri = 'postmessage'
			credentials = oauth_flow.step2_exchange(auth_code)
		except FlowExchangeError:
			response = make_response(json.dumps('Failed to upgrade the '
												'autherization code.'), 401)
			response.headers['Content-Type'] = 'application/json'
			return response

		# Check that the access token is valid.
		access_token = credentials.access_token
		url = ('ttps://www.googleapis.com/oauth2/v1/tokeninfo?access_token'
			   '=%s' % access_token)
		h = httplib2.Http()
		header, body = h.request(url, 'GET')
		result = json.loads(body)
		# If there was an error in the access token info, abort.
		if result.get('error') is not None:
			response = make_response(json.dumps(result.get('error')), 500)
			response.headers['Content-Type'] = 'application/json'

		# STEP 3 - Find User or make a new one

		# Get user info

		# see if user exists, if it doesn't make a new one

		# STEP 4 - Make token


		# STEP 5 - Send back token to the client


	# return jsonify({'token': token.decode('ascii'), 'duration': 600})


@app.route('/token')
@auth.login_required
def get_auth_token():
	token = g.user.generate_auth_token()
	return jsonify({'token': token.decode('ascii')})


@app.route('/users', methods=['POST'])
def new_user():
	username = request.json.get('username')
	password = request.json.get('password')
	if username is None or password is None:
		print "missing arguments"
		abort(400)

	if session.query(User).filter_by(username=username).first() is not None:
		print "existing user"
		user = session.query(User).filter_by(username=username).first()
		return jsonify({
						   'message': 'user already exists'}), 200  # , {
		# 'Location': url_for('get_user', id = user.id, _external = True)}

	user = User(username=username)
	user.hash_password(password)
	session.add(user)
	session.commit()
	return jsonify({
					   'username': user.username}), 201  # , {'Location':
	# url_for('get_user', id = user.id, _external = True)}


@app.route('/api/users/<int:id>')
def get_user(id):
	user = session.query(User).filter_by(id=id).one()
	if not user:
		abort(400)
	return jsonify({'username': user.username})


@app.route('/api/resource')
@auth.login_required
def get_resource():
	return jsonify({'data': 'Hello, %s!' % g.user.username})


if __name__ == '__main__':
	app.debug = True
	# app.config['SECRET_KEY'] = ''.join(random.choice(
	# string.ascii_uppercase + string.digits) for x in xrange(32))
	app.run(host='0.0.0.0', port=5000)
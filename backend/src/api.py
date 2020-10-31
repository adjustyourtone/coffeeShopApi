from logging import error
import os
from flask import Flask, request, jsonify, abort
from sqlalchemy import exc
import json
from flask_cors import CORS
from .database.models import db_drop_and_create_all, setup_db, Drink
from .auth.auth import AuthError, get_token_auth_header, requires_auth

app = Flask(__name__)
setup_db(app)
CORS(app)

'''
@TODO uncomment the following line to initialize the database
!! NOTE THIS WILL DROP ALL RECORDS AND START YOUR DB FROM SCRATCH
!! DON'T UNCOMMENT THIS UNLESS YOU WANT TO START WITH AN EMPTY DB
'''
# db_drop_and_create_all()


# ROUTES
@app.route('/')
def index():

    return jsonify({"message": 'Hello, Your application is running.'})


@app.route('/drinks')
def get_drinks():
    """This endpoint will retrieve all drinks from the database."""
    drinks = Drink.query.all()

    return jsonify({
        'success': True,
        'drinks': [drink.short() for drink in drinks]
    }), 200


@app.route('/drinks-detail', methods=['GET'])
@requires_auth('get:drinks-detail')
def get_drink_detail(payload):
    """This endpoint will allow permitted users to view drink recipes."""
    drinks = Drink.query.all()

    return jsonify({
        'success': "True",
        'drinks': [drink.long() for drink in drinks]
    }), 200


@app.route('/drinks', methods=['POST'])
@requires_auth('post:drinks')
def create_drink(payload):
    """This endpoint will allow permitted users access to create a new drink."""
    data = request.get_json()

    try:
        req_recipe = data['recipe']
        if isinstance(req_recipe, dict):
            req_recipe = [req_recipe]

        drink = Drink()
        drink.title = data['title']
        drink.recipe = json.dumps(req_recipe)  # convert object to a string
        drink.insert()

    except BaseException:
        abort(400)

    return jsonify({'success': True, 'drinks': [drink.long()]}), 200


@app.route('/drinks/<int:id>', methods=['PATCH'])
@requires_auth('patch:drinks')
def update_drink(payload, id):
    """This endpoint will allow permitted users the ability to update a drink recipe."""
    drink = Drink.query.get(id)
    if drink is None:
        abort(404)

    data = request.get_json()
    if 'title' in data:
        drink.title = data['title']

    if 'recipe' in data:
        drink.recipe = json.dumps(data['recipe'])

    drink.update()

    return jsonify({'success': True, 'drinks': [drink.long()]}), 200


@app.route('/drinks/<int:id>', methods=['DELETE'])
@requires_auth('delete:drinks')
def delete_drink(payload, id):
    """This endpoint will allow permitted users to delete a drink."""
    # get drink by ID
    drink = Drink.query.get(id)
    if drink is None:
        abort(404)

    drink.delete()

    return jsonify({'success': True, 'delete': drink.id}), 200


# Define Error Handlers
@app.errorhandler(422)
def unprocessable(error):
    """Unprocessable entity error handeler."""
    return jsonify({
        "success": False,
        "error": 422,
        "message": "This is an unprocessable entity."
    }), 422


@app.errorhandler(400)
def bad_request(error):
    """Bad request error handler."""
    return jsonify({
        "success": False,
        "error": 422,
        "message": "Bad Request. Please verify the information you submitted is correct and try again."
    }), 400


@app.errorhandler(401)
def unauthorized(error):
    """Unauthorized attempt error handler."""
    return jsonify({
        "success": False,
        "error": 401,
        "message": "Unauthorized attempt."
    }), 401


@app.errorhandler(500)
def internal_server_error(error):
    """Internal server error error handler."""
    return jsonify({
        "success": False,
        "error": 500,
        "message": "Internal server error. Please try again."
    }), 500


@app.errorhandler(404)
def resource_not_found(error):
    """Resource not found error handler."""
    return jsonify({
        'success': False,
        'error': 404,
        'message': 'This resoure has not been found.'
    }), 404


@app.errorhandler(AuthError)
def process_AuthError(error):
    """AuthError effor handler."""
    response = jsonify(error.error)
    response.status_code = error.status_code

    return response

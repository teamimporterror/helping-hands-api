from app import app, db, bcrypt, api, admin
from flask import jsonify, request
from flask_admin.contrib.sqla import ModelView
from flask_restful import Resource
from app.models import Donor, Address, Beneficiary, Listings, Orders, Reviews, Modules, AdminModel, Event
from functools import wraps
from werkzeug.utils import secure_filename
import sendgrid
import os
import jwt
import datetime
import requests
from PIL import Image
from io import BytesIO
import base64
import tweepy 


sg = sendgrid.SendGridAPIClient(apikey=app.config['SENDGRID_API_KEY'])


def send_mail(to_email, donor, beneficiary, listing):
    text = f"Hi {donor.first_name}, An order has been placed for your product of {listing.description} by "\
           f"{beneficiary.first_name} {beneficiary.last_name}."
    data = {
                "personalizations": [
                    {
                    "to": [
                        {
                        "email": to_email
                        }
                    ],
                    "subject": "Order placed for your product"
                    }
                ],
                "from": {
                    "email": app.config['SENDGRID_DEFAULT_FROM'],
                    "name": "BetterPledge"
                },
                "content": [
                    {
                        "type": "text/plain",
                        "value": text
                    }
                ]
            }
    response = sg.client.mail.send.post(request_body=data)
    print(response.status_code)
    # print(response.body)
    # print(response.headers)


admin.add_view(ModelView(Donor, db.session))
admin.add_view(ModelView(Address, db.session))
admin.add_view(ModelView(Beneficiary, db.session))
admin.add_view(ModelView(Listings, db.session))
admin.add_view(ModelView(Orders, db.session))
admin.add_view(ModelView(Reviews, db.session))
admin.add_view(ModelView(AdminModel, db.session))
admin.add_view(ModelView(Modules, db.session))


ALLOWED_EXTENSIONS = set(['jpg', 'jpeg'])


def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# TODO: add type to models and verify


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return {'message': 'Token is missing'}, 403

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            type = data['type']
            if type == 'donor':
                donor = Donor.query.filter_by(
                    username=data['username']).first()
                print(donor.first_name)
            elif type == 'beneficiary':
                beneficiary = Beneficiary.query.filter_by(
                    username=data['username']).first()
                print(beneficiary.first_name)
        except Exception:
            return {'message': 'Token is invalid'}, 403

        return f(*args, **kwargs)

    return decorated


@app.route('/', methods=['GET'])
def home():
    return jsonify({'message': 'Welcome to the api'})


def username_in_database_donor(username):
    username = Donor.query.filter_by(username=username).first()
    return username


def username_in_database_beneficiary(username):
    username = Beneficiary.query.filter_by(username=username).first()
    return username


def verify_module(module):          # TODO: if it works, add it at the beginning of all routes(90%)
    token = request.headers.get("x-access-token")
    token_data = jwt.decode(token, app.config['SECRET_KEY'])
    token_module = token_data.get('module')
    if token_module == module:
        return True


def send_tweet(donor,description,quantity,module):
    message = donor + " has decided to donate " + module +"\nQuantity :  " + str(quantity) + "\nDescription : " + description  + "\n\nUse #helpinghands and be the part of the change in the world"; 
    consumer_key=os.environ.get('CONSUMER_KEY')
    consumer_secret=os.environ.get('CONSUMER_SECRET')
    access_token=os.environ.get('ACCESS_TOKEN')
    access_token_secret=os.environ.get('ACCESS_TOKEN_SECRET')
    auth = tweepy.OAuthHandler(consumer_key, consumer_secret)
    auth.set_access_token(access_token, access_token_secret)
    api = tweepy.API(auth)
    api.update_status(message)


@app.route('/<module>/donor', methods=['POST'])
def createdonor(module):
    donor_pure = request.json
    donor = donor_pure.get('form')
    if not donor:
        return jsonify({"message": "not json"}), 400
    if not donor.get("street"):
        return jsonify({"message": "address street not provided"}), 400
    print(donor)
    check_donor = Donor.query.filter_by(email=donor.get('email')).first()
    if check_donor:
        return jsonify({'message': 'Donor with that email already exists!'})
    # modules = Modules.query.all()
    # # if module not in modules:           # TODO: check if this works
    #     return jsonify({'message': 'This module does not exist'})
    password_hash = bcrypt.generate_password_hash(
        donor.get('password')).decode('utf-8')
    username = donor.get('email').split('@')[0]
    check_username = username_in_database_donor(username)
    if check_username:
        while check_username:
            username = username + '1'
            check_username = username_in_database_donor(username)
    u = Donor(first_name=donor.get('first_name'), last_name=donor.get('last_name'), email=donor.get('email'), phone_no=donor.get('phone_no'), username=username,
              password_hash=password_hash, module=donor_pure.get('module'), organisation=donor.get('organisation'))
    address = Address(donor=u, city=donor.get('city'), street=donor.get(
        'street'), country=donor.get('country'), landmark=donor.get('landmark'))
    db.session.add(address)
    db.session.add(u)
    db.session.commit()
    return jsonify({'message': 'Donor added to database'}), 200


@app.route('/<module>/donors', methods=['GET'])
def donors(module):
    donors = Donor.query.filter_by(module=module).all()
    donor_list = []
    for donor in donors:
        address = Address.query.filter_by(donor=donor).first()
        if address:
            d = {'first_name': donor.first_name, 'last_name': donor.last_name, 'id': donor.id, 'phone_no': donor.phone_no,
                 'email': donor.email, 'username': donor.username, 'city': address.city, 'country': address.country,
                 'street': address.street, 'landmark': address.landmark, 'organisation': donor.organisation, 'module': donor.module}
        else:
            d = {'first_name': donor.first_name, 'last_name': donor.last_name, 'password_hash': donor.password_hash, 'id': donor.id, 'phone_no': donor.phone_no,
                 'email': donor.email, 'username': donor.username, 'module': donor.module}
        donor_list.append(d)
    return jsonify({'donors': donor_list}), 200


@app.route('/<module>/beneficiaries', methods=['GET'])
def beneficiaries(module):
    beneficiaries = Beneficiary.query.filter_by(module=module).all()
    beneficiaries_list = []
    for beneficiary in beneficiaries:
        address = Address.query.filter_by(beneficiary=beneficiary).first()
        if address:
            d = {'first_name': beneficiary.first_name, 'last_name': beneficiary.last_name, 'id': beneficiary.id, 'phone_no': beneficiary.phone_no,
                 'email': beneficiary.email, 'username': beneficiary.username, 'city': address.city, 'country': address.country,
                 'street': address.street, 'landmark': address.landmark, 'module': beneficiary.module}
        else:
            d = {'first_name': beneficiary.first_name, 'last_name': beneficiary.last_name, 'password_hash': beneficiary.password_hash, 'id': beneficiary.id, 'phone_no': beneficiary.phone_no,
                 'email': beneficiary.email, 'username': beneficiary.username, 'module': beneficiary.module}
        beneficiaries_list.append(d)
    return jsonify({'beneficiaries': beneficiaries_list}), 200


@app.route('/<module>/beneficiary', methods=['POST'])
def createbeneficiary(module):
    beneficiary_pure = request.json
    beneficiary = beneficiary_pure.get('form')
    if not beneficiary:
        return jsonify({"message": "not json"}), 400
    # if not beneficiary.get("street"):
    #     return jsonify({"message": "address street not provided"}), 400
    check_beneficiary = Beneficiary.query.filter_by(
        email=beneficiary.get('email')).first()
    if check_beneficiary:
        return jsonify({'message': 'beneficiary with that email already exists'})
    # modules = Modules.query.all()
    # if module not in modules:       # work on this later
    #     return jsonify({'message': 'This module does not exist'})
    password_hash = bcrypt.generate_password_hash(
        beneficiary.get('password')).decode('utf-8')
    username = beneficiary.get('email').split('@')[0]
    check_username = username_in_database_beneficiary(username)
    if check_username:
        while check_username:
            username = username + '1'
            check_username = username_in_database_beneficiary(username)
    u = Beneficiary(first_name=beneficiary.get('first_name'), last_name=beneficiary.get('last_name'), email=beneficiary.get('email'), phone_no=beneficiary.get('phone_no'), username=username,
                    password_hash=password_hash,  module=beneficiary_pure.get('module'), type="ngo", status="pending")
    address = Address(beneficiary=u)
    db.session.add(address)
    db.session.add(u)
    db.session.commit()
    return jsonify({'message': 'beneficiary added to database'}), 200


class Login(Resource):
    def post(self, module):
        user_data = request.json
        if not user_data:
            return None
            # return {"message": "not json"}, 400
        if user_data.get('type') == 'beneficiary':
            user = Beneficiary.query.filter_by( email=user_data.get('email')).first()
            organisation = ""
            type = 'beneficiary'
            status = user.status
        else:
            user = Donor.query.filter_by(email=user_data.get('email')).first()
            organisation = user.organisation
            type = 'donor'
            status = ""
        if user.module != module:
            return None
            # return {"message": "no account 0"}
        if user and bcrypt.check_password_hash(user.password_hash, user_data.get('password')):
            token = jwt.encode(
                {'username': user.username, 'first_name': user.first_name, 'organisation': organisation,
                 'last_name': user.last_name, 'type': type, 'id': user.id, 'module': user.module, "status": status,
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(days=365)},
                app.config['SECRET_KEY'])
            return {'token': token.decode('UTF-8')}, 200
        else:
            return None
            # return {"message": "no account 1"}


class Listing(Resource):
    def get(self, module):
        # if not verify_module(module):
        #     return {"message": "not authorized"}, 400
        send_all = request.args.get("send_all")
        if send_all == "0":
            listings = Listings.query.filter_by(module=module).all()
            listing_list = []
            for listing in listings:
                donor = Donor.query.get(listing.donor_id)
                address = Address.query.filter_by(
                    donor_id=listing.donor_id).first()
                if listing.quantity is None:
                    continue
                if listing.quantity < 1:
                    continue
                l = {"listing_id": listing.id,
                     "quantity": listing.quantity, "expiry": listing.expiry, "description": listing.description,
                     "type": listing.type, "image": listing.image, "lat": float(listing.lat), "lng": float(listing.lng), "donor_id": listing.donor_id,
                     "street": address.street, "landmark": address.landmark, "city": address.city, "country": address.country, 
                     'organisation': donor.organisation, "module": listing.module}
                listing_list.append(l)
            return {"listing": listing_list}, 200

        elif send_all == "1":
            listings = Listings.query.filter_by(module=module).all()
            # listings = Listings.query.all()
            listing_dict = {}
            for listing in listings:
                donor = Donor.query.get(listing.donor_id)
                address = Address.query.filter_by(
                    donor_id=listing.donor_id).first()
                # if listing.quantity < 1:
                #     continue
                listing_dict[listing.id] = {"listing_id": listing.id,
                                            "quantity": listing.quantity, "expiry": listing.expiry, "description": listing.description,
                                            "type": listing.type, "image": listing.image, "donor_id": listing.donor_id, "street": address.street,
                                            "landmark": address.landmark, "city": address.city, "country": address.country, 'organisation': donor.organisation,
                                            "module": listing.module, "lat": float(listing.lat), "lng": float(listing.lng)}
            return listing_dict
        else:
            return {"message": "send_all not given"}, 400

    @token_required
    def post(self, module):
        # verify_module(module)
        token = request.headers.get("x-access-token")
        token_data = jwt.decode(token, app.config['SECRET_KEY'])
        listing_json = request.json
        if not listing_json:
            return {"message": "not json"}, 400
        listing = listing_json.get('product')
        donor = Donor.query.filter_by(
            username=token_data.get('username')).first()
        # print(donor.username, "xxx")
        l = Listings(quantity=listing.get('quantity'), expiry=listing.get('expiry'),
                     description=listing.get('description'), type=listing.get('type'),
                     image=listing.get('image'), module=module, donor_id=donor.id, lat=listing_json.get('lat'),
                     lng=listing_json.get('lng'))
        db.session.add(l)
        db.session.commit()
        # send_tweet(donor.first_name+" "+donor.last_name, listing.get('description'), listing.get('quantity') , module)
        return {"message": "listing added"}, 200


class Order(Resource):
    # TODO: remove this or make it token protected
    # TODO: remember to send module alongside time_stamp level.
    @token_required
    def post(self, module):
        token = request.headers.get("x-access-token")
        token_data = jwt.decode(token, app.config['SECRET_KEY'])
        json_data = request.json
        if not json_data:
            return {"message": "not json"}, 400
        orders = json_data.get('orders')
        for i in range(0, len(orders)):
            if orders[i] is None:
                continue
            order = orders[i].get('product')
            donor = Donor.query.get(order.get('donor_id'))
            beneficiary_username = token_data.get("username")
            beneficiary = Beneficiary.query.filter_by(
                username=beneficiary_username).first()
            if not beneficiary:
                return {'message': 'beneficiary not found', 'username': beneficiary_username, "error": 1}, 400

            listing = Listings.query.get(order.get('listing_id'))
            quantity = orders[i].get('quantity')
            if quantity < 0:
                return {'message': 'listing quantity less than 0', "error": 1}, 400
            listing.quantity -= int(quantity)
            if listing.quantity < 0:
                return {'message': 'quantity more than stock', "error": 1}, 400
            o = Orders(donor=donor, beneficiary_id=beneficiary.id,
                       listing=listing, quantity=quantity, module=json_data.get('module'), time_stamp=json_data.get('time_stamp'))
            db.session.add(o)
            db.session.commit()
            # send_mail(to_email=donor.email, donor=donor,
            #           beneficiary=beneficiary, listing=listing)
        return {"message": "Your order has been placed.", "error": 0}, 200


class DonorListings(Resource):
    @token_required
    def get(self, module):
        # if current_user.module is not module:           # TODO: add replacement using token.
        #     return {"message": "not allowed"}, 400
        token = request.headers.get("x-access-token")
        token_data = jwt.decode(token, app.config['SECRET_KEY'])
        username = token_data.get("username")
        donor = Donor.query.filter_by(username=username).first()
        listings = Listings.query.filter_by(donor_id=donor.id).all()
        parsed_listings = []
        d = dict()
        # first parsing individual listings. overcomes object 'Listings' cannot be jsonify.
        for listing in listings:
            l = {"listing_id": listing.id,
                 "quantity": listing.quantity, "expiry": listing.expiry, "description": listing.description,
                 "type": listing.type, "image": listing.image, "donor_id": listing.donor_id}
            parsed_listings.append(l)

        count = 0
        all_listings = []
        # giving structure
        for listings in parsed_listings:
            d[count] = listings
            print(listings)
            all_listings.append(d)
            d = {}
            count = count + 1
        return {"listings": all_listings}, 200


# TODO: see where this route is being used and if it needs to have module or not. 
class SingleListing(Resource):
    def get(self, module):
        # if current_user.module is not module:
        #     return {"message": "not allowed"}, 400
        # if not verify_module(module):
        #     return {"message": "not authorized"}
        listing_id = request.args.get("listing_id")
        if not listing_id:
            return {"listing_id": listing_id}, 400
        listing = Listings.query.get(listing_id)
        if not listing:
            return {"message": "No listing available with that listing_id"}, 400
        donor = Donor.query.get(listing.donor_id)
        address = Address.query.filter_by(donor_id=listing.donor_id).first()
        return {"listing_id": listing.id, "quantity": listing.quantity, "expiry": listing.expiry, "description": listing.description,
                "type": listing.type, "image": listing.image, "donor_id": listing.donor_id, "street": address.street,
                "landmark": address.landmark, "city": address.city, "country": address.country, 'organisation': donor.organisation}


class UpdateListing(Resource):
    @token_required    # TODO: origin
    def post(self, module):
        # if current_user.module is not module:
        #     return {"message": "not allowed"}, 400
        token = request.headers.get("x-access-token")
        token_data = jwt.decode(token, app.config['SECRET_KEY'])
        token_module = token_data.get('module')
        if token_module != module:
            return {"message": "not allowed"}, 400
        listing_id = request.args.get("listing_id")
        update_listing = request.json
        if not listing_id:
            return {"message": "listing_id not provided"}, 400
        listing = Listings.query.get(listing_id)
        if not listing:
            return {"message": "no listing available with that listing_id"}, 400
        listing.quantity = update_listing.get("quantity")
        listing.description = update_listing.get("description")
        listing.expiry = update_listing.get("expiry")
        listing.type = update_listing.get("type")
        listing.image = update_listing.get("image")
        db.session.commit()
        return {"message": "listing updated"}, 200


class DeleteListing(Resource):
    @token_required
    def post(self, module):     # use this module variable to validate.
        # if current_user.module is not module:
        #     return {"message": "not allowed"}, 400
        token = request.headers.get("x-access-token")
        token_data = jwt.decode(token, app.config['SECRET_KEY'])
        token_module = token_data.get('module')
        if token_module != module:
            return {"message": "not allowed"}, 400
        listing_id = request.args.get("listing_id")
        if not listing_id:
            return {"message": "no listing_id sent in args"}, 400
        token = request.headers.get("x-access-token")
        token_data = jwt.decode(token, app.config['SECRET_KEY'])
        username = token_data.get("username")
        donor = Donor.query.filter_by(username=username).first()
        donor_listings = Listings.query.filter_by(donor_id=donor.id).all()
        # Listings.query.filter_by(id=listing_id).delete()
        listing = Listings.query.filter_by(id=listing_id).first()
        if not listing:
            return {"message": "no listing available with that listing_id"}, 400
        if listing not in donor_listings:
            return {"message": "permission denied"}, 400
        listing.quantity = 0
        db.session.commit()
        return {"message": "listing deleted"}, 200


class Profile(Resource):
    @token_required
    def get(self, module):      # use this module variable to validate.
        token = request.headers.get("x-access-token")
        token_data = jwt.decode(token, app.config['SECRET_KEY'])
        token_module = token_data.get('module')
        if token_module != module:
            return {"message": "not allowed"}, 400
        type = token_data.get('type')
        username = token_data.get("username")
        if type == 'donor':
            user = Donor.query.filter_by(username=username).first()
            address = Address.query.filter_by(donor_id=user.id).first()
            u = {'first_name': user.first_name, 'last_name': user.last_name, 'id': user.id, 'phone_no': user.phone_no,
                 'email': user.email, 'username': user.username, 'organisation': user.organisation, 'street': address.street, 'landmark': address.landmark,
                 'city': address.city, 'country': address.country, 'module': user.module}
        elif type == 'beneficiary':
            user = Beneficiary.query.filter_by(username=username).first()
            address = Address.query.filter_by(beneficiary_id=user.id).first()
            u = {'first_name': user.first_name, 'last_name': user.last_name, 'id': user.id, 'phone_no': user.phone_no,
                 'email': user.email, 'username': user.username, 'street': address.street, 'landmark': address.landmark,
                 'city': address.city, 'country': address.country, 'module': user.module}

        return {'user': u}, 200


class UpdateUser(Resource):
    @token_required
    def post(self, module):
        updated_user = request.json
        token = request.headers.get("x-access-token")
        token_data = jwt.decode(token, app.config['SECRET_KEY'])
        token_module = token_data.get('module')
        if token_module != module:
            return {"message": "not allowed"}, 400
        type = token_data.get('type')
        username = token_data.get("username")
        if type == 'donor':
            user = Donor.query.filter_by(username=username).first()
            user.organisation = updated_user.get('organisation')
            address = Address.query.filter_by(donor_id=user.id).first()
            check_username = Donor.query.filter_by(
                username=updated_user['username']).first()
            if check_username:
                if check_username.id != user.id:
                    return {'token': token, 'message': 0}, 400
        elif type == 'beneficiary':
            user = Beneficiary.query.filter_by(username=username).first()
            address = Address.query.filter_by(beneficiary_id=user.id).first()
            check_username = Beneficiary.query.filter_by(
                username=updated_user['username']).first()
            if check_username.id != user.id:
                return {'token': token, 'message': 0}, 400

        address.street = updated_user.get('street')
        address.city = updated_user.get('city')
        address.landmark = updated_user.get('landmark')
        address.country = updated_user.get('country')
        user.first_name = updated_user.get('first_name')
        user.last_name = updated_user.get('last_name')
        user.phone_no = updated_user.get('phone_no')
        user.username = updated_user.get('username')
        db.session.commit()
        token = jwt.encode(
            {'username': user.username, 'first_name': user.first_name, 'type': type, 'id': user.id, 'module': module,
             'exp': datetime.datetime.utcnow() + datetime.timedelta(days=365)},
            app.config['SECRET_KEY'])
        return {'token': token.decode('UTF-8'), 'message': 1}, 200


class BeneficiaryOrders(Resource):
    @token_required
    def get(self, module):
        token = request.headers.get("x-access-token")
        token_data = jwt.decode(token, app.config['SECRET_KEY'])
        token_module = token_data.get('module')
        if token_module != module:
            return {"message": "not allowed"}, 400
        username = token_data.get("username")
        beneficiary = Beneficiary.query.filter_by(username=username).first()
        orders = Orders.query.filter_by(beneficiary_id=beneficiary.id)
        order_list = []
        for order in orders:
            address = Address.query.filter_by(donor_id=order.donor_id).first()
            donor = Donor.query.filter_by(id=order.donor_id).first()
            listing = Listings.query.get(order.listing_id)
            l = {
                "donor_id": order.donor_id,
                "beneficiary_id": order.beneficiary_id,
                "listing_id": order.listing_id,
                "quantity": order.quantity,
                "time_stamp": order.time_stamp,
                "street": address.street,
                "landmark": address.landmark,
                "city": address.city,
                "country": address.country,
                "image": listing.image,
                "description": listing.description,
                "organisation": donor.organisation
            }
            order_list.append(l)
        order_list.reverse()
        return {"orders": order_list}


class DonorOrders(Resource):
    @token_required
    def get(self, module):
        token = request.headers.get("x-access-token")
        token_data = jwt.decode(token, app.config['SECRET_KEY'])
        token_module = token_data.get('module')
        if token_module != module:
            return {"message": "not allowed"}, 400
        username = token_data.get("username")
        donor = Donor.query.filter_by(username=username).first()    #TODO: check if username is unique 
        orders = Orders.query.filter_by(donor_id=donor.id).all()    # in all the modules for same email
        order_list = []
        for order in orders:
            address = Address.query.filter_by(donor_id=order.donor_id).first()
            listing = Listings.query.get(order.listing_id)
            beneficiary = Beneficiary.query.get(order.beneficiary_id)
            l = {"donor_id": order.donor_id,
                 "beneficiary_id": order.beneficiary_id,
                 "first_name": beneficiary.first_name,
                 "last_name": beneficiary.last_name,
                 "email": beneficiary.email,
                 "phone_no": beneficiary.phone_no,
                 "listing_id": order.listing_id,
                 "quantity": order.quantity,
                 "time_stamp": order.time_stamp,
                 "street": address.street,
                 "landmark": address.landmark,
                 "city": address.city,
                 "country": address.country,
                 "image": listing.image,
                 "description": listing.description,
                 "organisation": donor.organisation}
            order_list.append(l)
        order_list.reverse()
        return {"orders": order_list}


# randomize the image filename
class UploadImage(Resource):
    def post(self):
        # check if the post request has the file part
        if 'file' not in request.files:
            return {"messege": "No file sent"}, 400
        file = request.files['file']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            return {'massege': 'No selected file'}, 400
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            path = os.path.join(app.root_path, filename)
            file.save(path)
            # if float(score) > 0.7:
            #     return {"message": "This image may not be appropriate. Please choose a different image."}
            url = upload_to_imgur(path)
            return {"url": url}, 200


def upload_to_imgur(path):
    output = BytesIO()
    im = Image.open(path)
    im.save(output, format='JPEG')
    im_data = output.getvalue()
    base_64 = base64.b64encode(im_data)
    os.remove(path)
    url = 'https://api.imgur.com/3/image'
    payload = {'image': base_64}
    files = {}
    headers = {
        'Authorization': 'Client-ID b24245cb0505c2c'
    }
    response = requests.request(
        'POST', url, headers=headers, data=payload, files=files, allow_redirects=False)
    content = response.json()
    url = content.get('data').get('link')
    return url


class ModulesRoute(Resource):
    def get(self):
        modules = Modules.query.all()
        module_list = []
        for module in modules:
            l = {"name": module.name,
                 "image": module.image}
            module_list.append(l)
        print(module_list)
        return {"modules": module_list}, 200

    @token_required
    def post(self):
        token = request.headers.get("x-access-token")
        token_data = jwt.decode(token, app.config['SECRET_KEY'])
        if token_data.get('type') != "admin":
            return {"message": "not allowed"}, 200
        module = request.json
        if not module:
            return {"message": "not json"}, 400
        if module.get('name') is None or module.get('image') is None:
            return {"message": "name or image not provided"}
        module = Modules(name=module.get('name').lower(), image=module.get('image'))
        db.session.add(module)
        db.session.commit()
        return {"message": "module added to database"}, 200


class LoginAdmin(Resource):
    def post(self):
        user_data = request.json
        if not user_data:
            return {"message": "not json"}, 400
        user = AdminModel.query.filter_by(
            username=user_data.get('username')).first()
        if user and bcrypt.check_password_hash(user.password_hash, user_data.get('password')):
            token = jwt.encode(
                {'username': user.username, 'first_name': user.first_name, 'last_name': user.last_name, 'type': 'admin', 'id': user.id,
                    'exp': datetime.datetime.utcnow() + datetime.timedelta(days=365)},
                app.config['SECRET_KEY'])
            return {'token': token.decode('UTF-8')}, 200
        else:
            return None

@app.route('/mark_verify', methods=['POST'])
@token_required
def mark_verify():
        json_data = request.json
        beneficiary_id = json_data.get("beneficiary_id")
        beneficiary = Beneficiary.query.get(beneficiary_id)
        beneficiary.status = json_data.get('status')  
        db.session.commit()
        return jsonify({"message": "status updated for beneficiary"}), 200


@app.route('/admin/show_all_pending', methods=['GET'])
def show_all_pending():
    beneficiaries = Beneficiary.query.filter_by(status='pending').all()
    beneficiaries_list = []
    for beneficiary in beneficiaries:
        d = {'id': beneficiary.id, 'phone_no': beneficiary.phone_no,
                'email': beneficiary.email, 'username': beneficiary.username, 'module': beneficiary.module}
        beneficiaries_list.append(d)
    return jsonify({'beneficiaries': beneficiaries_list}), 200



class BeneficiaryVerification(Resource):
    @token_required
    def post(self, module):
        token = request.headers.get("x-access-token")
        token_data = jwt.decode(token, app.config['SECRET_KEY'])
        token_module = token_data.get('module')
        json_data = request.json
        if token_module != module:
            return {"message": "not allowed"}, 400
        username = token_data.get("username")
        beneficiary = Beneficiary.query.filter_by(username=username).first()
        beneficiary.ngo_name = json_data.get('ngo_name')
        beneficiary.image = json_data.get('image')
        beneficiary.sociallink1 = json_data.get('sociallink1')
        beneficiary.sociallink2 = json_data.get('sociallink2')
        beneficiary.sociallink3 = json_data.get('sociallink3')
        beneficiary.past_record = json_data.get('past_record')
        db.session.commit()
        return {"message": "got it"}, 200


class AdminCheck(Resource):
    @token_required
    def get(self):
        beneficiary_id = request.args.get("beneficiary_id")
        user = Beneficiary.query.get(beneficiary_id)
        address = Address.query.filter_by(beneficiary_id=user.id).first()
        u = {'first_name': user.first_name, 'last_name': user.last_name, 'id': user.id, 'phone_no': user.phone_no,
             'email': user.email, 'username': user.username, 'street': address.street, 'landmark': address.landmark,
             'city': address.city, 'country': address.country, 'module': user.module, 'ngo_name': user.ngo_name,
             'image': user.image, 'sociallink1': user.sociallink1, 'sociallink2': user.sociallink2, 'sociallink3': user.sociallink3,
             'past_record': user.past_record}
        return {"user": u}, 200


class EventRoute(Resource):
    @token_required
    def post(self):      # use this module variable to validate.
        json_data = request.json
        token = request.headers.get("x-access-token")
        token_data = jwt.decode(token, app.config['SECRET_KEY'])
        type = token_data.get('type')
        username = token_data.get("username")
        if type == 'donor':
            user = Donor.query.filter_by(username=username).first()
            event = Event(name=json_data.get('name'), description=json_data.get('description'),
                          start_date=json_data.get('start_date'), end_date=json_data.get('end_date'),
                          image=json_data.get('image'), donor_id=user.id, lat=json_data.get('lat'),
                          lng=json_data.get('lng'), phone_no=json_data.get('phone_no'))
        elif type == 'beneficiary':
            user = Beneficiary.query.filter_by(username=username).first()
            event = Event(name=json_data.get('name'), description=json_data.get('description'),
                          start_date=json_data.get('start_date'), end_date=json_data.get('end_date'),
                          image=json_data.get('image'), beneficiary_id=user.id, lat=json_data.get('lat'),
                          lng=json_data.get('lng'), phone_no=json_data.get('phone_no'))
        db.session.add(event)
        db.session.commit()
        return {'message': "event added to database"}, 200
   
    def get(self):
        events = Event.query.all()
        event_list = []
        for event in events:
            e = {"event_id": event.id, "start_date": event.expiry, "description": event.description,
                 "end_date": event.end_date,"lat": event.lat, "lng":event.lng, "image": event.image,
                  "name": event.name}
            event_list.append(e)
        return {"events": event_list}, 200

# @app.route('/show_all')
# def show_all_listing_latitudes():
#     listings = Listings.query.filter(id==1)
#     print(listings)
    # return "hello"


# class RequestModuleRoute(Resource):
#     @token_required
#     def post(self):      # use this module variable to validate.
#         json_data = request.json
#         token = request.headers.get("x-access-token")
#         token_data = jwt.decode(token, app.config['SECRET_KEY'])
#         type = token_data.get('type')
#         username = token_data.get("username")
#         if type == 'donor':
#             user = Donor.query.filter_by(username=username).first()
#             event = Event(name=json_data.get('name'), description=json_data.get('description'),
#                           start_date=json_data.get('start_date'), end_date=json_data.get('end_date'),
#                           image=json_data.get('image'), donor_id=user.id  )
#         elif type == 'beneficiary':
#             user = Beneficiary.query.filter_by(username=username).first()
#             event = Event(name=json_data.get('name'), description=json_data.get('description'),
#                           start_date=json_data.get('start_date'), end_date=json_data.get('end_date'),
#                           image=json_data.get('image'), beneficiary_id=user.id  )
#         db.session.add(event)
#         db.session.commit()
#         return {'message': "event added to database"}, 200
    
#     def get(self):
#         events = Event.query.all()
#         event_list = []
#         for event in events:
#             e = {"event_id": event.id, "start_date": event.expiry, "description": event.description,
#                  "end_date": event.end_date, "image": event.image, "name": event.name}
#             event_list.append(e)
#         return {"events": event_list}, 200



api.add_resource(Login, '/<module>/login')
api.add_resource(Listing, '/<module>/listing')
api.add_resource(Order, '/<module>/order')
api.add_resource(DonorListings, '/<module>/donorlistings')
api.add_resource(SingleListing, '/<module>/singlelisting')     # don't add <module> here
api.add_resource(UpdateListing, '/<module>/updatelisting')     # don't add <module> here 
api.add_resource(DeleteListing, '/<module>/deletelisting')
api.add_resource(Profile, '/<module>/user')
api.add_resource(UpdateUser, '/<module>/user/update')
api.add_resource(BeneficiaryOrders, '/<module>/beneficiary/orders')
api.add_resource(DonorOrders, '/<module>/donor/orders')
api.add_resource(UploadImage, '/uploadimage')
api.add_resource(ModulesRoute, '/modules')
api.add_resource(LoginAdmin, '/admin/login')
api.add_resource(EventRoute, '/event')
api.add_resource(BeneficiaryVerification, '/<module>/verify')
api.add_resource(AdminCheck, '/admin/verify')
# api.add_resource(RequestModuleRoute, '/admin/request')


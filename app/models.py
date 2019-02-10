from app import db


class Donor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(30))
    last_name = db.Column(db.String(30))
    email = db.Column(db.String(80))
    username = db.Column(db.String(40), unique=True)
    phone_no = db.Column(db.String(13))
    module = db.Column(db.String(40))
    organisation = db.Column(db.String(50))
    password_hash = db.Column(db.String(60))
    address = db.relationship('Address', backref='donor', lazy=True)
    reviews = db.relationship('Reviews', backref='donor', lazy=True)
    listings = db.relationship('Listings', backref='donor', lazy=True)
    orders = db.relationship('Orders', backref='donor', lazy=True)


class Beneficiary(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(60))
    last_name = db.Column(db.String(60))
    ngo_name = db.Column(db.String(60))
    email = db.Column(db.String(80))
    module = db.Column(db.String(40))
    username = db.Column(db.String(40), unique=True)
    phone_no = db.Column(db.String(13))
    # approved, rejected
    status = db.Column(db.String(13), default="pending")
    password_hash = db.Column(db.String(60))
    type = db.Column(db.Integer)
    image = db.Column(db.String(100))
    sociallink1 = db.Column(db.String(100))
    sociallink2 = db.Column(db.String(100))
    sociallink3 = db.Column(db.String(100))
    past_record = db.Column(db.Text())
    address = db.relationship('Address', backref='beneficiary', lazy=True)
    review = db.relationship('Reviews', backref='beneficiary', lazy=True)
    orders = db.relationship('Orders', backref='beneficiary', lazy=True)


class Address(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    donor_id = db.Column(db.Integer, db.ForeignKey('donor.id'))
    beneficiary_id = db.Column(db.Integer, db.ForeignKey('beneficiary.id'))
    city = db.Column(db.String(20), default='dehradun')
    street = db.Column(db.String(20), default='250 B')
    country = db.Column(db.String(20), default='India')
    landmark = db.Column(db.String(50), default='Opposite Dit University')


class Reviews(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    donor_id = db.Column(db.Integer, db.ForeignKey('donor.id'),
                         nullable=False)
    beneficiary_id = db.Column(db.Integer, db.ForeignKey('beneficiary.id'),
                               nullable=False)
    stars = db.Column(db.String(1))
    review = db.Column(db.Text())


class Orders(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    donor_id = db.Column(db.Integer, db.ForeignKey('donor.id'),
                         nullable=False)
    beneficiary_id = db.Column(db.Integer, db.ForeignKey('beneficiary.id'),
                               nullable=False)
    listing_id = db.Column(db.Integer, db.ForeignKey(
        'listings.id'), nullable=False)
    quantity = db.Column(db.String(20))
    module = db.Column(db.String(40))
    time_stamp = db.Column(db.String(20))


class Listings(db.Model):
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    quantity = db.Column(db.Integer)
    expiry = db.Column(db.String(20))
    description = db.Column(db.String(250))
    type = db.Column(db.String(10))
    image = db.Column(db.String(100))
    module = db.Column(db.String(40))
    lat = db.Column(db.String(40))
    lng = db.Column(db.String(40))
    orders = db.relationship('Orders', backref='listing', lazy=True)
    donor_id = db.Column(db.Integer, db.ForeignKey('donor.id'))


class Modules(db.Model):
    id = db.Column(db.Integer, primary_key=True, nullable=False)
    name = db.Column(db.String(40))
    image = db.Column(db.String(100))


class AdminModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(30), default="admin_first_name")
    last_name = db.Column(db.String(30), default="admin_last_name")
    email = db.Column(db.String(80), default="admin@site.com")
    username = db.Column(db.String(40), unique=True)
    password_hash = db.Column(db.String(60))


# TODO: add co-ordinates
class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    description = db.Column(db.String(250))
    start_date = db.Column(db.String(25))
    end_date = db.Column(db.String(25))
    phone_no = db.Column(db.String(25))
    image = db.Column(db.String(100))
    donor_id = db.Column(db.Integer, db.ForeignKey('donor.id'))
    beneficiary_id = db.Column(db.Integer, db.ForeignKey('beneficiary.id'))

from flask_sqlalchemy import SQLAlchemy
from app import app
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
db = SQLAlchemy(app)

class User(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    passhash = db.Column(db.String(100), nullable=False)  
    role = db.Column(db.String(20), nullable=False)  # 'User' or 'Creator'
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    
    playlists = db.relationship('Playlist', backref='user', lazy=True)
    created_songs = db.relationship('Song', backref='creator', lazy=True)
    created_albums = db.relationship('Album', backref='creator', lazy=True)
    
    def set_password(self, password):
        self.passhash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.passhash, password)

class Song(db.Model):
    __tablename__ = 'songs'
    song_id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    artist = db.Column(db.String(100), nullable=False)
    lyrics = db.Column(db.Text, nullable=False)
    genre = db.Column(db.String(50), nullable=False)
    rating = db.Column(db.Float, nullable=False, default=0.0)
    album_id = db.Column(db.Integer, db.ForeignKey('albums.album_id'))
    creator_id = db.Column(db.Integer, db.ForeignKey('users.user_id'))
    is_flag = db.Column(db.Boolean, nullable=False, default=False)
    filename = db.Column(db.String(255))

    playlist = db.relationship('Playlist', backref='song', lazy=True)


class Album(db.Model):
    __tablename__ = 'albums'
    album_id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    release_date = db.Column(db.Date)
    genre = db.Column(db.String(50), nullable=False)
    creator_id = db.Column(db.Integer, db.ForeignKey('users.user_id'))

    songs = db.relationship('Song', backref='album', lazy=True)

    def song_count(self):
        return Song.query.filter_by(album_id=self.album_id).count()

class Playlist(db.Model):
    __tablename__ = 'playlists'
    playlist_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'))
    song_id = db.Column(db.Integer, db.ForeignKey('songs.song_id'))


class CreatorBlacklist(db.Model):
    __tablename__ = 'creator_blacklist'
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('users.user_id'))
    creator_id = db.Column(db.Integer, db.ForeignKey('users.user_id'))

with app.app_context():
    db.create_all()

    # Check if the admin user exists
    admin = User.query.filter_by(username='admin').first()
    if not admin:
        admin = User(username='admin', role='Admin', is_admin=True)
        admin.set_password('admin')  # Be sure to hash the password
        db.session.add(admin)
        db.session.commit()

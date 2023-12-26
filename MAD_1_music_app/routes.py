from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory, jsonify
from models import db, User, Song, Album, Playlist, CreatorBlacklist
from app import app
from sqlalchemy import func, distinct
import os
import json
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash
import time
import re
import datetime
#---- decorator functions --------------------------------#
def auth_required(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if 'user_id' not in session:
            flash('You must be logged in to access this page.', "danger")
            return redirect(url_for('login')) 
        return func(*args, **kwargs)
    return inner

def admin_reqequired(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if 'user_id' not in session:
            flash('You must be logged in to access this page.', "danger")
            return redirect(url_for('login')) 
        user = User.query.get(session['user_id'])
        if not user.is_admin:
            flash('You must be an admin to access this page.', "danger")
            return redirect(url_for('index'))
        return func(*args, **kwargs)
    return inner

def creator_required(func):
    @wraps(func)
    def inner(*args, **kwargs):
        if 'user_id' not in session:
            flash('You must be logged in to access this page.', "danger")
            return redirect(url_for('login')) 
        user = User.query.get(session['user_id'])
        if not user.role == 'Creator':
            flash('You must be a creator to access this page.', "danger")
            return redirect(url_for('index'))
        return func(*args, **kwargs)
    return inner
#---- decorator functions --------------------------------#
@app.route('/')
@auth_required
def index():
    user=User.query.get(session['user_id'])
    user_id = session.get('user_id')
    parameter = request.args.get('parameter')
    query = request.args.get('query')
    blacklist_creator = CreatorBlacklist.query.filter_by(creator_id=user_id).first()
    creator_blacklist_entries = db.session.query(CreatorBlacklist.creator_id).all()
    creator_id_list = [entry[0] for entry in creator_blacklist_entries]
    albums = db.session.query(Album.album_id).filter(~Album.creator_id.in_(creator_id_list)).all()
    album_id_list = [album[0] for album in albums]
    albums = Album.query.filter(Album.album_id.in_(album_id_list)).all()

    if blacklist_creator:
        flash('You have been blacklisted ', "danger")
        return redirect(url_for('login'))

    else:
        if not parameter or not query:
            return render_template('index.html', user=user, albums=albums)

        if parameter == 'Album':
            albums = Album.query.filter(Album.title.ilike('%' + query + '%')).filter(Album.album_id.in_(album_id_list)).all()
            return render_template('index.html', user=user, albums=albums)
        
        return render_template('index.html', user=user, album=Album.query.all())

@app.route('/login')
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_post():
    username = request.form.get('username')
    password = request.form.get('password')
    admin_login = request.form.get('admin_login')

    if username == '' or password == '':
        flash('Please fill out all fields', "danger")
        return redirect(url_for('login'))
    
    if username == 'admin':
        flash('If you are an admin, please log in as an admin using the admin login page.', "danger")
        return redirect(url_for('login'))

    user = User.query.filter_by(username=username).first()

    if not user or not user.check_password(password):
        flash('Invalid username or password', "danger")
        return redirect(url_for('login'))

    if admin_login:
        if user.is_admin:
            session['user_id'] = user.user_id
            return redirect(url_for('admin_dashboard'))
        else:
            flash('You are not authorized to access the admin panel.', "danger")
            return redirect(url_for('login'))

    session['user_id'] = user.user_id
    return redirect(url_for('index'))

@app.route('/admin_login')
def admin_login():
    return render_template('admin_login.html')

@app.route('/admin_dashboard')
@admin_reqequired
def admin_dashboard():
    user_id = session.get('user_id')
    if user_id is not None:
        user = User.query.get(user_id)
        if user.is_admin:
            total_users = User.query.count()
            total_creators = User.query.filter_by(role='Creator').count()
            total_albums = Album.query.count()
            distinct_genres = db.session.query(func.count(distinct(Album.genre))).scalar()

            songs = Song.query.all()
            song_labels = [song.title for song in songs]
            song_ratings = [song.rating for song in songs]

            return render_template(
                'admin_dashboard.html',
                distinct_genres=distinct_genres, 
                user=user, 
                total_users=total_users,
                total_creators=total_creators, 
                total_albums=total_albums,
                song_labels=song_labels,  
                song_ratings=song_ratings
                )  
    else:
        flash('You are not authorized to access the admin dashboard.', "danger")
        return redirect(url_for('login'))

@app.route('/admin_login', methods=['POST'])
def admin_login_post():
    username = request.form.get('username')
    password = request.form.get('password')

    if username == '' or password == '':
        flash('Please fill out all fields', "danger")
        return redirect(url_for('admin_login'))

    admin_user = User.query.filter_by(username=username, is_admin=True).first()

    if not admin_user or not admin_user.check_password(password):
        flash('Invalid admin username or password', "danger")
        return redirect(url_for('admin_login'))

    session['user_id'] = admin_user.user_id
    return redirect(url_for('admin_dashboard'))

@app.route('/register') 
def login_register_page():
    return render_template('register.html')

@app.route('/register', methods=['POST'])
def register_post():
    username = request.form.get('username')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm_password')
    role = request.form.get('role') 
    if username == '' or password == '' or confirm_password == '' or not role:
        flash('Please fill out all fields and select a role', "danger")
        return redirect('register')
    if password != confirm_password:
        flash('Password and confirm password do not match. Please try again.', "danger")
        return redirect('register')
    if User.query.filter_by(username=username).first():
        flash('Username already in use. Please choose a different username.', "danger")
        return redirect('register')

    user = User(username=username, role=role)  
    user.set_password(password)
    db.session.add(user)
    db.session.commit()

    flash('Registration successful. You can now log in.', "success")
    return redirect(url_for('login'))

'''@app.route('/signup_as_creator')
@auth_required
def signup_as_creator():
    return render_template('signup_as_creator.html')'''

@app.route('/signup_as_creator', methods=['GET'])
@auth_required
def signup_as_creator():
    user = User.query.get(session['user_id'])
    return render_template('signup_as_creator.html', user=user)

@app.route('/change_role_to_creator', methods=['POST'])
@auth_required
def change_role_to_creator():
    
    user = User.query.get(session['user_id'])
    created_songs = Song.query.filter_by(creator_id=session['user_id']).all()
    
    user.role = 'Creator'

    db.session.commit()
    
    flash('Congratulations! You are now a Creator.', "success")
    return redirect(url_for('index'))


@app.route('/your_playlists')
@auth_required
def your_playlists():
    user_id = session['user_id']
    user = User.query.get(user_id)
    playlist_entry = Playlist.query.filter_by(user_id=user_id)
    blacklist_creator = CreatorBlacklist.query.filter_by(creator_id=user_id).first()
    if blacklist_creator:
        flash('You have been blacklisted from creating playlists.', "danger")
        return redirect(url_for('index'))
    else:
        return render_template('your_playlists.html', user=user, playlist=playlist_entry)  

@app.route('/creator_dashboard')
@creator_required
def creator_dashboard():
    user = User.query.get(session['user_id'])
    albums = user.created_albums
    return render_template('creator_dashboard.html', user=user,albums=albums)


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', "success")
    return redirect(url_for('login'))

@app.route('/albums/add')
@creator_required
def add_album():
    return render_template('albums/add.html',user=User.query.get(session['user_id']))

@app.route('/albums/add', methods=['POST'])
@creator_required
def add_album_post():
    title = request.form.get('title')
    if title == '':
        flash('Please enter a title', "success")
        return redirect(url_for('add_album'))
    release_date = request.form.get('release_date')
    if release_date:
        try:
            release_date = datetime.datetime.strptime(release_date, '%Y-%m-%d')
        except ValueError:
            flash('Invalid date format. Please use YYYY-MM-DD.', "danger")
            return redirect(url_for('index'))
        
    genre = request.form.get('genre')
    album = Album(title=title, release_date=release_date, genre=genre, creator_id=session['user_id'])
    db.session.add(album)
    db.session.commit()
    flash('Album added successfully', 'success')
    return redirect(url_for('creator_dashboard'))


#-----adding music files (mp3) --------------------------------#
ALLOWED_EXTENSIONS = {'mp3'}
app.config['UPLOAD_FOLDER'] = 'uploads'

#---------- Function to check if the file extension is allowed-------#
def allowed_song_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
#--------------- Sends static music files to browser ---------#
@app.route('/uploads/<path:path>')
def send_static_music(path):
    return send_from_directory('uploads', path)


@app.route('/albums/<int:album_id>/delete')
@creator_required
def delete_album(album_id):
    user=User.query.get(session['user_id'])
    albums = user.created_albums
    return render_template('albums/delete.html', user=user, albums=albums)

@app.route('/albums/<int:album_id>/delete', methods=['POST'])
@creator_required
def delete_album_post(album_id):
    # ------ Retrieve the album with the given ID from the database---#
    album = Album.query.get(album_id)
    if not album:
        flash('Album not found', 'error')
        return redirect(url_for('creator_dashboard'))

    db.session.delete(album)
    db.session.commit()
    flash('Album deleted successfully', 'success')
    return redirect(url_for('creator_dashboard'))

@app.route('/albums/<int:album_id>/edit')
@creator_required
def edit_album(album_id):
    user = User.query.get(session['user_id'])
    return render_template('albums/edit.html', album=Album.query.get(album_id), user=user)

@app.route('/albums/<int:album_id>/edit', methods=['POST'])
@creator_required
def edit_album_post(album_id):
    
    album = Album.query.get(album_id)
    if not album:
        flash('Album not found', 'danger')
        return redirect(url_for('creator_dashboard'))

    new_title = request.form.get('title')
    release_date_str = request.form.get('release_date')
    new_genre = request.form.get('genre')

    if not new_title or not release_date_str or not new_genre:
        flash('Please fill out all fields', 'danger')
        return redirect(url_for('edit_album', album_id=album_id))

    new_release_date = None

    if release_date_str:
        try:
            new_release_date = datetime.datetime.strptime(release_date_str, '%Y-%m-%d')
        except ValueError:
            flash('Invalid date format. Please use YYYY-MM-DD.', "danger")
            return redirect(url_for('edit_album', album_id=album_id))

    album.title = new_title
    album.release_date = new_release_date
    album.genre = new_genre

    db.session.commit()
    
    flash('Album updated successfully', 'success')
    return redirect(url_for('creator_dashboard'))
    

@app.route('/albums/<int:album_id>/show')
@creator_required  
def show_album(album_id):
    return render_template('albums/show.html',user=User.query.get(session['user_id']),album=Album.query.get(album_id))

@app.route('/albums/<int:album_id>/songs/add', methods=['GET', 'POST'])
@creator_required
def add_song(album_id):
    if request.method == 'POST':
        title = request.form.get('title')
        artist = request.form.get('artist')
        lyrics = request.form.get('lyrics')
        genre = request.form.get('genre')

        song_file = request.files['song_file']
        
        if not title or not artist or not lyrics or not genre or not song_file or not song_file.filename:
            flash('Please fill out all fields, including the song file', 'danger')
        
        elif not allowed_song_file(song_file.filename):
            flash('Invalid file type. Please upload an MP3 file.', 'danger')
            
        else:
            secured_song_name = secure_filename(song_file.filename)
        
            new_song = Song(title=title, artist=artist, lyrics=lyrics, genre=genre, creator_id=session['user_id'], album_id=album_id, filename=secured_song_name)
            db.session.add(new_song)
            db.session.commit()
            
            song_file.save(os.path.join('uploads',secured_song_name))
        
            flash('New song created successfully', 'success')
            return redirect(url_for('creator_dashboard'))

    return render_template('songs/add.html',user=User.query.get(session['user_id']) , album_id=album_id)


@app.route('/songs/<int:song_id>/delete')
@creator_required
def delete_song(song_id):
    return render_template('songs/delete.html', song=Song.query.get(song_id),user=User.query.get(session['user_id']))

@app.route('/songs/<int:song_id>/delete', methods=['POST'])
@creator_required
def delete_song_post(song_id):
    song = Song.query.get(song_id)
    
    if not song:
        flash('Song not found', 'danger')
        return redirect(url_for('creator_dashboard'))

    # Perform the deletion
    db.session.delete(song)
    db.session.commit()

    flash('Song deleted successfully', 'success')
    return redirect(url_for('creator_dashboard'))

@app.route('/songs/<int:song_id>/edit')
@creator_required
def edit_song(song_id):
    user = User.query.get(session['user_id'])
    return render_template('songs/edit.html', song=Song.query.get(song_id), user=user)

@app.route('/songs/<int:song_id>/edit', methods=['POST'])
@creator_required
def edit_song_post(song_id):
    song = Song.query.get(song_id)
    
    if not song:
        flash('Song not found', 'danger')
        return redirect(url_for('creator_dashboard'))

    if request.method == 'POST':
        title = request.form.get('title')
        artist = request.form.get('artist')
        lyrics = request.form.get('lyrics')
        genre = request.form.get('genre')

        # Update the song attributes
        song.title = title
        song.artist = artist
        song.lyrics = lyrics
        song.genre = genre

        db.session.commit()

        flash('Song updated successfully', 'success')
        return redirect(url_for('creator_dashboard'))
    
    return render_template('songs/edit.html', song=song)

@app.route('/songs/<int:song_id>/rate', methods=['POST'])
def rate_song(song_id):
    rating = request.form['rating']
    song = Song.query.get(song_id)
    
    if rating == 'like':
        song.rating += 1
    elif rating == 'dislike':
        song.rating -= 1
    
    db.session.commit()
    
    flash(f'Song rated {rating} successfully', 'success')
    return redirect(url_for('index'))

@app.route('/index')
def index_home():

    return redirect(url_for('index'))

@app.route('/add_to_playlist/<int:song_id>', methods=['POST'])
@auth_required  
def add_to_playlist(song_id):
    
    user_id = session['user_id']   
    song = Song.query.get(song_id)

    in_db_playlist = Playlist.query.filter_by(user_id=user_id, song_id=song_id).first()
    if in_db_playlist is not None:
        flash("Playlist Entry is already made", "danger")
        return redirect(url_for('index'))
    if song is not None:
        playlist_entry = Playlist(user_id=user_id, song_id=song_id)
        db.session.add(playlist_entry)
        db.session.commit()

    return redirect(url_for('your_playlists')) 

@app.route('/playlists/<int:song_id>')
@auth_required
def your_playlists_1(song_id):
    user = User.query.get(session['user_id'])
    playlist = Playlist.query.filter(Playlist.user_id == session['user_id']).all()
    return render_template('your_playlists.html', user=user, playlist=playlist, song_id=song_id)


@app.route('/flagged_songs')
@admin_reqequired
def flagged_songs():
    user = User.query.get(session['user_id'])
    all_songs = Song.query.all()
    return render_template('flagged_songs.html', all_songs=all_songs, user=user)

@app.route('/flag_song/<int:song_id>', methods=['POST'])
@admin_reqequired
def flag_song(song_id):
    song = Song.query.get(song_id)
    if song:
        if not song.is_flag:
            song.is_flag = True
            db.session.commit()
            flash('Song has been flagged', 'success')
        else:
            flash('Song is already flagged', 'danger')
    return redirect(url_for('flagged_songs'))

@app.route('/unflag_song/<int:song_id>', methods=['POST'])
@admin_reqequired
def unflag_song(song_id):
    song = Song.query.get(song_id)
    if song:
        if song.song_id:
            song.is_flag = False
            db.session.commit()
            flash('Song has been unflagged', 'success')
        else:
            flash('Song is not flagged', 'danger')
    return redirect(url_for('flagged_songs'))

@app.route('/remove_song/<int:song_id>', methods=['POST'])
@admin_reqequired
def remove_song(song_id):
    song = Song.query.get(song_id)
    if song:
        db.session.delete(song)
        db.session.commit()
    return redirect(url_for('flagged_songs'))

@app.route('/review_creator')
@admin_reqequired
def review_creator(): 
    user = User.query.get(session['user_id'])
    creators = User.query.filter_by(role='Creator').all()
    return render_template('review_creator.html', user=user, creators=creators)


@app.route('/blacklist_creator/<int:creator_id>', methods=['POST'])
def blacklist_creator(creator_id):
    admin_id = session['user_id'] 
 
    
    creator_blacklist = CreatorBlacklist.query.filter_by(admin_id=admin_id, creator_id=creator_id).first()
    if creator_blacklist:
        flash('Creator is already blacklisted.', 'danger')
    else:
        creator_blacklist = CreatorBlacklist(admin_id=admin_id, creator_id=creator_id)
        db.session.add(creator_blacklist)
        db.session.commit()
        flash('Creator has been blacklisted.', 'success')
 
    return redirect(url_for('review_creator'))
 
#------- Route to whitelist a creator ---------------#
@app.route('/whitelist_creator/<int:creator_id>', methods=['POST'])
def whitelist_creator(creator_id):
    admin_id = session['user_id']  
    creator_blacklist = CreatorBlacklist.query.filter_by(admin_id=admin_id, creator_id=creator_id).first()
    if creator_blacklist:
        db.session.delete(creator_blacklist)
        db.session.commit()
        flash('Creator has been whitelisted.','success')
    else:
        flash('Creator was not blacklisted.','danger')
    return redirect(url_for('review_creator'))


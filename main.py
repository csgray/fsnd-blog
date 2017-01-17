#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import re
from string import letters

import webapp2
import jinja2
import hashlib
import hmac
import random
import string

from google.appengine.ext import db

# Jinja2 template support
template_dir = os.path.join(os.path.dirname(__file__), "templates")
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

def render_string(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

# Hashing support
secret = '02Py3bQnNTw8MHwNCu0Z'

def make_secure_val(val):
    return "%s|%s" % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

# Blog
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_string(self, template, **params):
        return render_string(template, **params)

    def render(self, template, **kw):
        self.write(self.render_string(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val)
        )

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

def render_post(response, post):
    response.out.write("<b>" + post.subject + "</b><br>")
    response.out.write(post.content)

def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
    salt = h.split(',')[1]
    return h == make_pw_hash(name, pw, salt)

# Database Ancestors
def users_key(group='default'):
    return db.Key.from_path('users', group)

def blog_key(name="testing"):
    return db.Key.from_path("blogs", name)

# Database Objects
class Post(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)
    created_by = db.StringProperty(required=True)

    def render(self):
        self._render_text = self.content.replace("\n", "<br>")
        return render_string("post.html", p=self)

class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty

    @classmethod
    def by_id(cls, uid):
        return cls.get_by_id(uid, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = cls.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return cls(parent=users_key(),
                   name=name,
                   pw_hash=pw_hash,
                   email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

# Signup verification functions
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):
    return not email or EMAIL_RE.match(email)

# Page Handlers
class MainPage(Handler):
    def get(self):
        self.write(self.render_string("main.html"))

class FrontPage(Handler):
    def get(self):
        posts = db.GqlQuery("select * from Post order by created desc")
        username = None
        if self.user:
            username = self.user.name
        self.render("front.html", posts=posts, username=username)

class PostPage(Handler):
    def get(self, post_id):
        key = db.Key.from_path("Post", int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post)

class NewPost(Handler):
    def get(self):
        self.render("newpost.html")

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        created_by = self.user.name

        if subject and content:
            p = Post(parent=blog_key(), subject=subject, content=content, created_by=created_by)
            p.put()
            self.redirect("/blog/%s" % str(p.key().id()))
        else:
            error = "Blog posts need both a subject and content."
            self.render("newpost.html", subject=subject, content=content, error=error)

class SignUp(Handler):
    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        self.username = self.request.get("username")
        self.password = self.request.get("password")
        self.verify = self.request.get("verify")
        self.email = self.request.get("email")

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        # Check if the user already exists
        u = User.by_name(self.username)
        if u:
            msg = "That user already exists."
            self.render('signup.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog/welcome')

class Login(Handler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog/welcome')
        else:
            msg = "Invalid login."
            self.render('login.html', error=msg)

class Logout(Handler):
    def get(self):
        self.logout()
        self.redirect('/blog/signup')

class Welcome(Handler):
    def get(self):
        if self.user:
            self.render('welcome.html', username=self.user.name)
        else:
            self.redirect('/blog/signup')

class Edit(Handler):
    def get(self, post_id):
        key = db.Key.from_path("Post", int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("edit.html", post=post, subject = post.subject, content = post.content)
    
    def post(self, post_id):
        subject = self.request.get("subject")
        content = self.request.get("content")
        key = db.Key.from_path("Post", int(post_id), parent=blog_key())
        p = db.get(key)

        if self.user:
            username = self.user.name 

        if p.created_by == username:
            if subject and content:
                p.subject = self.request.get("subject")
                p.content = self.request.get("content")
                p.put()
                self.redirect("/blog/%s" % post_id)
            else:
                error = "Blog posts need both a subject and content."
                self.render("newpost.html", subject=subject, content=content, error=error)
        
        else:
            error = "You do not have permission to edit this post."
            self.render("edit.html", post=p, error=error)

class Delete(Handler):
    def get(self, post_id):
        key = db.Key.from_path("Post", int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("delete.html", post=post)
    
    def post(self, post_id):
        key = db.Key.from_path("Post", int(post_id), parent=blog_key())
        p = db.get(key)

        if self.user:
            username = self.user.name

        if p.created_by == username:
            p.delete()
            self.redirect("/blog/")
        
        else:
            error = "You do not have permission to delete this post."
            self.render("delete.html", post=p, error=error)

class Comment(Handler):
    def get(self, post_id):
        key = db.Key.from_path("Post", int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("comment.html", post=post)

# Page handlers
app = webapp2.WSGIApplication([("/", MainPage),
                               ("/blog/?", FrontPage),
                               ("/blog/([0-9]+)", PostPage),
                               ("/blog/newpost", NewPost),
                               ("/blog/signup", SignUp),
                               ("/blog/welcome", Welcome),
                               ("/blog/login", Login),
                               ("/blog/logout", Logout),
                               ("/blog/([0-9]+)/edit", Edit),
                               ("/blog/([0-9]+)/delete", Delete),
                               ("/blog/([0-9]+)/comment", Comment),
                              ], debug=True)

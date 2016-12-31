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

from google.appengine.ext import db

# Jinja2 template support
template_dir = os.path.join(os.path.dirname(__file__), "templates")
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

def render_string(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)
    
    def render_string(self, template, **params):
        return render_string(template, **params)
    
    def render(self, template, **kw):
        self.write(self.render_string(template, **kw))

def render_post(response, post):
    response.out.write("<b>" + post.subject + "</b><br>")
    response.out.write(post.content)

class MainPage(Handler):
    def get(self):
        self.write(self.render_string("main.html"))

# Blog
def blog_key(name = "testing"):
    return db.Key.from_path("blogs", name)

class Post(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    def render(self):
        self._render_text = self.content.replace("\n", "<br>")
        return render_string("post.html", p = self)

class FrontPage(Handler):
    def get(self):
        posts = db.GqlQuery("select * from Post order by created desc")
        self.render("front.html", posts = posts)

class PostPage(Handler):
    def get(self, post_id):
        key = db.Key.from_path("Post", int(post_id), parent=blog_key())
        post = db.get(key)

        # TODO: Make a better 404 template!
        if not post:
            self.error(404)
            return
        
        self.render("permalink.html", post = post)

class NewPost(Handler):
    def get(self):
        self.render("newpost.html")
    
    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            p = Post(parent = blog_key(), subject = subject, content = content)
            p.put()
            self.redirect("/blog/%s" % str(p.key().id()))
        else:
            error = "Blog posts need both a subject and content."
            self.render("newpost.html", subject = subject, content = content, error = error)

# Page handlers
app = webapp2.WSGIApplication([("/", MainPage),
                               ("/blog/?", FrontPage),
                               ("/blog/([0-9]+)", PostPage),
                               ("/blog/newpost", NewPost),
                               ], debug=True)

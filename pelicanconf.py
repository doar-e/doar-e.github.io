#!/usr/bin/env python
# -*- coding: utf-8 -*- #
from __future__ import unicode_literals

AUTHOR = u"Axel '0vercl0k' Souchet"
SITENAME = u'Diary of a reverse-engineer'
SITEURL = ''

PATH = 'content'

TIMEZONE = 'America/Los_Angeles'

DEFAULT_LANG = u'English'

# Feed generation is usually not desired when developing
FEED_ATOM = 'feeds/atom.xml'
FEED_RSS = 'feeds/rss.xml'
FEED_ALL_ATOM = 'feeds/all.atom.xml'
CATEGORY_FEED_ATOM = 'feeds/category.%s.atom.xml'
AUTHOR_FEED_ATOM = 'feeds/author.%s.atom.xml'

STATIC_PATHS = ['downloads', 'images', 'presentations']
ARTICLE_PATHS = ['articles']

MARKDOWN = {
  'extension_configs': {
    'markdown.extensions.toc': {
      'title': 'Table of contents:'
    },
    'markdown.extensions.codehilite': {
        'css_class': 'highlight',
    },
    'markdown.extensions.extra': {},
    'markdown.extensions.meta': {},
  },
  'output_format': 'html5',
}

PLUGIN_PATHS = ['plugins']
PLUGINS = ['summary']

THEME = 'themes/bootstrap2'

TWITTER_USERNAME = ''

# Social widget
SOCIAL = (
    ('@doar_e', 'https://twitter.com/doar_e'),
    ('@0vercl0k', 'https://twitter.com/0vercl0k'),
    ('@jonathansalwan', 'https://twitter.com/jonathansalwan'),
    ('@__x86', 'https://twitter.com/__x86'),
)

DEFAULT_PAGINATION = 10
DISPLAY_PAGES_ON_MENU = True

ARTICLE_URL = 'blog/{date:%Y}/{date:%m}/{date:%d}/{slug}/'
ARTICLE_SAVE_AS = 'blog/{date:%Y}/{date:%m}/{date:%d}/{slug}/index.html'

# Uncomment following line if you want document-relative URLs when developing
#RELATIVE_URLS = True

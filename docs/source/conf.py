# https://www.sphinx-doc.org/en/master/usage/configuration.html

# import os
# import sys
# sys.path.insert(0, os.path.abspath('.'))


project = 'Lith'
copyright = '2021, Piotr Husiatyński'
author = 'Piotr Husiatyński'


extensions = [
        "m2r2",
        "sphinxcontrib.httpdomain",
        "sphinxcontrib.httpexample",
]
source_suffix = ['.rst', '.md']

templates_path = ['_templates']

exclude_patterns = []

html_theme = 'sphinx_book_theme'

html_theme_options = {
  "external_links": [
      ("GitHub", "https://github.com/husio/lith"),
  ]
}
html_css_files = ["css/custom.css"]

html_static_path = ['_static']

httpexample_scheme = 'https'
http_strict_mode = True

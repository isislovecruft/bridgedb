"""Sphinx/docutils extension to create links to a Trac site using a
RestructuredText interpreted text role that looks like this::

    :trac:`trac_link_text`

For example::

    :trac:`2015`

would create a link to ticket number #2015 (e.g. the link URI would be
https://bugs.torproject.org/2015).

Adapted from recipe here_.

.. _here: http://stackoverflow.com/a/2111327/13564
"""

import urllib
from docutils import nodes, utils

def make_trac_link(name, rawtext, text, lineno, inliner,
                   options={}, content=[]):

    # quick, dirty, and ugly...
    if '<' in text and '>' in text:
        full_name, label = text.split('<')
        full_name = full_name.strip()
        label = label.strip('>').strip()
    else:
        full_name = text
        label = full_name

    env = inliner.document.settings.env
    base_url =  env.config.traclinks_base_url
    label = utils.unescape('ticket #' + label)
    ref = base_url + urllib.quote(full_name, safe='')
    node = nodes.reference(rawtext, label, refuri=ref, **options)

    return [node],[]


def setup(app):
    """setup function to register the extension"""
    app.add_config_value('traclinks_base_url',
                         'https://bugs.torproject.org/',
                         'env')
    app.add_role('trac', make_trac_link)

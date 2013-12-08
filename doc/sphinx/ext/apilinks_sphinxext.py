'''
Sphinx/docutils extension to create links to pyDoctor documentation using
a RestructuredText interpreted text role that looks like this:

    :api:`python_object_to_link_to <label>`

for example:

    :api:`twisted.internet.defer.Deferred <Deferred>`

Note, this is downloaded from:

   https://bazaar.launchpad.net/~khorn/pydoctor/sphinxext/view/head:/apilinks_sphinxext.py

with a couple local tweaks ("label = full_name" and https for URL).
'''

def make_api_link(name, rawtext, text, lineno, inliner,
                     options={}, content=[]):

    from docutils import nodes, utils

    # quick, dirty, and ugly...
    if '<' in text and '>' in text:
        full_name, label = text.split('<')
        full_name = full_name.strip()
        label = label.strip('>').strip()
    else:
        full_name = text
        label = full_name

    #get the base url for api links from the config file
    env = inliner.document.settings.env
    base_url =  env.config.apilinks_base_url

    # not really sufficient, but just testing...
    # ...hmmm, maybe this is good enough after all
    ref = ''.join((base_url, full_name, '.html'))

    node = nodes.reference(rawtext, utils.unescape(label), refuri=ref,
                           **options)

    nodes = [node]
    sys_msgs = []
    return nodes, sys_msgs


# setup function to register the extension

def setup(app):
    app.add_config_value('apilinks_base_url',
                         'https://twistedmatrix.com/documents/current/api/',
                         'env')
    app.add_role('api', make_api_link)


# -*- mode: markdown ; coding: utf-8 -*-

HACKING
=======

Hack on whatever you like. Ticket are [here][trac]. If you're doing something
big that doesn't have a ticket, you should probably make one. If you don't
want to register for a Trac account, you can use the ```cypherpunks``` account
with password ```writecode```.

## Git Workflow

See this article on git branching [workflow][workflow]. The only modifications
we make are:

  * Tagging is done in the ```release-*``` branches, rather than in master.
  * It's okay to use either the ```feature/*``` and ```fix/*``` branch naming
    scheme, or follow little-t Tor's branch naming scheme,
    i.e. ```bug666-description-r1```.

## Making a release

### Bumping the version number

Bumping the version number at release time (which, for BridgeDB really means
deploy time, as of right now) means doing the following:

    $ git checkout develop
    [merge some fix/bug/feature/etc branches]
    $ git checkout -b release-0.0.2 develop
    $ git tag -a -s bridgedb-0.0.2
    [pip maintainance commands *would* go here, if we ever have any]
    $ git checkout master
    $ git merge -S --no-ff release-0.0.2
    $ git checkout develop
    $ git merge -S --no-ff master
    $ git push <remote> master develop

And be sure not to forget to do:

    $ git push --tags

If the currently installed version is *not* from one of the signed tags, the
version number attribute created by versioneer will be the short ID of the git
commit from which the installation took place, prefixed with the most recent
tagged release at that point, i.e.:

    >>> import bridgedb
    >>> bridgedb.__version__
    0.0.1-git528ff30c

References
----------
[trac]: https://trac.torproject.org/projects/tor/query?status=accepted&status=assigned&status=needs_information&status=needs_review&status=needs_revision&status=new&status=reopened&component=BridgeDB&groupdesc=1&group=priority&col=id&col=summary&col=status&col=type&col=priority&col=changetime&report=34&order=priority
[workflow]: http://nvie.com/posts/a-successful-git-branching-model/

## teamcity-ldap-sync -- Sync your Teamcity groups and users with LDAP directory server

The *teamcity-ldap-sync* script is used for one side sync of existing LDAP groups and users into Teamcity.
Idea taken [zabbix-ldap-sync](https://github.com/dnaeon/zabbix-ldap-sync)

##### Tested on:
* Linux 4.14.3-1
* Python 2.7.12, 2.7.14 and Python 3.6.3
* ldap3==2.4 and requests==2.18.4

##### For test and development:
Copy-paste to your shell
```bash
cd && mkdir teamcity-test-srv && \
docker run -it --name teamcity-server \
-v $HOME/teamcity-test-srv/:/data/teamcity_server/datadir \
-v $HOME/teamcity-test-srv/:/opt/teamcity/logs      \
-p 80:8111     \
jetbrains/teamcity-server:10.0.4
```
Open browser, configure teamcity, paste user credential to teamcity-ldap.conf, test it.

## Requirements

* Python 2.7.x - Python 3.6.*
* [ldap3](https://github.com/cannatag/ldap3)
* [requests](https://github.com/requests/requests)


## Configuration

Teamcity user should have System Administrator role.

### Config file sections

#### [ldap]
* `type` - Select type of ldap server, can be `activedirectory` or `openldap`
* `uri` - URI of the LDAP server, including port
* `base` - Base `Distinguished Name`
* `binduser` - LDAP user which has permissions to perform LDAP search
* `bindpass` - Password for LDAP user
* `groups` - LDAP groups to sync with Teamcity (support wildcard - TESTED ONLY with Active Directory, see Command-line arguments)

#### [ad]
* `filtergroup` = The ldap filter to get group in ActiveDirectory mode, by default `(&(objectClass=group)(name=%s))`
* `filteruser` = The ldap filter to get the users in ActiveDirectory mode, by default `(objectClass=user)(objectCategory=Person)`
* `filterdisabled` = The filter to get the disabled user in ActiveDirectory mode, by default `(!(userAccountControl:1.2.840.113556.1.4.803:=2))`
* `filtermemberof` = The filter to get memberof in ActiveDirectory mode, by default `(memberOf:1.2.840.113556.1.4.1941:=%s)`
* `groupattribute` = The attribute used for membership in a group in ActiveDirectory mode, by default `member`
* `userattribute` = The attribute for users in ActiveDirectory mode `sAMAccountName`

#### [openldap]
* `type` = The storage mode for group and users can be `posix` or `groupofnames`
* `filtergroup` = The ldap filter to get group in OpenLDAP mode, by default `(&(objectClass=posixGroup)(cn=%s))`
* `filteruser` = The ldap filter to get the users in OpenLDAP mode, by default `(&(objectClass=posixAccount)(uid=%s))`
* `groupattribute` = The attribute used for membership in a group in OpenLDAP mode, by default `memberUid`
* `userattribute` = The attribute for users in openldap mode, by default `uid`

#### [teamcity]
* `server` - Teamcity URL
* `username` - Teamcity username.
* `password` - Teamcity user password


## Configuration file example

    [ldap]
    type = activedirectory
    uri = ldaps://company.com:636/
    base = dc=company,dc=com
    binduser = domain_login
    bindpass = domain_password
    groups = R.*.Teamcity.*

    [ad]
    filtergroup = (&(objectClass=group)(name=%s))
    filteruser = (objectClass=user)(objectCategory=Person)
    filterdisabled = (!(userAccountControl:1.2.840.113556.1.4.803:=2))
    filtermemberof = (memberOf:1.2.840.113556.1.4.1941:=%s)
    groupattribute = member
    userattribute = sAMAccountName

    [openldap]
    type = posix
    filtergroup = (&(objectClass=posixGroup)(cn=%s))
    filteruser = (&(objectClass=posixAccount)(uid=%s))
    groupattribute = memberUid
    userattribute = uid

    [teamcity]
    server = https://teamcity.company.com
    username = teamcity_user_login
    password = teamcity_user_password


## Command-line arguments

    Usage: teamcity-ldap-sync [-sr] -f <config>
           teamcity-ldap-sync -h

    Options:
      -h, --help                    Display this usage info
      -s, --skip-disabled           Skip disabled AD users
      -r, --recursive               Resolves AD group members recursively (i.e. nested groups)
      -f <config>, --file <config>  Configuration file to use

## Importing LDAP users into Teamcity

Now that we have the above mentioned configuration file created, let's import our groups and users from LDAP to Teamcity.

	$ teamcity-ldap-sync -f /path/to/teamcity-ldap.conf

You would generally be running the above scripts on regular basis, say each day from `cron(8)` in order to make sure your Teamcity is in sync with LDAP.

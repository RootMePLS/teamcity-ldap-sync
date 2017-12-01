import ldap3
from ldap3 import Server, Connection, AUTO_BIND_NO_TLS, SUBTREE, ALL_ATTRIBUTES, ALL, BASE
from urllib.parse import urlparse
import requests
import json
import configparser
import argparse


def get_args():
    """Get command line args from the user"""
    parser = argparse.ArgumentParser(description="Standard Arguments")

    parser.add_argument("-f", "--file",
                        required=True,
                        help="Configuration file to use")

    parser.add_argument("-w", "--wildcard-search",
                        required=False,
                        action='store_true',
                        help="Search AD group with wildcard (e.g. R.*.Teamcity.*) - TESTED ONLY with Active Directory")

    parser.add_argument("-r", "--recursive",
                        required=False,
                        action='store_true',
                        help='Resolves AD group members recursively (i.e. nested groups)')

    parser.add_argument("-l", "--lowercase",
                        required=False,
                        action='store_true',
                        help="Create AD user names as lowercase")

    parser.add_argument("-s", "--skip-disabled",
                        required=False,
                        action='store_true',
                        help="Skip disabled AD users")

    args = parser.parse_args()

    return args


class LDAPConn(object):
    """
    LDAP connector class

    Defines methods for retrieving users and groups from LDAP server.

    """

    def __init__(self, uri, base, user, passwd):
        # self.uri = uri
        self.uri = urlparse(uri)
        self.base = base
        self.ldap_user = user
        self.ldap_pass = passwd

    def connect(self):
        """
        Establish a connection to the LDAP server.

        Raises:
            SystemExit

        """

        server = Server(host=self.uri.hostname,
                        port=self.uri.port,
                        get_info=ALL)
        self.conn = Connection(server=server,
                               user=self.ldap_user,
                               password=self.ldap_pass,
                               check_names=True,
                               raise_exceptions=True)

        self.conn.bind()

    def disconnect(self):
        """
        Disconnect from the LDAP server.

        """
        self.conn.unbind()

    def get_group_members(self, group):
        """
        Retrieves the members of an LDAP group

        Args:
            group (str): The LDAP group name

        Returns:
            A list of all users in the LDAP group

        """
        attrlist = [group_member_attribute]
        filter = group_filter % group

        # result = self.conn.search_s(base=self.base,
        #                             scope=ldap.SCOPE_SUBTREE,
        #                             filterstr=filter,
        #                             attrlist=attrlist)

        result = self.conn.search(search_base=self.base,
                                  search_scope=SUBTREE,
                                  search_filter=filter,
                                  attributes=attrlist)
        if not result:
            print('>>> Unable to find group %s, skipping group' % group)
            return None

        # Get DN for each user in the group
        if active_directory:

            final_listing = {}

            result = json.loads(self.conn.response_to_json())['entries']

            for members in result:
                result_dn = members.get('dn')
                result_attrs = members.get('attributes')

            group_members = []
            attrlist = [uid_attribute]

            if recursive:
                # Get a DN for all users in a group (recursive)
                # It's available only on domain controllers with Windows Server 2003 SP2 or later

                member_of_filter_dn = memberof_filter % result_dn

                if skipdisabled:
                    filter = "(&%s%s%s)" % (user_filter, member_of_filter_dn, disabled_filter)
                else:
                    filter = "(&%s%s)" % (user_filter, member_of_filter_dn)

                uid = self.conn.search(search_base=self.base,
                                       search_scope=SUBTREE,
                                       search_filter=filter,
                                       attributes=attrlist)

                if uid:
                    group_members = self.conn.response_to_json()
                    group_members = json.loads(group_members)['entries']

            else:
                # Otherwise, just get a DN for each user in the group
                for member in result_attrs[group_member_attribute]:
                    if skipdisabled:
                        filter = "(&%s%s)" % (user_filter, disabled_filter)
                    else:
                        filter = "(&%s)" % user_filter

                    uid = self.conn.search(search_base=member,
                                           search_scope=SUBTREE,
                                           search_filter=filter,
                                           attributes=attrlist)

                    if uid:
                        group_members = self.conn.response_to_json()
                        group_members = json.loads(group_members)['entries']

            # Fill dictionary with usernames and corresponding DNs
            for item in group_members:
                dn = item.get('dn')
                username = item.get('attributes').get('sAMAccountName')

                if lowercase:
                    username = username.lower()

                final_listing[username] = dn

            return final_listing

        else:

            dn, users = result.pop()

            final_listing = {}

            # Get DN for each user in the group
            for uid in users[group_member_attribute]:

                if openldap_type == "groupofnames":
                    uid = uid.split('=', 2)
                    uid = uid[1].split(',', 1)
                    uid = uid[0]

                filter = user_filter % uid
                attrlist = [uid_attribute]

                # get the actual LDAP object for each group member
                user = self.conn.search_s(base=self.base,
                                          scope=ldap.SCOPE_SUBTREE,
                                          filterstr=filter,
                                          attrlist=attrlist)

                for items in user:
                    final_listing[uid] = items[0]

            return final_listing

    def get_groups_with_wildcard(self, groups_wildcard):
        print(">>> Search group with wildcard: %s" % groups_wildcard)

        filter = group_filter % groups_wildcard
        result_groups = []

        result = self.conn.search(search_base=self.base,
                                  search_scope=SUBTREE,
                                  search_filter=filter,
                                  attributes='cn')

        if result:
            result = json.loads(self.conn.response_to_json())['entries']
            for group in result:
                group_name = group['attributes'].get('cn')
                result_groups.append(group_name)

        if not result_groups:
            print('>>> Unable to find group %s, skipping group wildcard' % groups_wildcard)

        return result_groups

    def get_user_attributes(self, dn, attr_list):
        """
        Retrieves the 'media' attribute of an LDAP user

        Args:
            username (str): The LDAP distinguished name to lookup
            ldap_media (str): The name of the field containing the media address

        Returns:
            The user's media attribute value

        """

        filter = '(distinguishedName=%s)' % dn

        self.conn.search(search_base=self.base,
                         search_filter=filter,
                         search_scope=SUBTREE,
                         attributes=attr_list)

        if not self.conn:
            return None

        result = json.loads(self.conn.response_to_json())['entries'][0]['attributes']

        return result


class TeamCityLDAPConf(object):
    """
    TeamCity-LDAP configuration class
    Provides methods for parsing and retrieving config entries
    """

    def __init__(self, config):
        self.config = config

    def try_get_item(self, parser, section, option, default):
        """
        Gets config item

        Args:
            parser  (configparser): configparser
            section          (str): Config section name
            option           (str): Config option name
            default               : Value to return if item doesn't exist

        Returns:
            Config item value or default value

        """

        try:
            result = parser.get(section, option)
        except (configparser.NoOptionError, configparser.NoSectionError):
            result = default

        return result

    def try_get_section(self, parser, section, default):
        """
        Gets config section

        Args:
            parser  (configparser): configparser
            section          (str): Config section name
            default               : Value to return if section doesn't exist

        Returns:
            Config section dict or default value

        """

        try:
            result = parser.items(section)
        except configparser.NoSectionError:
            result = default

        return result

    def remove_config_section_items(self, section, items):
        """
        Removes items from config section

        Args:
            section     (list of tuples): Config section
            items                 (list): Item names to remove

        Returns:
            Config section without specified items

        """

        return [i for i in section if i[0] not in items]

    def load_config(self):
        """
        Loads the configuration file

        Raises:
            configparser.NoOptionError

        """
        parser = configparser.RawConfigParser()
        parser.read(self.config, encoding='utf-8')

        try:
            self.ldap_type = self.try_get_item(parser, 'ldap', 'type', None)

            self.ldap_uri = parser.get('ldap', 'uri')
            self.ldap_base = parser.get('ldap', 'base')

            self.ldap_groups = [i.strip() for i in parser.get('ldap', 'groups').split(',')]

            self.ldap_user = parser.get('ldap', 'binduser')
            self.ldap_pass = parser.get('ldap', 'bindpass')

            self.ldap_media = self.try_get_item(parser, 'ldap', 'media', 'mail')

            self.ad_filtergroup = parser.get('ad', 'filtergroup')
            self.ad_filteruser = parser.get('ad', 'filteruser')
            self.ad_filterdisabled = parser.get('ad', 'filterdisabled')
            self.ad_filtermemberof = parser.get('ad', 'filtermemberof')
            self.ad_groupattribute = parser.get('ad', 'groupattribute')
            self.ad_userattribute = parser.get('ad', 'userattribute')

            self.openldap_type = parser.get('openldap', 'type')
            self.openldap_filtergroup = parser.get('openldap', 'filtergroup')
            self.openldap_filteruser = parser.get('openldap', 'filteruser')
            self.openldap_groupattribute = parser.get('openldap', 'groupattribute')
            self.openldap_userattribute = parser.get('openldap', 'userattribute')

            self.tc_server = parser.get('teamcity', 'server')
            self.tc_username = parser.get('teamcity', 'username')
            self.tc_password = parser.get('teamcity', 'password')

            self.user_opt = self.try_get_section(parser, 'user', {})

            self.media_description = self.try_get_item(parser, 'media', 'description', 'Email')
            self.media_opt = self.remove_config_section_items(self.try_get_section(parser, 'media', {}),
                                                              ('description', 'userid'))

        except configparser.NoOptionError as e:
            raise SystemExit('Configuration issues detected in %s' % self.config)

    def set_groups_with_wildcard(self, ldap_conn):
        """
        Set group from LDAP with wildcard
        :return:
        """
        result_groups = []

        for group in self.ldap_groups:
            groups = ldap_conn.get_groups_with_wildcard(group)
            result_groups = result_groups + groups

        if result_groups:
            self.ldap_groups = result_groups
        else:
            raise SystemExit('ERROR - No groups found with wildcard')


class TeamCityClient(object):
    def __init__(self, tc_url, login, password, ldap_groups, ldap_object):
        self.rest_url = '{url}/app/rest/'.format(url=tc_url)
        self.ldap_object = ldap_object
        self.ldap_groups = ldap_groups
        self.session = requests.Session()
        self.session.auth = (login, password)
        self.session.headers.update({'Content-type': 'application/json', 'Accept': 'application/json'})
        self.tc_groups = TeamCityClient.get_tc_groups(self)
        self.tc_users = TeamCityClient.get_tc_users(self)

    def get_tc_groups(self):
        url = self.rest_url + 'userGroups'
        groups_in_tc = self.session.get(url, verify=False).json()
        return [group for group in groups_in_tc['group'] if '.Zabbix.' in group['name']]

    def get_tc_users(self):
        url = self.rest_url + 'users'
        users = self.session.get(url).json()['user']
        return [user['username'] for user in users]

    def get_user_groups(self, user):
        url = self.rest_url + 'users/' + user + '/groups'
        resp = self.session.get(url, verify=False)
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code != 200:
            return "Error: Couldn't find user " + user

    def get_users_from_group(self, group_name):
        if self.tc_groups:
            key = [group['key'] for group in self.tc_groups if group['name'] == group_name][0]
            url = self.rest_url + 'userGroups/key:' + key
            resp = self.session.get(url, verify=False)
            if resp.status_code != 200:
                Exception("Error: Couldn't find group " + group_name + '\n' + resp.content)
            users = resp.json()['users']['user']
            return [user['username'] for user in users if users]
        else:
            return []

    def add_user_to_group(self, user, group_name):
        url = self.rest_url + 'users/' + user + '/groups'
        user_groups = TeamCityClient.get_user_groups(self, user)
        href = [group['href'] for group in self.tc_groups if group['name'] == group_name][0]
        key = [group['key'] for group in self.tc_groups if group['name'] == group_name][0]
        new_group = {u'href': href,
                     u'name': group_name,
                     u'key': key}
        user_groups['group'].append(new_group)
        data = json.dumps(user_groups)
        resp = self.session.put(url, data=data, verify=False)
        if resp.status_code != 200:
            return "Error: Couldn't add user " + user + " to group " + group_name + '\n' + resp.content

    def remove_user_from_group(self, user, group_name):
        url = self.rest_url + 'users/' + user + '/groups'
        user_groups = TeamCityClient.get_user_groups(self, user)
        for group in user_groups['group']:
            if group['name'] == group_name:
                user_groups['group'].remove(group)
        data = json.dumps(user_groups)
        resp = self.session.put(url, data=data, verify=False)
        if resp.status_code != 200:
            return "Error: Couldn't add user " + user + " to group " + group + '\n' + resp.content

    def create_group(self, group_name):
        url = self.rest_url + 'userGroups'
        data = json.dumps({"name": group_name, "key": group_name[:16]})
        self.session.post(url, verify=False, data=data)

    def create_user(self, user):
        url = self.rest_url + 'users'
        if user['email'] == []:
            user['email'] = ''
        data = json.dumps({u'username': user['username'], u'name': user['name'], u'email': user['email']})

        self.session.post(url, verify=False, data=data)

    def start_sync(self):

        for group in self.ldap_groups:

            # Get users from LDAP group
            ldap_group_users = self.ldap_object.get_group_members(group)


            # Create group if not exists
            tc_groups = [gr['name'] for gr in self.tc_groups]
            if group not in tc_groups:
                TeamCityClient.create_group(self, group)
                self.tc_groups = TeamCityClient.get_tc_groups(self)

            # Create users if they not exist
            for login, dn in ldap_group_users.items():
                if login not in self.tc_users:
                    attr_list = ['sn', 'givenName', 'mail']
                    attributes = self.ldap_object.get_user_attributes(dn, attr_list)
                    user = {'username': login,
                            'name': attributes['givenName'] + ' ' +
                                    attributes['sn'] if attributes['sn'] else login,
                            'email': attributes.get('mail', '')}
                    TeamCityClient.create_user(self, user)

            # Get users from TC group
            tc_group_users = TeamCityClient.get_users_from_group(self, group)

            # Add users to TC group
            for user in ldap_group_users.keys():
                if user not in tc_group_users:
                    TeamCityClient.add_user_to_group(self, user, group)

            # Remove users from TC group
            for user in tc_group_users:
                if user not in ldap_group_users.keys():
                    TeamCityClient.remove_user_from_group(self, user, group)


def main():
    # Parse CLI arguments
    args = get_args()

    config = TeamCityLDAPConf(args.file)
    config.load_config()

    # set up AD differences, if necessary
    global active_directory
    global openldap_type
    global group_filter
    global disabled_filter
    global user_filter
    global memberof_filter
    global group_member_attribute
    global uid_attribute
    global lowercase
    global skipdisabled
    global deleteorphans
    global recursive

    lowercase = args.lowercase
    skipdisabled = args.skip_disabled
    recursive = args.recursive

    if config.ldap_type == 'activedirectory':
        active_directory = "true"
        group_filter = config.ad_filtergroup
        user_filter = config.ad_filteruser
        disabled_filter = config.ad_filterdisabled
        memberof_filter = config.ad_filtermemberof
        group_member_attribute = config.ad_groupattribute
        uid_attribute = config.ad_userattribute

    else:
        active_directory = None
        openldap_type = config.openldap_type
        group_filter = config.openldap_filtergroup
        user_filter = config.openldap_filteruser
        group_member_attribute = config.openldap_groupattribute
        uid_attribute = config.openldap_userattribute

    wildcard_search = args.wildcard_search

    ldap_conn = LDAPConn(config.ldap_uri, config.ldap_base, config.ldap_user, config.ldap_pass)
    ldap_conn.connect()

    if wildcard_search:
        config.set_groups_with_wildcard(ldap_conn)

    tc = TeamCityClient(config.tc_server, config.tc_username, config.tc_password, config.ldap_groups, ldap_conn)
    tc.start_sync()
    print("HOOOORAY Sync complete")


if __name__ == '__main__':
    main()

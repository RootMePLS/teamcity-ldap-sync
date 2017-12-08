import argparse
import json
import requests
import random
from ldap3 import Server, Connection, SUBTREE, ALL

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse

try:
    import configparser
except ImportError:
    import ConfigParser as configparser


def get_args():
    def _usage():
        return """
    Usage: teamcity-ldap-sync [-sr] -f <config>
           teamcity-ldap-sync -h

    Options:
      -h, --help                    Display this usage info
      -s, --skip-disabled           Skip disabled AD users
      -r, --recursive               Resolves AD group members recursively (i.e. nested groups)
      -f <config>, --file <config>  Configuration file to use

    """

    """Get command line args from the user"""
    parser = argparse.ArgumentParser(description="Standard Arguments", usage=_usage())

    parser.add_argument("-f", "--file",
                        required=True,
                        help="Configuration file to use")

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


class TeamCityLDAPConfig(object):
    """
    TeamCity-LDAP configuration class
    Provides methods for parsing and retrieving config entries
    """

    def __init__(self, parser):
        try:
            if parser.has_section('ldap'):
                self.ldap_type = parser.get('ldap', 'type')
                self.ldap_uri = parser.get('ldap', 'uri')
                self.ldap_base = parser.get('ldap', 'base')
                self.ldap_user = parser.get('ldap', 'binduser')
                self.ldap_pass = parser.get('ldap', 'bindpass')
                self.ldap_groups = [i.strip() for i in parser.get('ldap', 'groups').split(',')]
                self.ldap_wildcard = any('*' in group for group in self.ldap_groups)

            if parser.has_section('ad'):
                self.ad_filtergroup = parser.get('ad', 'filtergroup')
                self.ad_filteruser = parser.get('ad', 'filteruser')
                self.ad_filterdisabled = parser.get('ad', 'filterdisabled')
                self.ad_filtermemberof = parser.get('ad', 'filtermemberof')
                self.ad_groupattribute = parser.get('ad', 'groupattribute')
                self.ad_userattribute = parser.get('ad', 'userattribute')

            if parser.has_section('openldap'):
                self.openldap_type = parser.get('openldap', 'type')
                self.openldap_filtergroup = parser.get('openldap', 'filtergroup')
                self.openldap_filteruser = parser.get('openldap', 'filteruser')
                self.openldap_groupattribute = parser.get('openldap', 'groupattribute')
                self.openldap_userattribute = parser.get('openldap', 'userattribute')

            if parser.has_section('teamcity'):
                self.tc_server = parser.get('teamcity', 'server')
                self.tc_username = parser.get('teamcity', 'username')
                self.tc_password = parser.get('teamcity', 'password')
                self.tc_verify_certificate = parser.get('teamcity', 'verify_certificate')

        except configparser.NoOptionError as e:
            raise SystemExit('Configuration issues detected in %s' % e)

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


class LDAPConnector(object):
    """
    LDAP connector class

    Defines methods for retrieving users and groups from LDAP server.

    """

    def __init__(self, args, config):
        self.uri = urlparse(config.ldap_uri)
        self.base = config.ldap_base
        self.ldap_user = config.ldap_user
        self.ldap_pass = config.ldap_pass
        self.lowercase = args.lowercase
        self.skipdisabled = args.skip_disabled
        self.recursive = args.recursive

        if config.ldap_type == 'activedirectory':
            self.active_directory = "true"
            self.group_filter = config.ad_filtergroup
            self.user_filter = config.ad_filteruser
            self.disabled_filter = config.ad_filterdisabled
            self.memberof_filter = config.ad_filtermemberof
            self.group_member_attribute = config.ad_groupattribute
            self.uid_attribute = config.ad_userattribute

        else:
            self.active_directory = None
            self.openldap_type = config.openldap_type
            self.group_filter = config.openldap_filtergroup
            self.user_filter = config.openldap_filteruser
            self.group_member_attribute = config.openldap_groupattribute
            self.uid_attribute = config.openldap_userattribute

    def __enter__(self):
        server = Server(host=self.uri.hostname,
                        port=self.uri.port,
                        get_info=ALL)

        self.conn = Connection(server=server,
                               user=self.ldap_user,
                               password=self.ldap_pass,
                               check_names=True,
                               raise_exceptions=True)

        self.conn.bind()
        return self

    def __exit__(self, exctype, exception, traceback):
        self.conn.unbind()
        print('Synchronization complete')

    def group_exist(self, group):
        filter = self.group_filter % group

        self.conn.search(search_base=self.base,
                         search_filter=filter,
                         search_scope=SUBTREE,
                         attributes=['sn'])

        if self.conn.entries:
            return True
        else:
            return False

    def get_group_members(self, group):
        """
        Retrieves the members of an LDAP group

        Args:
            group (str): The LDAP group name

        Returns:
            A list of all users in the LDAP group

        """
        attrlist = [self.group_member_attribute]
        filter = self.group_filter % group

        result = self.conn.search(search_base=self.base,
                                  search_scope=SUBTREE,
                                  search_filter=filter,
                                  attributes=attrlist)
        if not result:
            print('Unable to find group {}, skipping group'.format(group))
            return None

        # Get DN for each user in the group
        if self.active_directory:

            final_listing = {}

            result = json.loads(self.conn.response_to_json())['entries']

            for members in result:
                result_dn = members['dn']
                result_attrs = members['attributes']

            group_members = []
            attrlist = [self.uid_attribute]

            if self.recursive:
                # Get a DN for all users in a group (recursive)
                # It's available only on domain controllers with Windows Server 2003 SP2 or later

                member_of_filter_dn = self.memberof_filter % result_dn

                if self.skipdisabled:
                    filter = "(&%s%s%s)" % (self.user_filter, member_of_filter_dn, self.disabled_filter)
                else:
                    filter = "(&%s%s)" % (self.user_filter, member_of_filter_dn)

                uid = self.conn.search(search_base=self.base,
                                       search_scope=SUBTREE,
                                       search_filter=filter,
                                       attributes=attrlist)

                if uid:
                    group_members = self.conn.response_to_json()
                    group_members = json.loads(group_members)['entries']

            else:
                # Otherwise, just get a DN for each user in the group
                for member in result_attrs[self.group_member_attribute]:
                    if self.skipdisabled:
                        filter = "(&%s%s)" % (self.user_filter, self.disabled_filter)
                    else:
                        filter = "(&%s)" % self.user_filter

                    uid = self.conn.search(search_base=member,
                                           search_scope=SUBTREE,
                                           search_filter=filter,
                                           attributes=attrlist)

                    if uid:
                        group_members = self.conn.response_to_json()
                        group_members = json.loads(group_members)['entries']

            # Fill dictionary with usernames and corresponding DNs
            for item in group_members:
                dn = item['dn']
                username = item['attributes']['sAMAccountName']

                final_listing[username.lower()] = dn

            return final_listing

        else:

            dn, users = result.pop()

            final_listing = {}

            # Get DN for each user in the group
            for uid in users[self.group_member_attribute]:

                if self.openldap_type == "groupofnames":
                    uid = uid.split('=', 2)
                    uid = uid[1].split(',', 1)
                    uid = uid[0]

                filter = self.user_filter % uid
                attrlist = [self.uid_attribute]

                # get the actual LDAP object for each group member
                user = self.conn.search(search_base=self.base,
                                        search_scope=SUBTREE,
                                        search_filter=filter,
                                        attributes=attrlist)

                for items in user:
                    final_listing[uid] = items[0]

            return final_listing

    def get_groups_with_wildcard(self, groups_wildcard):
        print("Search group with wildcard: {}".format(groups_wildcard))

        filter = self.group_filter % groups_wildcard
        result_groups = []

        result = self.conn.search(search_base=self.base,
                                  search_scope=SUBTREE,
                                  search_filter=filter,
                                  attributes='cn')

        if result:
            result = json.loads(self.conn.response_to_json())['entries']
            for group in result:
                group_name = group['attributes']['cn']
                result_groups.append(group_name)

        if not result_groups:
            print('Unable to find group {}, skipping group wildcard'.format(groups_wildcard))

        return result_groups

    def get_user_attributes(self, dn, attr_list):
        """
        Retrieves list of attributes of an LDAP user

        Args:
            :param dn: The LDAP distinguished name to lookup
            :param attr_list: List of attributes to extract

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


class TeamCityClient(object):
    def __init__(self, config, ldap_object):
        self.rest_url = '{url}/app/rest/'.format(url=config.tc_server)
        self.ldap_object = ldap_object
        self.ldap_groups = config.ldap_groups
        self.session = requests.Session()
        self.session.auth = (config.tc_username, config.tc_password)
        self.session.headers.update({'Content-type': 'application/json', 'Accept': 'application/json'})
        self.session.verify = config.tc_verify_certificate
        self.tc_groups = TeamCityClient.get_tc_groups(self)
        self.tc_users = TeamCityClient.get_tc_users(self)

    def get_tc_groups(self):
        url = self.rest_url + 'userGroups'
        groups_in_tc = self.session.get(url, verify=False).json()
        return [group for group in groups_in_tc['group']]

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
            return "Error: Couldn't find user {}\n{}".format(user, resp.content)

    def get_users_from_group(self, group_name):
        if [group['key'] for group in self.tc_groups if group['name'] == group_name]:
            key = [group['key'] for group in self.tc_groups if group['name'] == group_name][0]
            url = self.rest_url + 'userGroups/key:' + key
            resp = self.session.get(url, verify=False)
            if resp.status_code != 200:
                Exception("Error: Couldn't find group {}\n{}".format(group_name, resp.content))
            users = resp.json()['users']['user']
            return [user['username'] for user in users if users]
        else:
            return []

    def add_user_to_group(self, user, group_name):
        print("Adding user {} to group {}".format(user, group_name))
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
            print("Error: Couldn't add user {} to group {}\n{}".format(user, group_name, resp.content))

    def remove_user_from_group(self, user, group_name):
        print("Removing user {} from group {}".format(user, group_name))
        url = self.rest_url + 'users/' + user + '/groups'
        user_groups = TeamCityClient.get_user_groups(self, user)
        for group in user_groups['group']:
            if group['name'] == group_name:
                user_groups['group'].remove(group)
        data = json.dumps(user_groups)
        resp = self.session.put(url, data=data, verify=False)
        if resp.status_code != 200:
            print("Error: Couldn't remove user {} from group {}\n{}".format(user, group_name, resp.content))

    def create_group(self, group_name):
        print("Creating group {} in TC".format(group_name))
        url = self.rest_url + 'userGroups'
        key = ''.join(random.choice('0123456789ABCDEF') for i in range(16))
        data = json.dumps({"name": group_name, "key": key})
        resp = self.session.post(url, verify=False, data=data)
        if resp.status_code == 200:
            self.tc_groups = TeamCityClient.get_tc_groups(self)
        else:
            print("Error: Couldn't create group {}\n{}".format(group_name, resp.content))

    def create_user(self, user):
        print("Creating user {}".format(user['username']))
        url = self.rest_url + 'users'
        if not user['email']:
            user['email'] = ''
        data = json.dumps({u'username': user['username'], u'name': user['name'], u'email': user['email']})

        resp = self.session.post(url, verify=False, data=data)
        if resp.status_code == 200:
            self.tc_users = TeamCityClient.get_tc_users(self)
        else:
            print("Error: Couldn't create user {}\n{}".format(user['username'], resp.content))

    def start_sync(self):

        for ldap_group in self.ldap_groups:

            if self.ldap_object.group_exist(ldap_group):

                print("Syncing group: {}\n{}".format(ldap_group, "=" * 20))

                # Get users from LDAP group
                ldap_group_users = self.ldap_object.get_group_members(ldap_group)

                # Create group if not exists
                tc_groups = [gr['name'] for gr in self.tc_groups]
                if ldap_group not in tc_groups:
                    TeamCityClient.create_group(self, ldap_group)

                # Create users if they not exist
                for login, dn in ldap_group_users.items():
                    if login not in self.tc_users:
                        attr_list = ['sn', 'givenName', 'mail']
                        attributes = self.ldap_object.get_user_attributes(dn, attr_list)
                        user = {
                            'username': login,
                            'name': attributes['givenName'] + ' ' + attributes['sn'] if attributes['sn'] else login,
                            'email': attributes.get('mail', '')
                        }
                        TeamCityClient.create_user(self, user)

                # Get users from TC group
                tc_group_users = TeamCityClient.get_users_from_group(self, ldap_group)

                # Add users to TC group
                for user in ldap_group_users.keys():
                    if user not in tc_group_users:
                        TeamCityClient.add_user_to_group(self, user, ldap_group)

                # Remove users from TC group
                for user in tc_group_users:
                    if user not in ldap_group_users.keys():
                        TeamCityClient.remove_user_from_group(self, user, ldap_group)

            else:
                print("Couldnt find group {}".format(ldap_group))


def main():
    # Parse CLI arguments
    args = get_args()

    # Read config file
    parser = configparser.RawConfigParser()
    parser.read(args.file)

    # Create config object from config file
    config = TeamCityLDAPConfig(parser)

    # Connect to LDAP
    with LDAPConnector(args, config) as ldap_conn:
        if config.ldap_wildcard:
            config.set_groups_with_wildcard(ldap_conn)

        tc = TeamCityClient(config, ldap_conn)
        tc.start_sync()


if __name__ == '__main__':
    main()

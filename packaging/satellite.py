#!/usr/bin/python

# (c) 2016, Timothy Vandenbrande <timothy.vandenbrande@gmail.com>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible. If not, see <http://www.gnu.org/licenses/>.


DOCUMENTATION = '''
---
module: satellite
author: Timothy Vandenbrande
short_description: satellite/katello automation
description:
    - This module allows you to execute different actions on the Satellite/Katello through its API.
    - It allows you to list organisations, contentviews, environments, versions, actions, systems and erratas
    - It allows you to give info about an organisation, a contentview, an environment, a version, get a versionlist, an action or a system
    - Publish a contentview.
    - Promote environments in a contentview.
    - Remove versions from a contentview.
version_added: "2.2"
requirements:
    - requests
options:
    user:
        description:
            - the user to authenticate with
        required: true
    password:
        description:
            - the password to authenticate the user with.
        required: true
    server:
        description:
            - the name/ip of your satellite
        required: true
    ssl_verify:
        description:
            - boolean switch to make a secure or insecure connection to the server.
        default: false
        required: false
    action:
        description:
            - what you wish to do.
        default: "list"
        required: false
        choices: ['list', 'info', 'promote', 'publish', 'delete', 'update']
    actiontype:
        description:
            - on which you wish to perform your action.
        default: "list"
        required: false
        choices: ['organisation', 'contentview', 'environment', 'version', 'versionlist', 'action', 'system', 'errata']
    organisation:
        description:
            - the organisation your action applies on
            - required when I(action==list), I(action==info), I(action==promote), I(action==publish), I(action==delete) or I(action==update)
        required: false
    contentview:
        description:
            - the contentview your action applies on
        required: false
    version:
        description:
            - the version your action applies on
        required: false
    environment:
        description:
            - the environment your action applies on
        required: false
    actionid:
        description:
            - the actionid your action applies on
        required: false
    releaseversion:
        description:
            - the releaseversion your action applies on
        required: false
    force:
        description:
            - a force uption for promote/delete action
        default: false
        required: false
'''

RETURN = '''
action:
    description: Returns the result of the action.
    returned: always
    type: dict
    sample: {
        "cli_example": null,
        "ended_at": "2016-05-13T14:08:08Z",
        "humanized": {
          "action": "Publish",
          "errors": [
          ],
          "input": [
            [
              "content_view",
              {
                "link": "#/content_views/22/versions",
                "text": "content view 'TEST'"
              }
            ],
            [
              "organization",
              {
                "link": "/organizations/3/edit",
                "text": "organization 'Ypto'"
              }
            ]
          ],
          "output": ""
        },
        "id": "fd0b0205-d6d4-4191-bc14-f28a564125a0",
        "input": {
          "content_view": {
            "id": 22,
            "label": "TEST",
            "name": "TEST"
          },
          "content_view_id": 22,
          "current_user_id": 3,
          "environment_id": 2,
          "history_id": 1216,
          "locale": "en",
          "organization": {
            "id": 3,
            "label": "Ypto",
            "name": "Ypto"
          },
          "services_checked": [
            "pulp",
            "pulp_auth",
            "elasticsearch",
            "candlepin",
            "candlepin_auth"
          ],
          "user_id": 3
        },
        "label": "Actions::Katello::ContentView::Publish",
        "output": {
        },
        "pending": false,
        "progress": 1.0,
        "result": "success",
        "started_at": "2016-05-13T14:06:52Z",
        "state": "stopped",
        "username": "admin"
  }
'''

EXAMPLES = '''
# Get a list of all the versions for a defined contentview
  action: satellite
  args:
    action: "info"
    server: "{{ satellite_server }}"
    user: "admin"
    password: "{{ sat_admin_pass }}"
    actiontype: "versionlist"
    contentview: "{{ contentview }}"
    organisation: "{{ org }}"

# Promote an environment
  action: satellite
  args:
    action: "promote"
    server: "{{ satellite_server }}"
    user: "admin"
    password: "{{ sat_admin_pass }}"
    contentview: "{{ contentview }}"
    organisation: "{{ org }}"
    version: "68.0"
    environment: "test"

# Get version info
  action: satellite
  args:
    action: "info"
    server: "{{ satellite_server }}"
    user: "admin"
    password: "{{ sat_admin_pass }}"
    actiontype: "version"
    contentview: "{{ contentview }}"
    version: "67.0"
  register: cleanup

# Remove obsolete version from content view
  action: satellite
  args:
    action: "delete"
    actiontype: "version"
    server: "{{ satellite_server }}"
    user: "admin"
    password: "{{ sat_admin_pass }}"
    contentview: "{{ contentview }}"
    organisation: "{{ org }}"
    version: "67.0"
'''

from __main__ import *

import json
import sys
import datetime
import time
import os
import logging
from time import sleep
try:
    import json
except ImportError:
    import simplejson as json

SAT_FAILED = 1
SAT_SUCCESS = 0
SAT_UNAVAILABLE = 2


class SatConn(object):
    'Connection to the Satellite'
    def __init__(self, module):
        self.module = module
        url = "https://%s" % module.params['server']
        self.kat_api = "%s/katello/api/v2/" % url
        self.katello_api = "%s/katello/api/" % url
        self.sat_api = "%s/api/v2/" % url
        self.foreman_tasks_api = "%s/foreman_tasks/api/tasks/" % url
        self.post_headers = {'Content-Type': 'application/json'}
        self.username = module.params['url_username']
        self.password = module.params['url_password']
        self.ssl_verify = module.params['ssl_verify']

        try:
            self.test()
        except:
            raise Exception("Failed to connect to the satellite.")

    def get_json(self, location):
        """
        Performs a GET using the passed URL location
        """

        result = requests.get(location, auth=(self.username, self.password), verify=self.ssl_verify)
        return result.json()

    def post_json(self, location, json_data):
        """
        Performs a POST and passes the data to the URL location
        """

        result = requests.post(
            location,
            data=json_data,
            auth=(self.username, self.password),
            verify=self.ssl_verify,
            headers=self.post_headers)
        return result.json()

    def put_json(self, location, json_data):
        """
        Performs a POST and passes the data to the URL location
        """

        result = requests.put(
            location,
            data=json_data,
            auth=(self.username, self.password),
            verify=self.ssl_verify,
            headers=self.post_headers)
        return result.json()

    def delete_json(self, location, json_data):
        """
        Performs a POST and passes the data to the URL location
        """

        result = requests.delete(
            location,
            data=json_data,
            auth=(self.username, self.password),
            verify=self.ssl_verify,
            headers=self.post_headers)
        return result.json()

    def test(self):
        org = self.get_json(self.kat_api + "organizations/")
        if org.get('error', None):
            return False
        else:
            return True

    def find_action(self, actionid):
        return self.get_json(self.foreman_tasks_api + str(actionid))

    def find_organisation(self, orgid):
        if orgid == 0:
            org = self.get_json(self.kat_api + "organizations/")
            if 'errors' in org.keys():
                return org
            else:
                return org['results']
        else:
            org = self.get_json(self.kat_api + "organizations/" + str(orgid))
            return org

    def find_contentview(self, cvid):
        if cvid == 0:
            cv_info = self.get_json(self.kat_api + "content_views/")
            if 'errors' in cv_info.keys():
                return cv_info
            else:
                return cv_info['results']
        else:
            cv_info = self.get_json(self.kat_api + "content_views/" + str(cvid))
            return cv_info

    def publish_contentview(self, cvid):
        rinfo = self.post_json(
            self.kat_api + "/content_views/" + str(cvid) + "/publish",
            json.dumps({"id": cvid, })
        )
        return rinfo

    def find_environment(self, orgid, envid):
        if envid == 0:
            env_info = self.get_json(self.kat_api + "organizations/" + str(orgid) + "/environments/")
            if 'errors' in env_info.keys():
                return env_info
            else:
                return env_info['results']
        else:
            env_info = self.get_json(self.kat_api + "organizations/" + str(orgid) + "/environments/" + str(envid))
            return env_info

    def promote_environment(self, revid, envid, force):
        rinfo = self.post_json(
            self.kat_api + "/content_view_versions/" + str(revid) + "/promote",
            json.dumps({
                "id": revid,
                "environment_id": envid,
                "force": force,
            })
        )
        return rinfo

    def delete_version(self, revid):
        rinfo = self.delete_json(
            self.kat_api + "/content_view_versions/" + str(revid),
            json.dumps({
                "id": revid,
            })
        )
        return rinfo

    def find_system(self, orgid, sysid):
        if sysid == 0:
            sys = self.get_json(self.kat_api + "organizations/" + str(orgid) + "/systems/" + "?per_page=10000&full_results=true")
        else:
            sys = self.get_json(self.kat_api + "organizations/" + str(orgid) + "/systems/" + "?search=" + str(sysid))
        if 'errors' in sys.keys():
            return sys
        else:
            return sys['results']

    def get_system(self, sysid):
            sys = self.get_json(self.kat_api + "systems/" + str(sysid))
            return sys

    def find_errata(self, sysid):
        errata = self.get_json(self.kat_api + "systems/" + str(sysid) + "/errata")
        return errata['results']


class Satellite(object):
    def __init__(self, module):
        self.module = module

    def __get_conn(self):
        self.conn = SatConn(self.module)
        return self.conn

    def get_organisation(self, organisation):
        self.__get_conn()
        if type(organisation) == str:
            orgs = self.list_organisations()
            for org in orgs:
                if organisation == org['name']:
                    orgid = org['id']
                    break
        else:
            orgid = organisation
        return self.conn.find_organisation(orgid)

    def get_action(self, action):
        self.__get_conn()
        return self.conn.find_action(action)

    def list_organisations(self):
        self.__get_conn()
        orgs = self.conn.find_organisation(0)
        results = []
        for org in orgs:
            result_org = dict()
            result_org['name'] = org['name']
            result_org['id'] = org['id']
            results.append(result_org)
        return results

    def get_contentview(self, contentview):
        self.__get_conn()
        if type(contentview) == str:
            cvs = self.list_contentviews()
            for cv in cvs:
                if contentview == cv['name']:
                    cvid = cv['id']
                    break
        else:
            cvid = contentview
        return self.conn.find_contentview(cvid)

    def list_contentviews(self):
        self.__get_conn()
        cvs = self.conn.find_contentview(0)
        results = []
        for cv in cvs:
            result_cv = dict()
            result_cv['name'] = cv['name']
            result_cv['id'] = cv['id']
            results.append(result_cv)
        return results

    def publish_contentview(self, contentview):
        cvid = self.get_contentview(contentview)['id']
        rinfo = self.conn.publish_contentview(cvid)

        pending = True

        while pending:
            time.sleep(5)
            action = self.get_action(rinfo['id'])
            pending = action['pending']
        return action

    def get_environment(self, organisation, environment):
        self.__get_conn()
        orgid = self.get_organisation(organisation)['id']
        envid = environment
        if type(environment) == str:
            envs = self.list_environments(orgid)
            for env in envs:
                if environment == env['name']:
                    envid = env['id']
                    break
        else:
            envid = environment
        return self.conn.find_environment(orgid, envid)

    def list_environments(self, organisation):
        self.__get_conn()
        orgid = self.get_organisation(organisation)['id']
        envs = self.conn.find_environment(orgid, 0)
        results = []
        for env in envs:
            result_env = dict()
            result_env['name'] = env['name']
            result_env['id'] = env['id']
            results.append(result_env)
        return results

    def get_version(self, contentview, version):
        self.__get_conn()
        cv_info = self.get_contentview(contentview)
        if type(version) == str:
            for rev in cv_info['versions']:
                if version == rev['version']:
                    break
        else:
            for rev in cv_info['versions']:
                if rev['id'] == version:
                    break
        return rev

    def list_versions(self, organisation, contentview):
        self.__get_conn()
        revs = self.get_contentview(contentview)['versions']
        results = []
        for rev in revs:
            result_rev = dict()
            result_rev['name'] = rev['version']
            result_rev['id'] = rev['id']
            result_rev['environment'] = []
            for env in rev['environment_ids']:
                result_rev['environment'].append(self.get_environment(organisation, env)['name'])
            results.append(result_rev)
        return results

    def promote_environment(self, version, contentview, environment, organisation, force):
        self.__get_conn()
        revid = self.get_version(contentview, version)['id']
        envid = self.get_environment(organisation, environment)['id']

        rinfo = self.conn.promote_environment(revid, envid, force)
        if "errors" in rinfo.keys():
            rinfo['result'] = "failed"
            return rinfo

        pending = True

        while pending:
            time.sleep(5)
            action = self.get_action(rinfo['id'])
            pending = action['pending']
        return action

    def delete_version(self, version, contentview):
        self.__get_conn()
        revid = self.get_version(contentview, version)['id']

        rinfo = self.conn.delete_version(revid)
        if "errors" in rinfo.keys():
            rinfo['result'] = "failed"
            return rinfo

        pending = True

        while pending:
            time.sleep(5)
            action = self.get_action(rinfo['id'])
            pending = action['pending']
        return action

    def list_systems(self, organisation):
        self.__get_conn()
        orgid = self.get_organisation(organisation)['id']
        systems = self.conn.find_system(orgid, 0)
        if type(systems) == dict():
            return systems
        results = []
        for sys in systems:
            result_sys = dict()
            result_sys['name'] = sys['name']
            result_sys['id'] = sys['id']
            result_sys['environment'] = sys['environment']['name']
            result_sys['content_view'] = sys['content_view']['name']
            result_sys['release'] = sys['release']
            try:
                result_sys['release_ver'] = sys['release_ver']
            except:
                result_sys['release_ver'] = sys['release']
            result_sys['installedProducts'] = sys['installedProducts']
            results.append(result_sys)
        return results

    def get_system(self, organisation, system):
        self.__get_conn()
        orgid = self.get_organisation(organisation)['id']
        sysid = system
        if type(system) == str:
            systems = self.conn.find_system(orgid, system)
            for sys in systems:
                if system == sys['name']:
                    sysid = sys['id']
                    break
        else:
            sysid = system
        return self.conn.get_system(sysid)

    def list_errata(self, organisation, system):
        self.__get_conn()
        sysid = self.get_system(organisation, system)['id']
        return self.conn.find_errata(sysid)


def core(module):

    action = module.params.get('action', None)

    s = Satellite(module)
    res = {}

    if action == 'list':
        actiontype = module.params.get('actiontype', None)
        if actiontype is None:
            return SAT_FAILED, "actiontype is a required argument for a list action."
        elif actiontype == 'organisation':
            orgs = s.list_organisations()
            if type(orgs) == dict():
                if 'errors' in orgs.keys():
                    return SAT_FAILED, orgs
            return SAT_SUCCESS, {"organisations": orgs}
        elif actiontype == 'contentview':
            cvs = s.list_contentviews()
            if type(cvs) == dict():
                if 'errors' in cvs.keys():
                    return SAT_FAILED, cvs
            return SAT_SUCCESS, {"contentviews": cvs}
        elif actiontype == 'environment':
            organisation = module.params.get('organisation', None)
            if organisation is None:
                return SAT_FAILED, "organisation is a required argument to list environments."
            envs = s.list_environments(organisation)
            if type(envs) == dict():
                if 'errors' in envs.keys():
                    return SAT_FAILED, envs
            return SAT_SUCCESS, {"environments": envs}
        elif actiontype == 'version':
            organisation = module.params.get('organisation', None)
            if organisation is None:
                return SAT_FAILED, "organisation is a required argument to list environments."
            contentview = module.params.get('contentview', None)
            if contentview is None:
                return SAT_FAILED, "contentview is a required argument to list versions."
            rev = s.list_versions(organisation, contentview)
            if type(rev) == dict():
                if 'errors' in rev.keys():
                    return SAT_FAILED, rev
            return SAT_SUCCESS, {"versions": rev}
        elif actiontype == 'system':
            organisation = module.params.get('organisation', None)
            if organisation is None:
                return SAT_FAILED, "organisation is a required argument to list systems."
            systems = s.list_systems(organisation)
            if type(systems) == dict():
                if 'errors' in systems.keys():
                    return SAT_FAILED, systems
            return SAT_SUCCESS, {"systems": systems}
        elif actiontype == 'errata':
            organisation = module.params.get('organisation', None)
            if organisation is None:
                return SAT_FAILED, "organisation is a required argument to get errata."
            system = module.params.get('system', None)
            if system is None:
                return SAT_FAILED, "system is a required argument to get errata."
            err = s.list_errata(organisation, system)
            return SAT_SUCCESS, {"errata": err}

    elif action == 'info':
        actiontype = module.params.get('actiontype', None)
        if actiontype is None:
            return SAT_FAILED, "actiontype is a required argument for an info action."
        if actiontype == 'organisation':
            organisation = module.params.get('organisation', None)
            if organisation is None:
                return SAT_FAILED, "organisation is a required argument."
            org = s.get_organisation(organisation)
            return SAT_SUCCESS, {"organisation": org}
        elif actiontype == 'contentview':
            contentview = module.params.get('contentview', None)
            if contentview is None:
                return SAT_FAILED, "contentview is a required argument."
            cv = s.get_contentview(contentview)
            return SAT_SUCCESS, {"contentview": cv}
        elif actiontype == 'environment':
            organisation = module.params.get('organisation', None)
            if organisation is None:
                return SAT_FAILED, "organisation is a required argument to get an environment."
            environment = module.params.get('environment', None)
            if environment is None:
                return SAT_FAILED, "environment is a required argument."
            env = s.get_environment(organisation, environment)
            return SAT_SUCCESS, {"environments": env}
        elif actiontype == 'version':
            contentview = module.params.get('contentview', None)
            if contentview is None:
                return SAT_FAILED, "contentview is a required argument to get an versions."
            version = module.params.get('version', None)
            if version is None:
                return SAT_FAILED, "version is a required argument."
            rev = s.get_version(contentview, version)
            return SAT_SUCCESS, {"version": rev}
        elif actiontype == 'versionlist':
            organisation = module.params.get('organisation', None)
            if organisation is None:
                return SAT_FAILED, "organisation is a required argument to list environments."
            contentview = module.params.get('contentview', None)
            if contentview is None:
                return SAT_FAILED, "contentview is a required argument to list versions."
            revs = s.list_versions(organisation, contentview)
            rev_list = [float(rev['name']) for rev in revs]
            return SAT_SUCCESS, {"versionlist": rev_list}
        elif actiontype == 'action':
            actionid = module.params.get('actionid', None)
            if actionid is None:
                return SAT_FAILED, "actionid is a required argument."
            action = s.get_action(actionid)
            return SAT_SUCCESS, {"action ": action}
        elif actiontype == 'system':
            organisation = module.params.get('organisation', None)
            if organisation is None:
                return SAT_FAILED, "organisation is a required argument to get a system."
            system = module.params.get('system', None)
            if system is None:
                return SAT_FAILED, "system is a required argument."
            sys = s.get_system(organisation, system)
            return SAT_SUCCESS, {"systems": sys}

    elif action == 'publish':
        contentview = module.params.get('contentview', None)
        if contentview is None:
            return SAT_FAILED, "contentview is a required argument to publish a new version."
        rinfo = s.publish_contentview(contentview)
        if rinfo['result'] == "success":
            return SAT_SUCCESS, {"changed": True, "action": rinfo, "msg": "The content view was successfully published to a new version."}
        else:
            return SAT_FAILED, rinfo

    elif action == 'promote':
        contentview = module.params.get('contentview', None)
        if contentview is None:
            return SAT_FAILED, "contentview is a required argument."
        version = module.params.get('version', None)
        if version is None:
            return SAT_FAILED, "version is a required argument."
        environment = module.params.get('environment', None)
        if environment is None:
            return SAT_FAILED, "environment is a required argument."
        organisation = module.params.get('organisation', None)
        if organisation is None:
            return SAT_FAILED, "organisation is a required argument."

        version_list = s.list_versions(organisation, contentview)
        for version_info in version_list:
            if (version_info['name'] == version or version_info['id'] == version) and environment in version_info["environment"]:
                return SAT_SUCCESS, {"changed": False, "msg": "The environment was already promoted to this version."}
                break

        rinfo = s.promote_environment(version, contentview, environment, organisation, module.params.get('force', None))
        if rinfo['result'] == "success":
            return SAT_SUCCESS, {"changed": True, "action": rinfo, "msg": "The environment was successfully promoted to a new version."}
        else:
            return SAT_FAILED, rinfo

    elif action == 'update':
        actiontype = module.params.get('actiontype', None)
        if actiontype is None:
            return SAT_FAILED, "actiontype is a required argument."
        elif actiontype == 'system':
            environment = module.params.get('environment', None)
            contentview = module.params.get('contentview', None)
            organisation = module.params.get('organisation', None)
            releaseversion = module.params.get('releaseversion', None)

    elif action == 'delete':
        actiontype = module.params.get('actiontype', None)
        if actiontype is None:
            return SAT_FAILED, "actiontype is a required argument."
        elif actiontype == 'version':
            contentview = module.params.get('contentview', None)
            if contentview is None:
                return SAT_FAILED, "contentview is a required argument."
            version = module.params.get('version', None)
            if version is None:
                return SAT_FAILED, "version is a required argument."
            organisation = module.params.get('organisation', None)
            if organisation is None:
                return SAT_FAILED, "organisation is a required argument."

            version_list = s.list_versions(organisation, contentview)
            if float(version) not in [float(rev['name']) for rev in version_list]:
                return SAT_SUCCESS, {"changed": False, "msg": "The version was already removed from this environment."}

            rinfo = s.delete_version(version, contentview)
            if rinfo['result'] == "success":
                return SAT_SUCCESS, {"changed": True, "action": rinfo, "msg": "The version was successfully removed from the contentview."}
            else:
                return SAT_FAILED, rinfo


def main():
    module = AnsibleModule(
        argument_spec = dict(
            action         = dict(default='list', choices=['list', 'info', 'promote', 'publish', 'delete', 'update']),
            url_username   = dict(required=True, aliases=['user']),
            url_password   = dict(required=True, aliases=['password']),
            server         = dict(required=True),
            ssl_verify     = dict(default=True, type='bool'),
            actiontype     = dict(choices=['organisation', 'contentview', 'environment', 'version', 'versionlist', 'action', 'system', 'errata']),
            organisation   = dict(),
            contentview    = dict(),
            version        = dict(),
            environment    = dict(),
            actionid       = dict(),
            system         = dict(),
            releaseversion = dict(),
            force          = dict(default=False, type='bool')
        ),
    )

    rc = SAT_SUCCESS
    try:
        rc, result = core(module)
    except Exception, e:
        module.fail_json(msg=str(e))

    if rc != 0:  # something went wrong emit the msg
        module.fail_json(rc=rc, msg=result)
    else:
        module.exit_json(**result)


# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *

if __name__ == '__main__':
    main()

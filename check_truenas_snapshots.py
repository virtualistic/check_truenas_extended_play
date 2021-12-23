import argparse
import json
import sys
import string
import urllib3
import requests
import logging
from dataclasses import dataclass
from enum import Enum
from datetime import datetime


# @dataclass
# class SnapShot:
#     SnapshotName: str


class RequestTypeEnum(Enum):
    GET_REQUEST = 1
    POST_REQUEST = 2


class Startup(object):

    def __init__(self, hostname, user, secret, use_ssl, verify_cert, ignore_dismissed_alerts, debug_logging, snapshot_name):
        self._hostname = hostname
        self._user = user
        self._secret = secret
        self._use_ssl = use_ssl
        self._verify_cert = verify_cert
        self._ignore_dismissed_alerts = ignore_dismissed_alerts
        self._debug_logging = debug_logging
        self._snapshot_name = snapshot_name
        #self._wfree = zpool_warn
        #self._cfree = zpool_critical
        #self._show_zpool_perfdata = show_zpool_perfdata

        http_request_header = 'https' if use_ssl else 'http'

        self._base_url = ('%s://%s/api/v2.0' % (http_request_header, hostname))

        self.setup_logging()
        self.log_startup_information()


    def log_startup_information(self):
        logging.debug('')
        logging.debug('hostname: %s', self._hostname)
        logging.debug('use_ssl: %s', self._use_ssl)
        logging.debug('verify_cert: %s', self._verify_cert)
        logging.debug('base_url: %s', self._base_url)
        logging.debug('snapshot_name: %s', self._snapshot_name)
        #logging.debug('wfree: %d', self._wfree)
        #logging.debug('cfree: %d', self._cfree)
        logging.debug('')

    # Do a GET or POST request
    def do_request(self, resource, requestType, optionalPayload):
        try:
            request_url = '%s/%s/' % (self._base_url, resource)
            logging.debug('request_url: %s', request_url)
            logging.debug('requestType: ' + repr(requestType))
            # logging.debug('optionalPayloadAsJson:' + optionalPayloadAsJson)

            # We assume that all incoming payloads are JSON.
            optionalPayloadAsJson = json.dumps(optionalPayload)
            logging.debug('optionalPayloadAsJson:' + optionalPayloadAsJson)

            # We get annoying warning text output from the urllib3 library if we fail to do this
            if (not self._verify_cert):
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            auth = False
            headers = {}

            # If username provided, try to authenticate with username/password combo
            if (self._user):
                auth = (self._user, self._secret)
            # Otherwise, use API key
            else:
                headers = {'Authorization': 'Bearer ' + self._secret}

            # GET Request
            if (requestType is RequestTypeEnum.GET_REQUEST):
                if (optionalPayload):
                    r = requests.get(request_url,
                                    auth=auth,
                                    headers=headers,
                                    data=optionalPayloadAsJson,
                                    verify=self._verify_cert)
                else:
                    r = requests.get(request_url,
                                    auth=auth,
                                    headers=headers,
                                    verify=self._verify_cert)
                logging.debug('GET request response: %s', r.text)
            # POST Request
            elif (requestType is RequestTypeEnum.POST_REQUEST):
                if (optionalPayload):
                    r = requests.post(request_url,
                                    auth=auth,
                                    headers=headers,
                                    data=optionalPayloadAsJson,
                                    verify=self._verify_cert)
                else:
                    r = requests.post(request_url,
                                    auth=auth,
                                    headers=headers,
                                    verify=self._verify_cert)
                logging.debug('POST request response: %s', r.text)
            else:
                print('UNKNOWN - request failed - Unknown RequestType: ' + requestType)
                sys.exit(3)

            r.raise_for_status()
        except:
            print('UNKNOWN - request failed - Error when contacting TrueNAS server: ' + str(sys.exc_info()))
            sys.exit(3)

        if r.ok:
            try:
                return r.json()
            except:
                print('UNKNOWN - json failed to parse - Error when contacting TrueNAS server: ' + str(sys.exc_info()))
                sys.exit(3)

    # GET request
    def get_request(self, resource):
        return self.do_request(resource, RequestTypeEnum.GET_REQUEST, None)

    # GET request with payload
    def get_request_with_payload(self, resource, optionalPayload):
        return self.do_request(resource, RequestTypeEnum.GET_REQUEST, optionalPayload)

    # POST request
    def post_request(self, resource):
        return self.do_request(resource, RequestTypeEnum.POST_REQUEST, None)

    # POST request with payload
    def post_request_with_payload(self, resource, optionalPayload):
        return self.do_request(resource, RequestTypeEnum.POST_REQUEST, optionalPayload)

    def check_zfs_snapshot(self):
        snapshots = self.get_request('zfs/snapshot')
        #print(type(snapshots))
        snapshots2 = [snap for snap in snapshots if self._snapshot_name in snap["id"]]
        #all_snaps = str(snapshots2["id"])
        #snapshots2.sort(key="id")

        snapshot_date_list = []
        for snap in snapshots2:
            snap_id = snap["id"]
            snap_creation = snap["properties"]["creation"]["value"]
            #snap_id = snap_id.replace("_", "-")
            #str.replace('; ', ', ') and then a str.split(', ')
            snap_creation_date_str = snap_id[-16:len(snap_id) - 6]  #  snap_id.split("auto-")
            snap_creation_date_object = datetime.strptime(snap_creation_date_str, "%Y-%m-%d")

            #snap_creation_list = [snap_id for snap_id in snap_creation_list]
            #print(snap_creation_list)
            #print(sorted(snap_creation_list))
            #snap_creation_list.sort(key=lambda snap_id: snap_id[0])
            #TODO have to just get the dates, strip name + time then sort the sjizzle
            #my_dates.sort(key=lambda date: datetime.strptime(date, "%d-%b-%y"))
            snapshot_date_list.append(snap_creation_date_object)
            #snap_creation_date_object.sort(key=lambda date: datetime.strptime(date, "%Y-%m-%d"))
            print(snap_creation_date_object)
            #print(f"{snap_id} was created on: {snap_creation}")
        snapshot_date_list.sort()
        print(snapshot_date_list)
        latest_snap = snapshot_date_list[-1].strftime("%Y-%m-%d")  #["id"]
        print(f"the latest snapshot is {latest_snap}")
        #date_latest_snap = (latest_snap[-16:len(latest_snap) - 6])
        ##date_latest_snap = latest_snap.lstrip("pool02/ds02/audiobooks@auto-")#[0:14])
        #print(date_latest_snap)

    def handle_requested_alert_type(self, alert_type):
        if alert_type == 'alerts':
            self.check_alerts()
        if alert_type == 'snapshots':
            self.check_zfs_snapshot()
        elif alert_type == 'repl':
            self.check_repl()
        elif alert_type == 'update':
            self.check_update()
        else:
            print("Unknown type: " + alert_type)
            sys.exit(3)

    def setup_logging(self):
        logger = logging.getLogger()

        if (self._debug_logging):
            # print('Trying to set logging level debug')
            logger.setLevel(logging.DEBUG)
        else:
            # print('Should be setting no logging level at all')
            logger.setLevel(logging.CRITICAL)


check_truenas_script_version = '1.0'


def main():
    # Build parser for arguments
    parser = argparse.ArgumentParser(description='Checks a TrueNAS/FreeNAS server using the 2.0 API. Version ' + check_truenas_script_version)
    parser.add_argument('-H', '--hostname', required=True, type=str, help='Hostname or IP address')
    parser.add_argument('-u', '--user', required=False, type=str, help='Username, only root works, if not specified: use API Key')
    parser.add_argument('-p', '--passwd', required=True, type=str, help='Password or API Key')
    parser.add_argument('-t', '--type', required=True, type=str, help='Type of check, either alerts, snapshots, zpool, zpool_capacity, repl, or update')
    parser.add_argument('-sn', '--snapshotname', required=True, type=str, default='all', help='For check type snapshot, the name of snapshot to check.; defaults to all zpools.')
    parser.add_argument('-ns', '--no-ssl', required=False, action='store_true', help='Disable SSL (use HTTP); default is to use SSL (use HTTPS)')
    parser.add_argument('-nv', '--no-verify-cert', required=False, action='store_true', help='Do not verify the server SSL cert; default is to verify the SSL cert')
    parser.add_argument('-ig', '--ignore-dismissed-alerts', required=False, action='store_true', help='Ignore alerts that have already been dismissed in FreeNas/TrueNAS; default is to treat them as relevant')
    parser.add_argument('-d', '--debug', required=False, action='store_true', help='Display debugging information; run script this way and record result when asking for help.')


    # if no arguments, print out help
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    # Parse the arguments
    args = parser.parse_args(sys.argv[1:])

    use_ssl = not args.no_ssl
    verify_ssl_cert = not args.no_verify_cert

    startup = Startup(args.hostname, args.user, args.passwd, use_ssl, verify_ssl_cert, args.ignore_dismissed_alerts, args.debug, args.snapshotname )

    startup.handle_requested_alert_type(args.type)


if __name__ == '__main__':
    main()

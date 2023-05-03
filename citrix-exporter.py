#!/usr/bin/env python
from calendar import EPOCH
import os
from datetime import datetime
from typing import Mapping
import yaml
import json
import time
import signal
import logging
import requests
import argparse
import sys
from prometheus_client import start_http_server
from prometheus_client.core import GaugeMetricFamily, CounterMetricFamily, REGISTRY, InfoMetricFamily
from urllib3.exceptions import InsecureRequestWarning
from urllib3.exceptions import SubjectAltNameWarning
from requests.auth import HTTPBasicAuth
from tenacity import retry, RetryError, retry_if_exception_type
from tenacity import stop_after_attempt, wait_fixed, retry_if_result

NS_USERNAME_FILE = '/mnt/nslogin/username'
NS_PASSWORD_FILE = '/mnt/nslogin/password'
DEPLOYMENT_WITH_CPX = 'sidecar'
CPX_CRED_DIR = '/var/deviceinfo'
CPX_CRED_FILE = '/var/deviceinfo/random_id'
NSERR_SESSION_EXPIRED = 0x1BC
NSERR_AUTHTIMEOUT = 0x403
NSERR_NOUSER = 0x162
NSERR_INVALPASSWD = 0x163
EPOCH_TIME = datetime(1970,1,1)


def parseConfig(args):
    '''Parses the config file for specified metrics.'''

    try:
        with open(args.config_file, 'r') as stream:
            config = yaml.load(stream, Loader=yaml.FullLoader)
            for key in config.keys():
                args.__setattr__(key.replace('-', '_'), config[key])
    except Exception as e:
        logger.error('Error while reading config file: {}'.format(e))
        print(e)
    return args


def get_metrics_file_data(metrics_file, metric):
    '''Loads stat types from metrics file or any specific metric.'''
    try:
        f = open(metrics_file, 'r')
        # collect selected metrics only
        if metric:
            _metrics_data = json.load(f)
            _metrics_json = {d: _metrics_data[d]
                             for d in _metrics_data.keys() if d in metric}
        # collect all default metrics
        else:
            _metrics_json = json.load(f)
    except Exception as e:
        logger.error('Error while loading metrics: {}'.format(e))
    return _metrics_json


def set_logging_args(log_file, log_level):
    '''Sets logging file and level as per the arguments.'''

    try:
        logging.basicConfig(
            filename=log_file,
            filemode='w',
            format='%(asctime)s %(levelname)-8s %(message)s',
            datefmt='%FT%T%z',
            level={
                'DEBUG': logging.DEBUG,
                'INFO': logging.INFO,
                'WARN': logging.WARN,
                'ERROR': logging.ERROR,
                'CRITICAL': logging.CRITICAL,
            }[log_level.upper()])
    except Exception as e:
        print('Error while setting logger configs:: %s', e)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logger = logging.getLogger('citrix_adc_metrics_exporter')
    return logger


def start_exporter_server(port):
    ''' Sets an http server for prometheus client requests.'''

    logger.info('Starting the exporter on port %s.' % port)
    try:
        start_http_server(port)
        print("Exporter is running...")
    except Exception as e:
        logger.critical('Error while opening port: {}'.format(e))
        print(e)


def retry_cpx_password_read(ns_password):
    if ns_password is not None:
        return False
    return True

# Generally in the side car mode, credentials should be immediately available.
# Credential file availability cannot take more than a minute in SIDECAR mode even when nodes are highly engaged.
# Wait for credentials max upto 120 seconds.
# There is no need to wait indefinetely even if credentials are not available after two minutes.


@retry(stop=stop_after_attempt(120), wait=wait_fixed(1), retry=retry_if_result(retry_cpx_password_read))
def read_cpx_credentials(ns_password):
    if os.path.isdir(CPX_CRED_DIR):
        if os.path.isfile(CPX_CRED_FILE) and os.path.getsize(CPX_CRED_FILE):
            try:
                with open(CPX_CRED_FILE, 'r') as fr:
                    ns_password = fr.read()
                    if ns_password is not None:
                        logger.info(
                            "SIDECAR Mode: Successfully read crendetials for CPX")
                    else:
                        logger.debug(
                            "SIDECAR Mode: None password while reading CPX crednetials from file")
            except IOError as e:
                logger.debug(
                    "SIDECAR Mode: IOError {}, while reading CPX crednetials from file".format(e))
    return ns_password


def get_cpx_credentials(ns_user, ns_password):
    'Get ns credenttials when CPX mode'

    logger.info("SIDECAR Mode: Trying to get credentials for CPX")
    try:
        ns_password = read_cpx_credentials(ns_password)
    except RetryError as e:
        logger.error('SIDECAR Mode: Unable to fetch CPX credentials {}'.format(e))

    if ns_password is not None:
        ns_user = 'nsroot'
    return ns_user, ns_password

# Priority order for credentials follows the order config.yaml input > env variables
# First env values are populated which can then be overwritten by config values if present.


def get_login_credentials(args):
    '''Gets the login credentials i.e ADC username and passoword'''

    ns_user = os.environ.get("NS_USER")
    ns_password = os.environ.get("NS_PASSWORD")

    deployment_mode = os.environ.get("NS_DEPLOYMENT_MODE", "")
    if deployment_mode.lower() == 'sidecar':
        logger.info('ADC is running as sidecar')
    else:
        logger.info('ADC is running as standalone')

    if os.environ.get('KUBERNETES_SERVICE_HOST') is not None:
        if os.path.isfile(NS_USERNAME_FILE):
            try:
                with open(NS_USERNAME_FILE, 'r') as f:
                    ns_user = f.read().rstrip()
            except Exception as e:
                logger.error('Error while reading secret. Verify if secret is properly mounted:{}'.format(e))

        if os.path.isfile(NS_PASSWORD_FILE):
            try:
                with open(NS_PASSWORD_FILE, 'r') as f:
                    ns_password = f.read().rstrip()
            except Exception as e:
                logger.error('Error while reading secret. Verify if secret is properly mounted:{}'.format(e))

        if ns_user is None and ns_password is None:
            if deployment_mode.lower() == DEPLOYMENT_WITH_CPX:
                ns_user, ns_password = get_cpx_credentials(
                    ns_user, ns_password)

    else:
        if hasattr(args, 'username'):
            ns_user = args.username

        if hasattr(args, 'password'):
            ns_password = args.password

    return ns_user, ns_password


def get_ns_session_protocol(args):
    'Get ns session protocol to access ADC'
    secure = args.secure.lower()
    if secure == 'yes':
        ns_protocol = 'https'
    else:
        ns_protocol = 'http'
    return ns_protocol


def retry_login(value):
    """Return True if value is None"""
    return value == 'retry'


def retry_get(value):
    """Return True if value is None"""
    x1, x2 = value
    return x1 == 'retry'


def get_ns_cert_path(args):
    'Get ns cert path if protocol is secure option is set'
    if args.cacert_path:
        ns_cacert_path = args.cacert_path
    else:
        ns_cacert_path = os.environ.get("NS_CACERT_PATH", None)

    if not ns_cacert_path:
        logger.error('EXITING : Certificate Validation enabled but cert path not provided')
        sys.exit()

    if not os.path.isfile(ns_cacert_path):
        logger.error('EXITING: ADC Cert validation enabled but CA cert does not exist {}'.format(ns_cacert_path))
        sys.exit()

    logger.info('CA certificate path found for validation')
    return ns_cacert_path


def get_cert_validation_args(args, ns_protocol):
    'Get ns validation args, if validation set, then fetch cert path'
    if args.validate_cert:
        ns_cert_validation = args.validate_cert.lower()
    else:
        ns_cert_validation = os.environ.get("NS_VALIDATE_CERT", 'no').lower()

    if ns_cert_validation == 'yes':
        if ns_protocol == 'https':
            logger.info('Cert Validation Enabled')
            ns_cert = get_ns_cert_path(args)
        else:
            logger.error('EXITING: Cert validation enabled on insecure session')
            sys.exit()
    else:
        ns_cert = False  # Set ns_sert as False for no cert validation
    return ns_cert

class CitrixAdcCollector(object):
    ''' Add/Update labels for metrics using prometheus apis.'''

    SUCCESS = 'SUCCESS'
    FAILURE = 'FAILURE'
    INVALID = 'INVALID'

    def __init__(self, nsip, metrics, username, password, protocol,
                 nitro_timeout, ns_cert):
        self.nsip = nsip
        self.metrics = metrics
        self.username = username
        self.password = password
        self.protocol = protocol
        self.nitro_timeout = nitro_timeout
        self.ns_cert = ns_cert
        self.ns_session = None
        self.stats_access_pending = False
        self.ns_session_pending = False

    # Collect metrics from Citrix ADC
    def collect(self):

        if self.stats_access_pending or self.ns_session_pending:
            yield self.populate_probe_status(self.FAILURE)
            return

        if not self.login():
            yield self.populate_probe_status(self.FAILURE)
            return

        data = {}
        self.stats_access_pending = True
        status = self.INVALID
        for entity in self.metrics.keys():
            logger.debug('Collecting metric {}'.format(entity))
            try:
                status, entity_data = self.collect_data(entity)
            except Exception as e:
                logger.error('Could not collect metric :{}'.format(e))

            if status == self.FAILURE:
                self.ns_session_clear()
                yield self.populate_probe_status(status)
                return

            if entity_data:
                data[entity] = entity_data

        # Add labels to metrics and provide to Prometheus
        log_prefix_match = True
        for entity_name, entity in self.metrics.items():
            if('labels' in entity.keys()):
                label_names = [v[1] for v in entity['labels']]
                label_names.append('nsip')
            else:
                label_names = []
                label_names.append('nsip')

            # Provide collected metric to Prometheus as a counter
            entity_stats = data.get(entity_name, [])
            if(type(entity_stats) is not list):
                entity_stats = [entity_stats]

            for ns_metric_name, prom_metric_name in entity.get('counters', []):
                c = CounterMetricFamily(
                    prom_metric_name, ns_metric_name, labels=label_names)
                for data_item in entity_stats:
                    if not data_item:
                        continue

                    if ns_metric_name not in data_item.keys():
                        logger.info('Counter stats {} not enabled for entity: {}'.format(ns_metric_name, entity_name))
                        break

                    if('labels' in entity.keys()):
                        label_values = [data_item[key]
                                        for key in [v[0] for v in entity['labels']]]
                        label_values.append(self.nsip)
                    else:
                        label_values = [self.nsip]
                    try:
                        c.add_metric(label_values, float(
                            data_item[ns_metric_name]))
                    except Exception as e:
                        logger.error('Caught exception while adding counter {} to {}: {}'.format(ns_metric_name, entity_name, str(e)))

                yield c


            for ns_metric_name, prom_metric_name in entity.get('time', []):
                t = CounterMetricFamily(
                    prom_metric_name, ns_metric_name, labels=label_names)
                for data_item in entity_stats:
                    if not data_item:
                        continue

                    if ns_metric_name not in data_item.keys():
                        logger.info('Counter stats {} not enabled for entity: {}'.format(ns_metric_name, entity_name))
                        break

                    if('labels' in entity.keys()):
                        label_values = [data_item[key]
                                        for key in [v[0] for v in entity['labels']]]
                        label_values.append(self.nsip)
                    else:
                        label_values = [self.nsip]
                    try:
                        t.add_metric(label_values, float(
                            int((datetime.strptime(data_item[ns_metric_name], '%a %b %d %H:%M:%S %Y') - EPOCH_TIME).total_seconds())))
                    except Exception as e:
                        logger.error('Caught exception while adding counter {} to {}: {}'.format(ns_metric_name, entity_name, str(e)))

                yield t

            for ns_metric_name, prom_metric_name in entity.get('enumasinfo', []):
                en = InfoMetricFamily(
                    prom_metric_name, ns_metric_name, labels=label_names)
                for data_item in entity_stats:
                    if not data_item:
                        continue

                    if ns_metric_name not in data_item.keys():
                        logger.info('EnumAsInfo stats {} not enabled for entity: {}'.format(ns_metric_name, entity_name))
                        break

                    if('labels' in entity.keys()):
                        label_values = [data_item[key]
                                        for key in [v[0] for v in entity['labels']]]
                        label_values.append(self.nsip)
                    else:
                        label_values = [self.nsip]
                    try:
                        en.add_metric(label_values, dict({
                            prom_metric_name: data_item[ns_metric_name]}
                        ))
                    except Exception as e:
                        logger.error('Caught exception while adding enumasinfo {} to {}: {}'.format(ns_metric_name, entity_name, str(e)))

                yield en

            # Provide collected metric to Prometheus as a gauge
            for ns_metric_name, prom_metric_name in entity.get('gauges', []):
                g = GaugeMetricFamily(
                    prom_metric_name, ns_metric_name, labels=label_names)

                for data_item in entity_stats:
                    if not data_item:
                        continue

                    if ns_metric_name not in data_item.keys():
                        logger.info('Gauge stat {} not enabled for entity: {}'.format(ns_metric_name, entity_name))
                        break

                    if('labels' in entity.keys()):
                        label_values = [data_item[key]
                                        for key in [v[0] for v in entity['labels']]]
                        label_values.append(self.nsip)
                    else:
                        label_values = [self.nsip]
                    try:
                        g.add_metric(label_values, float(
                            data_item[ns_metric_name]))
                    except Exception as e:
                        logger.error('Caught exception while adding counter {} to {}: {}'.format(ns_metric_name, entity_name, str(e)))

                yield g
        self.stats_access_pending = False
        yield self.populate_probe_status(status)

    # Function to fire nitro commands and collect data from NS
    def collect_data(self, entity):
        '''Fetches stats from ADC using nitro call for different entity types.'''

        url = '%s://%s/%s' % (self.protocol, self.nsip, entity)

        try:
            status, data = self.get_entity_stat(url)
            if data:
                if entity in data:
                    return status, data[entity]
                else:
                    logger.info('No metric data available for entity: {}'.format(entity))
                    if status == self.INVALID:
                        logger.debug('Invalid metric fetch for entity "{}" ' \
                                      'with errorcode:{} '.format(entity,data['errorcode']))
                    return status, None
            else:
                logger.warning('Unable to fetch data for entity: {}'.format(entity))
                return status, None
        except Exception as e:
            logger.error('Error in fetching entity {}'.format(e))
            return self.FAILURE, None

    @retry(stop=stop_after_attempt(2), retry=retry_if_result(retry_get))
    def ns_session_get(self, url):
        try:
            r = self.ns_session.get(
                url, verify=self.ns_cert, timeout=self.nitro_timeout)
            data = r.json()
            if data:
                if 'errorcode' in data:
                    if data['errorcode'] == 0:
                        return self.SUCCESS, data
                    elif data['errorcode'] in [NSERR_SESSION_EXPIRED, NSERR_AUTHTIMEOUT]:
                        self.ns_session_clear()
                        if self.login():
                           return 'retry', None
                        else:
                           return self.FAILURE, None
                    else:
                        return self.INVALID, data
            else:
                return self.FAILURE, None
        except requests.exceptions.RequestException as err:
            logger.error('Stat Access Error {}'.format(err))
        except Exception as e:
            logger.error('Unable to access stats from ADC {}'.format(e))
        return self.FAILURE, None

    def get_entity_stat(self, url):
        '''Fetches stats from ADC using nitro using for a particular entity.'''
        try:
            return self.ns_session_get(url)
        except RetryError as e:
            logger.error('Get Retries Exhausted {}'.format(e))
        except Exception as e:
            logger.error('Stat Access Failed {}'.format(e))
        return self.FAILURE, None

    def ns_session_clear(self):
        self.ns_session.close()
        self.ns_session = None
        self.ns_session_pending = False
        self.stats_access_pending = False

    def login(self):
        if self.ns_session:
            return True

        try:
            if self.ns_session_login() == self.SUCCESS:
                return True
        except RetryError as e:
            logger.error('Login Retries Exhausted {}'.format(e))
        except Exception as e:
            logger.error('Login Session Failed {}'.format(e))

        self.ns_session_clear()
        return False

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(5), retry=retry_if_result(retry_login))
    def ns_session_login(self):
        ''' Login to Citrix and get a session id for stat access'''
        payload = {"login": {'username': self.username,
                             'password': self.password}}
        url = '%s://%s/nitro/v1/config/login' % (self.protocol, self.nsip)
        self.ns_session = requests.Session()
        self.ns_session_pending = True
        try:
            response = self.ns_session.post(url, json=payload,
                                            verify=self.ns_cert, timeout=self.nitro_timeout)
            data = response.json()
            if data['errorcode'] == 0:
                logger.info("ADC Session Login Successful")
                sessionid = data['sessionid']
                self.ns_session.headers.update({'Set-Cookie': "sessionid=" + sessionid})
                self.ns_session_pending = False
                return self.SUCCESS
            elif data['errorcode'] in [NSERR_SESSION_EXPIRED, NSERR_AUTHTIMEOUT]:
                logger.error("ADC Session Login Failed: Retrying")
                return 'retry'
            elif data['errorcode'] in [NSERR_NOUSER, NSERR_INVALPASSWD]:
                logger.error('Invalid username or password for ADC')
        except requests.exceptions.RequestException as err:
            logger.error('Session Login Error {}'.format(err))
        except Exception as e:
            logger.error('Login Session Failed : {}'.format(e))
        return self.FAILURE

    def populate_probe_status(self, status):
        label_names = []
        label_names.append('nsip')
        g = GaugeMetricFamily("citrixadc_probe_success", "probe_success", labels=label_names)
        if status == self.FAILURE:
            g.add_metric([self.nsip], int("0"))
        else:
            g.add_metric([self.nsip], int("1"))

        return g



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--target-url', required=True, type=str,
                        help='The base URL path for the Odata point. Required')
    parser.add_argument('--start-delay', default=10, type=float,
                        help='Start the exporter running after a delay to allow other containers to start. Default: 10s')
    parser.add_argument('--port', default=8888, type=int,
                        help='The port for the exporter to listen on. Default: 8888')
    parser.add_argument('--metric', required=False, action='append', type=str,
                        help='Collect only the metrics specified here, may be used multiple times.')
    parser.add_argument('--secure', default='no', type=str,
                        help='yes: Use HTTPS, no: Use HTTP. Default: no')
    parser.add_argument('--validate-cert', required=False, type=str,
                        help='yes: Validate Cert, no: Do not validate cert. Default: no')
    parser.add_argument('--cacert-path', required=False,
                        type=str, help='Certificate path for secure validation')
    parser.add_argument('--timeout', default=10, type=float,
                        help='Timeout for Nitro calls.')
    parser.add_argument('--metrics-file', required=False, default='/exporter/metrics.json',
                        type=str, help='Location of metrics.json file. Default: /exporter/metrics.json')
    parser.add_argument('--log-file', required=False, default='/exporter/exporter.log',
                        type=str, help='Location of exporter.log file. Default: /exporter/exporter.log')
    parser.add_argument('--log-level', required=False, default='INFO', type=str, choices=[
                        'DEBUG', 'INFO', 'WARN', 'ERROR', 'CRITICAL', 'debug', 'info', 'warn', 'error', 'critical'])
    parser.add_argument('--config-file', required=False, type=str)

    # parse arguments provided
    args = parser.parse_args()

    # set logging credentials
    global logger
    logger = set_logging_args(args.log_file, args.log_level)

    # parse config file if provided as an argument
    if args.config_file:
        args = parseConfig(args)

    # Get username and password of Citrix ADC
    ns_user, ns_password = get_login_credentials(args)

    # Wait for other containers to start.
    logger.info('Sleeping for %s seconds.' % args.start_delay)
    time.sleep(args.start_delay)

    # Load the metrics file specifying stats to be collected
    metrics_json = get_metrics_file_data(args.metrics_file, args.metric)

    # Get protocol type to access ADC
    ns_protocol = get_ns_session_protocol(args)

    # Get cert validation args provided
    ns_cert = get_cert_validation_args(args, ns_protocol)

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    requests.packages.urllib3.disable_warnings(SubjectAltNameWarning)

    # Start the server to expose the metrics.
    start_exporter_server(args.port)


    # Register the exporter as a stat collector
    logger.info('Registering collector for %s' % args.target_nsip)

    try:
        REGISTRY.register(CitrixAdcCollector(nsip=args.target_nsip, metrics=metrics_json, username=ns_user,
                                             password=ns_password, protocol=ns_protocol,
                                             nitro_timeout=args.timeout, ns_cert=ns_cert))
    except Exception as e:
        logger.error('Invalid arguments! could not register collector for {}::{}'.format(args.target_nsip, e))

    while True:
        signal.pause()

if __name__ == '__main__':
    main()

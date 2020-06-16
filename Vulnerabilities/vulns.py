#!/usr/bin/env python3
# encoding: utf-8

from elasticsearch import Elasticsearch
from cortexutils.analyzer import Analyzer

class VulnerabilitiesAnalyzer(Analyzer):
    # Analyzer's constructor
    def __init__(self):
        # Call the constructor of the super class
        Analyzer.__init__(self)
        self.host = self.get_param('config.host', "localhost", 'Host parameter is missing')
        self.port = self.get_param('config.port', "9200", 'Port parameter is missing')
        self.https = self.get_param('config.https', False)
        self.scanrange = self.get_param('config.scanrange', "14", 'Scan range parameter is missing')
        self.fieldip = self.get_param('config.scanip', None, 'IP is missing')
        self.fielddate = self.get_param('config.scandate', None, 'Scan timestamp index is missing')
        self.index = self.get_param('config.index', None, 'Elasticsearch index is missing')
        self.username = self.get_param('config.username', 'elastic')
        self.password = self.get_param('config.password', 'changeme')
        self.cert_check = self.get_param('config.verifyssl', True, None)
        self.cert_path = self.get_param('config.cert_path', None)
        self.client = None
        self.service = self.get_param('config.service', None, 'Service parameter is missing')

    def run(self):
        Analyzer.run(self)
        elasticsearch_array = []
        for server in self.host:
            elasticsearch_array.append("{}:{}".format(server, self.port))
        #Setup user
        if self.username is not None:
            self.https_auth = (self.username, self.password)
        else:
            self.https_auth = None

        try:
            self.client = Elasticsearch(elasticsearch_array, use_ssl=self.https, http_auth=self.https_auth, verify_certs=self.cert_check, ca_certs=self.cert_path)
        except Exception as e:
            self.error("Elasticsearch is not available or wrong user/password", e)
            return

        result = {}
        es_result_ids = []
        es_result_data = []
        es_result_buckets = []
        range = "now-"+str(self.scanrange)+"d"
        data = self.get_param('data', None, 'Data is missing')
        try:
             res = self.client.search(index=self.index, body={"query":{"bool":{"must":[{"match":{self.fieldip:data}}],"filter":[{"range":{"@timestamp":{"gte":range}}}]}},"aggs":{"scans":{"filter":{"range":{"@timestamp":{"gte":range}}},"aggs":{"scan_date":{"terms":{"field":self.fielddate}}}}},"size":1000})
        except Exception as e:
            self.unexpectedError(e)
            return

        es_result_buckets = res['aggregations']['scans']
        for doc in res['hits']['hits']:
            es_result_ids.append(doc['_id'])
            es_result_data.append(doc['_source'])
        result['ids'] = list(set(es_result_ids))
        result['results'] = es_result_data
        result['agg'] = es_result_buckets

        # Return the report
        return self.report(result)

    def summary(self, raw):
        taxonomies = []
        namespace = "Vuln"
        predicate = "Scans"

        if len(raw["agg"]) == 1:
            value = "{} match".format(len(raw["agg"]))
        else:
            value = "{} matches".format(len(raw["agg"]))

        level = "info"

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {"taxonomies": taxonomies}

if __name__ == '__main__':
    VulnerabilitiesAnalyzer().run()


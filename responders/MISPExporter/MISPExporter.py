#!/usr/bin/env python3
# encoding: utf-8
# Many thanks to code borrowed from the yet-to-be-merged RT4-CreateTicket responder!


from cortexutils.responder import Responder
import json
import requests
from pymisp import PyMISP, ExpandedPyMISP, MISPEvent, MISPTag
from pymisp.tools import make_binary_objects
import logging
import base64
from datetime import datetime, timedelta
from io import BytesIO

class MISPExporter(Responder):
    def __init__(self, logger=None):
        # Setup logging
        self.logger = logger or logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        # Create file handler
        handler = logging.FileHandler('/var/log/cortex/mispexport.log')
        handler.setLevel(logging.DEBUG)
        # Create format
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        handler.setFormatter(formatter)
        # add the file handler to the logger
        self.logger.addHandler(handler)
        self.logger.debug("Logging initialized. Saving to /var/log/cortex/mispexport.log")
        try:
            Responder.__init__(self)
            self.misp_url = self.get_param('config.misp_url', None, "MISP URL missing")
            self.misp_api = self.get_param('config.misp_api', None, "MISP API Key missing")
            self.taxonomy_prefix = self.get_param('config.taxonomy_prefix', None)
            self.misp_distribution = self.get_param("config.misp_distribution", None, "MISP Distribution must be set")
            self.misp_threat_level = self.get_param("config.misp_threat_level", None, "MISP Threat Level must be set")
            self.misp_analysis = self.get_param("config.misp_analysis", None, "MISP analysis level must be set")
            self.misp_publish = self.get_param("config.misp_publish", 0)
            self.all_observables = self.get_param("config.all_observables", 1)
            self.support_files = self.get_param("config.suppot_files", 1)
            # If universal_tag isn't set then the whole thing dies. Maybe put another try in here?
            self.universal_tag = self.get_param('config.universal_tag', None)
            self.logger.debug("Loaded configs okay")
        except Exception as ex:
            self.logger.error("Exception occurred loading configs", exc_info=True)
        try:
            self.misp = ExpandedPyMISP(self.misp_url, self.misp_api, False)
        except Exception as ex:
            self.logger.error("Exception occurred loading MISP", exc_info=True)

        self.misp_map = {
            "ip-src": {"cat": "Network activity", "type": "ip-src"},
            "ip-dst": {"cat": "Network activity", "type": "ip-dst"},
            "domain": {"cat": "Network activity", "type": "domain"},
            "url": {"cat": "Network activity", "type": "url"},
            "uri_path": {"cat": "Network activity", "type": "uri"},
            "email-subject": {"cat": "Payload delivery", "type": "email-subject"},
            "email-src": {"cat": "Payload delivery", "type": "email-src"},
            "email-dst": {"cat": "Payload delivery", "type": "email-dst"},
            "unique-string": {"cat": "Artifacts dropped", "type": "pattern-in-file"},
            "sig-bro": {"cat": "External analysis", "type": "bro"},
            "sig-snort": {"cat": "External analysis", "type": "snort"},
            "sig-yara": {"cat": "Artifacts dropped", "type": "yara"},
            "sig-other": {"cat": "Support Tool", "type": "other"},
            "tewi-number": {"cat": "Internal reference", "type": "text", "tag": "tewi-number"},
            "ext-ref": {"cat": "Internal reference", "type": "text", "tag": "ext-ref"},
            "related-case": {"cat": "Internal reference", "type": "text", "tag": "related-case"},
            "user-agent": {"cat": "Network activity", "type": "user-agent"},
            "md5": {"cat": "Payload delivery", "type": "md5"},
            "sha1": {"cat": "Payload delivery", "type": "sha1"},
            "sha256": {"cat": "Payload delivery", "type": "sha256"}
        }

    def get_observables(self, thehive_url, thehive_token, case_id):
        payload = {
            "query": { "_parent": { "_type": "case", "_query": { "_id": case_id } } },
            "range": "all"
        }
        headers = { 'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(thehive_token) }

        thehive_api_url_case_search = '{}/api/case/artifact/_search'.format(thehive_url)
        r = requests.post(thehive_api_url_case_search, data=json.dumps(payload), headers=headers)
        self.logger.debug("Request sent. Response: %s", str(r))

        if r.status_code != requests.codes.ok:
            self.logger.error("POSTing ERROR: %s", str(r.text))
            self.error(json.dumps(r.text))

        observables = r.json()
        self.logger.debug("instance_data: %s", str(observables))
        return observables

    def get_case_tasks(self, thehive_url, thehive_token, case_id):
        payload = {
            "query": { "_parent": { "_type": "case", "_query": { "_id": case_id } } },
            "range": "all"
        }
        headers = { 'Content-Type': 'application/json', 'Authorization': 'Bearer {}'.format(thehive_token) }

        thehive_api_url_case_search = '{}/api/case/task/_search'.format(thehive_url)
        r = requests.post(thehive_api_url_case_search, data=json.dumps(payload), headers=headers)
        self.logger.debug("Request sent. Response: %s", str(r))

        if r.status_code != requests.codes.ok:
            self.logger.error("POSTing ERROR: %s", str(r.text))
            self.error(json.dumps(r.text))

        task_data = r.json()
        self.logger.debug("task_data: %s", str(task_data))
        return task_data

    def get_task_logs(self, thehive_url, thehive_token, case_id, task_data):
        task_log_headers = {'Authorization': 'Bearer {}'.format(thehive_token) }
        all_task_logs = {}
        for task in task_data:
            thehive_api_url_task_logs = "{}/api/case/task/{}/log".format(thehive_url, task['id'])
            # r = requests.get(thehive_api_url_task_logs, headers=headers)
            r = requests.get(thehive_api_url_task_logs, headers=task_log_headers)
            self.logger.debug("Request sent. Response: %s", str(r))

            if r.status_code != requests.codes.ok:
                self.logger.error("GET ERROR: %s", str(r.text))
                self.error(json.dumps(r.text))
            task_logs = r.json()
            #self.logger.debug("task_logs: %s", str(task_logs))
            if task['id'] not in all_task_logs:
                all_task_logs[task['id']]=task_logs
        self.logger.debug("all_task_logs: %s", str(all_task_logs))
        return all_task_logs

    def download_file(self, thehive_url, thehive_token, att_hash):
        download_headers = {'Authorization': 'Bearer {}'.format(thehive_token) }
        thehive_api_url_download = "{}/api/datastore/{}".format(thehive_url, att_hash)
        r = requests.get(thehive_api_url_download, headers=download_headers)
        self.logger.debug("Request sent. Response: %s", str(r))
        if r.status_code != requests.codes.ok:
            self.logger.error("GET ERROR: %s", str(r.text))
            self.error(json.dumps(r.text))
        encoded_file = str(base64.b64encode(r.content).decode("utf-8"))
        return encoded_file

    def search_misp(self, event_info):
        self.logger.debug("Searching MISP for %s", str(event_info))
        result = self.misp.search(eventinfo=event_info)
        epoch = int(self.get_param("data.createdAt")/1000)
        self.logger.debug("epoch date/time is set to %s", str(epoch))
        dt = datetime.fromtimestamp(epoch)
        if len(result) == 0:
            self.logger.debug("No results found.")
            event = MISPEvent()
            event.distribution = self.misp_distribution
            event.threat_level = self.misp_threat_level
            event.analysis = self.misp_analysis
            event.info = event_info
            event.set_date(dt)
            #event = misp.add_event(event)['Event']
            is_new = True
        else:
            self.logger.debug("%s results found!", str(len(result)))
            for evt in result:
                if evt['Event']['info'] == event_info:
                    self.logger.debug("Matching result found!")
                    if 'SharingGroup' in evt["Event"]:
                        del evt['Event']['SharingGroup']
                    # event = evt['Event']
                    event = MISPEvent()
                    event.from_dict(**evt)
                    is_new = False
                    break
                if event == '':
                    # Event not found, even though search results were returned
                    # Build new event
                    self.logger.debug("Results were found but no event matched.")
                    event = MISPEvent()
                    event.distribution = self.misp_distribution
                    event.threat_level = self.misp_threat_level
                    event.analysis = self.misp_analysis
                    event.info = event_info
                    event.set_date(dt)
                    is_new = True
                    #event = misp.add_event(event)['Event']
        return event, is_new

    def update_existing_event(self, misp_event):
        # Get the existing event so we can compare it to our new event
        update_results = []
        event_id = misp_event.id
        result = self.misp.search(eventid=event_id)
        for evt in result:
            existing_event = MISPEvent()
            existing_event.from_dict(**evt)
            break
        # Loop through attributes
        for old_attr in existing_event.Attribute:
            for new_attr in misp_event.Attribute:
                if new_attr.value == old_attr.value:
                    # Update the time
                    epoch = datetime.now() + timedelta(seconds=1)
                    new_attr.timestamp = epoch
                    res = self.misp.update_attribute(new_attr, attribute_id=old_attr.uuid)
                    update_results.append(res)

        return update_results

    def add_misp_attributes(self, misp_event, thehive_case):
        # Add all observables that aren't malware samples
        for obs in thehive_case['observables']:
            # Ignore files b/c we process them under the malware and suppoting file sections
            if obs['dataType']=="file":
                continue
            # Check if we're exporting all observables or only the ones marked as IOCs
            if self.all_observables:
                export_obs = True
            else:
                if obs['ioc']:
                    export_obs = True
                else:
                    export_obs = False
            if export_obs:
                if 'description' in obs:
                    comment = obs['description']
                else:
                    comment = ""
                misp_tags = []

                if len(obs['tags'])>0:
                    for tag in obs['tags']:
                        misp_tag = MISPTag()
                        misp_tag.from_dict(name=tag)
                        if misp_tag not in misp_tags:
                            misp_tags.append(misp_tag)

                if obs['dataType'] in self.misp_map:
                    if 'tag' in self.misp_map[obs['dataType']]:
                        misp_tag = MISPTag()
                        if self.taxonomy_prefix:
                            tag_name = self.taxonomy_prefix+":"+self.misp_map[obs['dataType']]['tag']
                        else:
                            tag_name = self.misp_map[obs['dataType']]['tag']
                        misp_tag.from_dict(name=tag_name)
                        misp_tags.append(misp_tag)

                    misp_event.add_attribute(self.misp_map[obs['dataType']]['type'], obs['data'],
                        category=self.misp_map[obs['dataType']]['cat'], tags=misp_tags, comment=comment)
                else:
                    misp_event.add_attribute("other", obs['data'], tags=misp_tags, comment=comment)
        
        # Add malware samples
        if isinstance(thehive_case['malware'], dict):
            for mal_hash, sample in thehive_case['malware'].items():
                decoded = base64.b64decode(sample['file'])
                pseudofile = BytesIO(decoded)
                try:
                    fo, peo, seos = make_binary_objects(pseudofile=pseudofile)
                except Exception as ex:
                    self.logger.warning("Error parsing sample", exc_info=True)
                    continue
                if seos:
                    for s in seos:
                        misp_event.add_object(s)
                if peo:
                    misp_event.add_object(peo)
                if fo:
                    misp_event.add_object(fo)

        # Add case-related data
        case_owner = self.get_param('data.createdBy', "Unknown")
        custom_fields = self.get_param('data.customFields', None)
        self.logger.debug("Processing custom fields... %s", str(custom_fields))
        for k, v in custom_fields.items():
            #self.logger.debug("Key/Value: %s : %s", (str(k), str(v)))
            if k == "sitRep":
                #self.logger.debug("sitRep found. K/V: %s : %s", (str(k), str(v)))
                misp_tag = MISPTag()
                if self.taxonomy_prefix:
                    tag_name = self.taxonomy_prefix+":sit-rep"
                else:
                    tag_name = "sit-rep"
                misp_tag.from_dict(name=tag_name)
                misp_event.add_attribute("text", v['string'], category="Internal reference", tags=[misp_tag])
            elif k.startswith("bureau"):
                #self.logger.debug("bureau found. K/V: %s : %s", (str(k), str(v)))
                misp_tag = MISPTag()
                if self.taxonomy_prefix:
                    tag_name = self.taxonomy_prefix+":bureau"
                else:
                    tag_name = "bureau"
                misp_tag.from_dict(name=tag_name)
                misp_event.add_attribute("text", k, category="Internal reference", tags=[misp_tag],
                    comment=v['string'])
            elif k == "caseSource":
                #self.logger.debug("caseSource found. K/V: %s : %s", (str(k), str(v)))
                misp_tag = MISPTag()
                if self.taxonomy_prefix:
                    tag_name = self.taxonomy_prefix+":case-source"
                else:
                    tag_name = "case-source"
                misp_tag.from_dict(name=tag_name)
                misp_event.add_attribute("text", v['string'], category="Internal reference", tags=[misp_tag])
            elif k == "timeOccurred":
                #self.logger.debug("timeOccured found. K/V: %s : %s", (str(k), str(v)))
                misp_tag = MISPTag()
                if self.taxonomy_prefix:
                    tag_name = self.taxonomy_prefix+":time-occurred"
                else:
                    tag_name = "time-occurred"
                misp_tag.from_dict(name=tag_name)
                misp_event.add_attribute("text", v['date'], category="Internal reference", tags=[misp_tag])
            else:
                #self.logger.debug("other found. K/V: %s : %s", (str(k), str(v)))
                misp_tag = MISPTag()
                if self.taxonomy_prefix:
                    tag_name = self.taxonomy_prefix+":"+str(k)
                else:
                    tag_name = str(k)
                misp_tag.from_dict(name=tag_name)
                misp_event.add_attribute("other", v['string'], tags=[misp_tag])

        # Add case details as external analysis
        case_details = self.get_param('data.description', None)
        if case_details:
            misp_event.add_attribute("comment", case_details, category="External analysis")

        return misp_event

    def run(self):
        try:
            Responder.run(self)
            data = self.get_param('data', None, 'Missing data field')
            self.logger.debug("dir of self: %s", str(dir(self)))
            self.logger.debug("data: %s", str(data))
            #self.report({"data":data})


        except Exception as ex:
            self.logger.error("Run exception", exc_info=True)
            self.error(ex)

        thehive_url = self.get_param('config.thehive_url', None, """
            Missing URL for TheHive. Must have configured this Responder setting to process Cases.""")
        thehive_token = self.get_param('config.thehive_token', None, """
            Missing API token for TheHive. Must have configured this Responder setting to process Cases.""")
        case_id = self.get_param('data._id')
        
        # Get observables from Case
        observables = self.get_observables(thehive_url, thehive_token, case_id)

        # Get case tasks
        case_tasks = self.get_case_tasks(thehive_url, thehive_token, case_id)

        # Get task logs
        task_logs = self.get_task_logs(thehive_url, thehive_token, case_id, case_tasks)

        # Download files
        malware = {}
        for observable in observables:
            if 'attachment' in observable:
                filename = observable['attachment']['name']
                att_hash = observable['attachment']['hashes'][0]
                if att_hash not in malware:
                    encoded_file = self.download_file(thehive_url, thehive_token, att_hash)
                    malware[att_hash]={'file': encoded_file, 'name': filename}

        # Collect supporting files from task_logs
        support_files = {}
        for log in task_logs:
            if 'attachment' in log:
                filename = log['attachment']['name']
                att_hash = log['attachment']['hashes'][0]
                if att_hash not in support_files:
                    encoded_file = self.download_file(thehive_url, thehive_token, att_hash)
                    support_files[att_hash]={'file': encoded_file, 'name': filename}

        # Bundle it all together
        thehive_case = {'case_tasks': case_tasks,
                        'malware': malware,
                        'observables': observables,
                        'support_files': support_files,
                        'task_logs': task_logs}

        # Search MISP for existing event
        title = self.get_param('data.title')
        case_no = self.get_param('data.caseId')
        event_info = "Case #"+str(case_no)+" - "+title
        # Get existing MISP event or build new one
        self.logger.debug("Searching MISP for existing events")
        misp_event, is_new = self.search_misp(event_info)
        self.logger.debug("Search finished. New event?: %s", str(is_new))
        # Add observables to MISP event as attributes
        final_misp_event = self.add_misp_attributes(misp_event, thehive_case)
        self.logger.debug("Processing final MISP event: %s", str(final_misp_event.to_dict()))
        # Update or add the event
        if is_new:
            try:
                result = self.misp.add_event(final_misp_event)
                self.logger.debug("New event successfully created: %s", str(result))
                self.report({'message': "New event successfully created.",
                             'url': self.misp_url+"/events/view/"+result['Event']['id'],
                             'results': result})
            except Exception as ex:
                self.logger.error("Exception occurred creating new event.", exc_info=True)
                self.error(str(ex))
                
        else:
            try:
                result = self.misp.update_event(final_misp_event)
                attrib_results = self.update_existing_event(final_misp_event)
                self.logger.debug("Existing event successfully updated: %s", str(result))
                self.report({'message': "Existing event successfully updated.",
                             'url': self.misp_url+"/events/view/"+result['Event']['id'],
                             'results': result,
                             'attrib_results': attrib_results})
            except Exception as ex:
                self.logger.error("Exception occurred while updating event.", exc_info=True)
                self.error(str(ex))

if __name__ == '__main__':
    MISPExporter().run()

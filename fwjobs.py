#! /usr/bin/python3

################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2022  flexiWAN Ltd.
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
################################################################################

import json
import traceback
from datetime import datetime

from fwobject import FwObject
from fwsqlitedict import FwSqliteDict

class FwJobs(FwObject):
    """This is the class representation of received and processed job database.
    Persistent database that is used to keep requests received from flexiManage.
    These requests are called jobs on flexiManage. Hence the 'FwJobs' name.

    Example of the typical entry:
    {
        "request": "sync-device",
        "errors": [
        {
            "request": "add-route",
            "command": {
                "name": "python",
                "error": "add_remove_route: dev_id_to_linux_if_name failed"
            },
            "revert": {
                "name": "python",
                "error": "add_remove_route: dev_id_to_linux_if_name failed"
            }
        },
        {
            "reverted_request": "remove-route",
            "command": {
                "name": "python",
                "error": "add_remove_route: dev_id_to_linux_if_name failed"
            }
        }
        ],
        "job_id": "5110",
        "state": "failed",
        "received_at": "Jun 08, 2022, 05:01 AM"
    }
    """

    def __init__(self, db_file):
        """Constructor method

        :param db_file:      SQLite database file name.
        """
        FwObject.__init__(self)

        self.db = FwSqliteDict(db_file)
        # Holds the list of job ids. Made in order to avoid costly list generation
        # during jobs collection manipulation.
        self.job_ids = list(self.db.keys())
        self.max_stored_jobs = 16
        # Holds the id of the job which is currently being executed.
        self.current_job_id = None

    # the three functions below (__enter__, __exit__, and finalize) are needed in order
    # for the "with" construct to work properly
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, trace_back):
        self.finalize()

    def finalize(self):
        """Destructor
        """
        self.db.close()

    def start_recording(self, job_id, request):
        """Adds received job record into database.

        :param job_id:      The id of the job received from flexiManage.
        :param request:     The received request.

        :returns: None.
        """

        if not job_id:
            return

        self.current_job_id = job_id

        entry = self.db.get(job_id)
        if entry is not None:
            self.log.debug(f"start_recording(job_id={job_id}): job exists, return")
            return

        # pop the oldest item in the database, if max size exceeded
        if len(self.db) >= self.max_stored_jobs:
            self.db.pop(self.job_ids.pop(0))
        self.job_ids.append(self.current_job_id)
        received_at = datetime.now().strftime('%b %d, %Y, %I:%M %p')
        request_name = request['message'] if request['message'] != 'aggregated' else "aggregated(%s)" % (str(list(map(lambda x: x['message'], request['params']['requests']))))
        self.db[self.current_job_id] = {
            'received_at': received_at,
            'request': request_name,
            'state': 'running',
            'errors': [],
        }
        self.log.debug(f"(start_record), job_id {self.current_job_id} added, total number of recorded jobs {len(self.job_ids)}")

    def add_record(self, job_id, err):
        """Creates job record. Useful when the error occurred during pre-processing
        of the request, but we still want to create a record of a failure

        :param job_id:      The id of the job received from flexiManage.
        :param error:       The error to be recorded.

        :returns: None.
        """
        if not job_id:  # Take care of requests without 'job_id', like 'get-device-stats'
            return

        self.start_recording(job_id, { 'message': '' })
        self.update_current_record(err)
        self.stop_recording(job_id, { 'ok': 0})

    def update_current_record(self, error):
        """Updates current job record in case of an error. Uses stored current job id.

        :param error:       The error which occurred while processing the job.

        :returns: None.
        """

        self.update_record(self.current_job_id, error)

    def update_record(self, job_id, error):
        """Updates job record in case of an error.

        :param job_id:      The id of the job to update.
        :param error:       The dictionary with error which occurred while processing the job. Example:
        :{'request': 'upgrade-device-sw', 'command': 'extract previous version', 'error': 'failed to extract previous version'}

        :returns: None.
        """

        if not job_id:
            return

        self._update(job_id, 'failed', error)

    def stop_recording(self, job_id, reply):
        """Stops recording job updates.

        :param reply:       Job process result.

        :returns: None.
        """

        if not job_id:
            return

        self._update(job_id, 'complete' if reply['ok'] == 1 else 'failed')
        if job_id == self.current_job_id:
            self.current_job_id = None

    def _update(self, job_id, state, error=None):
        """Updates current job status in the database.

        :param state:       Job state. 'complete' and 'failed' are valid state names
                            used for compatibility with management
        :param error:       Error which occurred during the execution of the
                            request. When the error is None, assume the job
                            has finished successfully.

        :returns: None.
        """

        try:
            entry = self.db.get(job_id)
            if not entry:
                self.log.error(f"(update), job {job_id} not found")
                return

            entry['state'] = state
            if error:
                # error happened during job handling
                entry['errors'].append(error)
            self.db[job_id] = entry # The underneath sqldict does not support in-memory modification, so replace whole element
            return
        except Exception as e:
            self.log.error(
                "update(%s) failed: %s, %s"
                % (job_id, str(e), str(traceback.format_exc()))
            )

    def dump(self, job_ids=None):
        """Dumps requested jobs database into list of recent jobs.

        :param job_ids: The ids of the jobs to retrieve.

        :returns: The list of requested jobs stored in database.
        """
        jobs = []
        db_keys = (
            list(filter(lambda job_id: int(job_id) in job_ids, self.job_ids))
            if job_ids
            else self.job_ids
        )
        for job_id in sorted(db_keys):
            job = {
                'job_id': job_id,
                'request': self.db[job_id].get('request', ''),
                'received_at': self.db[job_id].get('received_at', {}),
                'errors': self.db[job_id].get('errors', []),
                'state': self.db[job_id].get('state', ''),
            }
            jobs.append(job)

        return jobs

    def dumps(self):
        """Dumps stored jobs into printable string."""
        return json.dumps(self.dump(), indent=2, sort_keys=True)

    def update_job_error(self, error, job_id=None):
        """Updates job error.

        :param error : The error to report.
        :param job_id: The job id of the request.

        :returns: None.
        """
        if not job_id:
            job_id = self.current_job_id
        if job_id == None:
            self.log.warning(f"(update_job_error), job id empty, nothing to update")
            return

        entry = self.db.get(job_id)
        if not entry:
            self.log.error(f"(update_job_error), job entry id {job_id} not found")
            return

        if error:
            # error happened during job handling
            entry['errors'].append(error)
            self.db[job_id] = entry # The underneath sqldict does not support in-memory modification, so replace whole element
            return
        self.log.warning(f"(update_job_error), job {job_id}, error is empty, nothing to update")

-- III-IV
-- Copyright 2023 Julio Merino
--
-- Licensed under the Apache License, Version 2.0 (the "License"); you may not
-- use this file except in compliance with the License.  You may obtain a copy
-- of the License at:
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
-- WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
-- License for the specific language governing permissions and limitations
-- under the License.

CREATE TABLE IF NOT EXISTS tasks (
    -- Unique identifier for this task.
    id UUID PRIMARY KEY NOT NULL,

    -- JSON-serialized contents of the task.
    json TEXT NOT NULL,

    -- Current status of the task.
    status_code SMALLINT NOT NULL,

    -- Reason explaining the current status of the task.  May be NULL depending
    -- on the status_code.
    status_reason TEXT,

    -- Number of times the task attempted to run.
    runs SMALLINT NOT NULL,

    -- The time the task was created.  Useful for debugging purposes.
    created TIMESTAMPTZ NOT NULL,

    -- The time the task was last updated.  Must be initialized as "created" when
    -- the task is first inserted into the queue.
    updated TIMESTAMPTZ NOT NULL,

    -- The earliest time the task is allowed to run.
    only_after TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS tasks_by_runnable_state
    ON tasks (status_code, updated);

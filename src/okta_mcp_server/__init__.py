# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import ssl

import truststore

truststore.inject_into_ssl()

# Patch SamlApplicationSettingsSignOn so that the five StrictBool fields the Okta
# API sometimes omits on older/partial SAML app configs become optional (default False).
# Without this patch the SDK raises a pydantic ValidationError for every such app,
# crashing list_applications and list_group_apps entirely.
from okta.models.saml_application_settings_sign_on import SamlApplicationSettingsSignOn
from pydantic_core import PydanticUndefined

_BOOL_FIELDS_TO_MAKE_OPTIONAL = (
    "allow_multiple_acs_endpoints",
    "assertion_signed",
    "honor_force_authn",
    "request_compressed",
    "response_signed",
)
for _fname in _BOOL_FIELDS_TO_MAKE_OPTIONAL:
    _field = SamlApplicationSettingsSignOn.model_fields.get(_fname)
    if _field is not None and _field.default is PydanticUndefined:
        _field.default = False
SamlApplicationSettingsSignOn.model_rebuild(force=True)

from . import server


def main():
    """Run the Okta MCP server."""
    server.main()

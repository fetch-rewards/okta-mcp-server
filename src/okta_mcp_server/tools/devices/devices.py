# The Okta software accompanied by this notice is provided pursuant to the following terms:
# Copyright © 2025-Present, Okta, Inc.
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from typing import Optional

from loguru import logger
from mcp.server.fastmcp import Context

from okta_mcp_server.server import mcp
from okta_mcp_server.utils.client import get_okta_client
from okta_mcp_server.utils.pagination import (
    build_query_params,
    create_paginated_response,
    extract_after_cursor,
    paginate_all_results,
)
from okta_mcp_server.utils.scope_guard import require_scopes
from okta_mcp_server.utils.validation import validate_ids


@mcp.tool()
@require_scopes("okta.devices.read")
async def list_devices(
    ctx: Context,
    search: str = "",
    expand: Optional[str] = None,
    fetch_all: bool = False,
    after: Optional[str] = None,
    limit: Optional[int] = None,
) -> dict:
    """List all managed and registered devices in the Okta organization, with pagination support.

    This calls Okta's Device API (GET /api/v1/devices) — the actual device inventory,
    not device assurance policies. Use this to answer questions like "how many devices
    are registered" or "list devices with a given status".

    IMPORTANT — default page size:
        When limit is NOT provided, the server defaults to 20 devices per page.
        ALWAYS omit the limit parameter unless the user explicitly requests a
        different page size.

    Parameters:
        search (str, optional): SCIM filter expression to filter devices
            (e.g. 'status eq "ACTIVE"'). Searches include device profile
            properties and the device id, status, and lastUpdated properties.
        expand (str, optional): Pass "user" to include associated user details
            and management status for each device in the _embedded attribute.
        fetch_all (bool, optional): If True, automatically fetch all pages of results.
            Default: False.
            NOTE: fetch_all is capped at 10 pages (2,000 devices) to keep responses
            manageable. If the org has more devices than the cap, the result will be
            partial — always check pagination_info.stopped_early in the response.
        after (str, optional): Pagination cursor for fetching results after this point.
        limit (int, optional): Maximum number of devices to return per page (min 1, max 200).
            Default: 20.

    Examples:
        - List active devices: list_devices(search='status eq "ACTIVE"')
        - Next page: list_devices(search='status eq "ACTIVE"', after="cursor_value")
        - All pages: list_devices(fetch_all=True)

    Returns:
        Dict containing:
        - items: List of device objects
        - total_fetched: Number of devices returned
        - has_more: Boolean indicating if more results are available
        - next_cursor: Cursor for the next page (if has_more is True)
        - fetch_all_used: Boolean indicating if fetch_all was used
        - pagination_info: Additional pagination metadata (when fetch_all=True)
    """
    logger.info("Listing devices from Okta organization")
    logger.debug(f"Search: '{search}', expand: '{expand}', fetch_all: {fetch_all}, after: '{after}', limit: {limit}")

    if limit is None:
        limit = 20

    limit_clamped = None
    if limit < 1:
        logger.warning(f"Limit {limit} is below minimum (1), setting to 1")
        limit_clamped = f"limit {limit} is below minimum (1); clamped to 1"
        limit = 1
    elif limit > 200:
        logger.warning(f"Limit {limit} exceeds maximum (200), setting to 200")
        limit_clamped = f"limit {limit} exceeds maximum (200); clamped to 200"
        limit = 200

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        effective_limit = 200 if fetch_all else limit
        query_params = build_query_params(search=search, after=after, limit=effective_limit, expand=expand)

        logger.debug("Calling Okta API to list devices")
        devices, response, err = await client.list_devices(**query_params)

        if err:
            logger.error(f"Okta API error while listing devices: {err}")
            return {"error": f"Error: {err}"}

        if not devices:
            logger.info("No devices found")
            result = create_paginated_response([], response, fetch_all_used=fetch_all)
            if limit_clamped:
                result["warning"] = limit_clamped
            return result

        device_items = list(devices)

        _has_more = (hasattr(response, "has_next") and response.has_next()) or bool(extract_after_cursor(response))
        if fetch_all and response and _has_more:
            logger.info(f"fetch_all=True, auto-paginating from initial {len(device_items)} devices")

            async def _next_page(cursor):
                p = {k: v for k, v in query_params.items() if k not in ["after", "limit"]}
                p["after"] = cursor
                p["limit"] = 200
                return await client.list_devices(**p)

            async def _on_page(pages, total):
                logger.info(f"[list_devices] Page {pages} fetched — {total} devices total so far")
                if pages % 5 == 0:
                    await ctx.info(f"Fetching devices... {total} fetched so far ({pages} pages)")

            all_devices, pagination_info = await paginate_all_results(
                response, device_items, next_page_fn=_next_page, on_page=_on_page, max_pages=10
            )

            logger.info(
                f"Successfully retrieved {len(all_devices)} devices across {pagination_info['pages_fetched']} pages"
            )
            result = create_paginated_response(
                all_devices, response, fetch_all_used=True, pagination_info=pagination_info
            )
            warnings = []
            if limit_clamped:
                warnings.append(limit_clamped)
            if pagination_info.get("stopped_early"):
                warnings.append(
                    f"CRITICAL: fetch_all stopped early after {pagination_info['pages_fetched']} pages "
                    f"({result['total_fetched']} devices). The org almost certainly has MORE devices. "
                    f"Reason: {pagination_info.get('stop_reason')}. "
                    "You MUST tell the user the count found is a lower bound, not the exact total."
                )
            if warnings:
                result["warning"] = warnings if len(warnings) > 1 else warnings[0]
            return result
        else:
            logger.info(f"Successfully retrieved {len(device_items)} devices")
            result = create_paginated_response(device_items, response, fetch_all_used=fetch_all)
            if limit_clamped:
                result["warning"] = limit_clamped
            return result

    except Exception as e:
        logger.error(f"Exception while listing devices: {type(e).__name__}: {e}")
        return {"error": f"Exception: {e}"}


@mcp.tool()
@require_scopes("okta.devices.read", error_return_type="list")
@validate_ids("device_id")
async def get_device(device_id: str, ctx: Context = None) -> list:
    """Get a device by ID from the Okta organization.

    This tool retrieves a single managed or registered device by its ID.

    Parameters:
        device_id (str, required): The ID of the device to retrieve.

    Returns:
        List containing the device details.
    """
    logger.info(f"Getting device with ID: {device_id}")

    manager = ctx.request_context.lifespan_context.okta_auth_manager

    try:
        client = await get_okta_client(manager)
        logger.debug(f"Calling Okta API to get device {device_id}")

        device, _, err = await client.get_device(device_id)

        if err:
            logger.error(f"Okta API error while getting device {device_id}: {err}")
            return [f"Error: {err}"]

        logger.info(f"Successfully retrieved device: {device_id}")
        return [device]
    except Exception as e:
        logger.error(f"Exception while getting device {device_id}: {type(e).__name__}: {e}")
        return [f"Exception: {e}"]

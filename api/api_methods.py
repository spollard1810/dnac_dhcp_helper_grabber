from typing import Dict, List, Optional, Any
import requests
from requests.auth import HTTPBasicAuth
import os
from dotenv import load_dotenv
import urllib3
import atexit

# Disable SSL warnings
urllib3.disable_warnings()

class APIClient:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(APIClient, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        # Always reload environment variables
        load_dotenv(override=True)

        # Initialize session and token if not already done
        if not hasattr(self, 'session'):
            self.session = requests.Session()
            self.session.verify = False  # Disable SSL verification
            self.token = None
            # Register cleanup on program exit
            atexit.register(self.close)

        # Skip rest of initialization if already initialized
        if self._initialized:
            # Update credentials from environment
            self._load_credentials()
            return

        # First time initialization
        self._load_credentials()
        self._initialized = True

    def close(self) -> None:
        """Close the session and cleanup resources."""
        if hasattr(self, 'session') and self.session:
            self.session.close()
            self.session = None
            self.token = None
            self._initialized = False

    def __del__(self):
        """Ensure resources are cleaned up when the object is deleted."""
        self.close()

    def _load_credentials(self):
        """Load or reload credentials from environment variables"""
        # Get credentials from environment
        self.host = os.getenv('DNAC_HOST')
        if not self.host:
            raise ValueError('DNAC_HOST must be provided in .env file')

        self.username = os.getenv('DNAC_USERNAME')
        if not self.username:
            raise ValueError('DNAC_USERNAME must be provided in .env file')

        self.password = os.getenv('DNAC_PASSWORD')
        if not self.password:
            raise ValueError('DNAC_PASSWORD must be provided in .env file')

        # Strip any trailing slashes and protocol from host
        self.host = self.host.rstrip('/').replace('https://', '').replace('http://', '')
        self.base_url = f'https://{self.host}'  # Always use HTTPS

        # Re-authenticate with new credentials
        self.authenticate()

    def authenticate(self) -> None:
        """Authenticate with DNA Center and get token"""
        url = f"https://{self.host}/dna/system/api/v1/auth/token"

        print(f"\nDebug - Authentication attempt:")
        print(f"URL: {url}")
        print(f"Username: {self.username}")
        print(f"Using HTTPBasicAuth: {HTTPBasicAuth(self.username, self.password)}")

        try:
            # Create a new session just for auth to avoid any header conflicts
            auth_session = requests.Session()
            auth_session.verify = False

            print("\nMaking authentication request...")
            response = auth_session.post(
                url,
                auth=HTTPBasicAuth(self.username, self.password),
                verify=False
            )

            print(f"Response status code: {response.status_code}")
            print(f"Response headers: {response.headers}")

            if response.status_code != 200:
                print(f"Response content: {response.text}")

            response.raise_for_status()
            self.token = response.json()['Token']
            print(f"Successfully got token: {self.token[:10]}...")

            # Update session headers with new token
            self.session.headers.update({
                'X-Auth-Token': self.token,
                'Content-Type': 'application/json'
            })
        except requests.exceptions.RequestException as e:
            print(f"Authentication failed with error: {str(e)}")
            print(f"Full error details: {e.__dict__}")
            raise Exception(f'Error getting auth token: {e}')

    def _handle_request(self, method: str, url: str, **kwargs) -> Dict:
        """Handle API request with token refresh if needed"""
        try:
            response = self.session.request(method, url, **kwargs)

            # If we get a 401, try to refresh the token and retry once
            if response.status_code == 401:
                self.authenticate()
                response = self.session.request(method, url, **kwargs)

            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise Exception(f'API request failed: {e}')

    def post_dna_intent_api_v1_images_image_id_site_wise_product_names(self, content__type: Any, image_id: Any) -> Dict[str, Any]:
        """Assign network device product name to the given software image

        Assign network device product name and sites for the given image identifier. Refer `/dna/intent/api/v1/images` API for obtaining imageId

        Args:
            content__type (Any): Request body content type
            image_id (Any): Software image identifier. Refer `/dna/intent/api/v1/images` API for obtaining `imageId`

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/images/{image_id}/siteWiseProductNames'
        url = url.format(image_id=image_id)
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_images_image_id_site_wise_product_names(self, image_id: Any, product_name: Optional[Any] = None, product_id: Optional[Any] = None, recommended: Optional[Any] = None, assigned: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None) -> Dict[str, Any]:
        """Retrieves network device product names assigned to a software image.

        Returns a list of network device product names and associated sites for a given image identifier. Refer `/dna/intent/api/v1/images` API for obtaining `imageId`.

        Args:
            image_id (Any): Software image identifier. Refer `/dna/intent/api/v1/images` API for obtaining `imageId`
            product_name (Any): Filter with network device product name. Supports partial case-insensitive search. A minimum of 3 characters is required for the search.
            product_id (Any): Filter with product ID (PID)
            recommended (Any): Filter with recommended source. If `CISCO` then the network device product assigned was recommended by Cisco and `USER` then the user has manually assigned. Available values: CISCO, USER
            assigned (Any): Filter with the assigned/unassigned, `ASSIGNED` option will filter network device products that are associated with the given image. The `NOT_ASSIGNED` option will filter network device products that have not yet been associated with the given image but apply to it. Available values: ASSIGNED, NOT_ASSIGNED
            offset (Any): The first record to show for this page; the first record is numbered 1. The minimum value is 1
            limit (Any): The number of records to show for this page. The minimum and maximum values are 1 and 500, respectively

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/images/{image_id}/siteWiseProductNames'
        url = url.format(image_id=image_id)
        params = {
            'productName': product_name,
            'productId': product_id,
            'recommended': recommended,
            'assigned': assigned,
            'offset': offset,
            'limit': limit,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_template_programmer_template_version_template_id(self, template_id: Any) -> Dict[str, Any]:
        """Gets all the versions of a given template

        Get all the versions of template by its id

        Args:
            template_id (Any): templateId(UUID) to get list of versioned templates

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/template-programmer/template/version/{template_id}'
        url = url.format(template_id=template_id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_wireless_accesspoint_configuration(self, content__type: Optional[Any] = None) -> Dict[str, Any]:
        """Configure Access Points V1

        User can configure multiple access points with required options using this intent API.
This API does not support configuration of CleanAir or SI for IOS-XE devices with version greater than or equal to 17.9

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/wireless/accesspoint-configuration'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def post_dna_intent_api_v2_template_programmer_template_deploy(self, content__type: Any) -> Dict[str, Any]:
        """Deploy Template V2

        V2 API to deploy a template.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v2/template-programmer/template/deploy'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_site_wise_product_names_count(self, site_id: Optional[Any] = None, product_name: Optional[Any] = None) -> Dict[str, Any]:
        """Returns the count of network device product names for a site

        Returns the count of network device product names for given filters. The default value of `siteId` is global.

        Args:
            site_id (Any): Site identifier to get the list of all available products under the site. The default value is global site id. See https://developer.cisco.com/docs/dna-center/get-site/ for siteId
            product_name (Any): Filter with network device product name. Supports partial case-insensitive search. A minimum of 3 characters are required for search

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/siteWiseProductNames/count'
        params = {
            'siteId': site_id,
            'productName': product_name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sda_multicast_virtual_networks(self, fabric_id: Optional[Any] = None, virtual_network_name: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None) -> Dict[str, Any]:
        """Get multicast virtual networks

        Returns a list of multicast configurations for virtual networks that match the provided query parameters.

        Args:
            fabric_id (Any): ID of the fabric site where multicast is configured.
            virtual_network_name (Any): Name of the virtual network associated to the multicast configuration.
            offset (Any): Starting record for pagination.
            limit (Any): Maximum number of records to return.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/multicast/virtualNetworks'
        params = {
            'fabricId': fabric_id,
            'virtualNetworkName': virtual_network_name,
            'offset': offset,
            'limit': limit,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_sda_multicast_virtual_networks(self, content__type: Any) -> Dict[str, Any]:
        """Add multicast virtual networks

        Adds multicast for virtual networks based on user input.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sda/multicast/virtualNetworks'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_sda_multicast_virtual_networks(self, content__type: Any) -> Dict[str, Any]:
        """Update multicast virtual networks

        Updates multicast configurations for virtual networks based on user input.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sda/multicast/virtualNetworks'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def post_dna_data_api_v1_network_devices_id_trend_analytics(self, content__type: Any, id: Any) -> Dict[str, Any]:
        """The Trend analytics data for the network Device in the specified time range

        The Trend analytics data for the network Device in the specified time range. The data is grouped based on the trend time Interval, other input parameters like attribute and aggregate attributes. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-AssuranceNetworkDevices-1.0.2-resolved.yaml

        Args:
            content__type (Any): Request body content type
            id (Any): The device Uuid

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/data/api/v1/networkDevices/{id}/trendAnalytics'
        url = url.format(id=id)
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_devices_device_controllability_settings(self) -> Dict[str, Any]:
        """Get device controllability settings

        Device Controllability is a system-level process on Catalyst Center that enforces state synchronization for some device-layer features. Its purpose is to aid in the deployment of required network settings that Catalyst Center needs to manage devices. Changes are made on network devices during discovery, when adding a device to Inventory, or when assigning a device to a site. If changes are made to any settings that are under the scope of this process, these changes are applied to the network devices during the Provision and Update Telemetry Settings operations, even if Device Controllability is disabled. The following device settings will be enabled as part of Device Controllability when devices are discovered. - SNMP Credentials. - NETCONF Credentials. Subsequent to discovery, devices will be added to Inventory. The following device settings will be enabled when devices are added to inventory. - Cisco TrustSec (CTS) Credentials. The following device settings will be enabled when devices are assigned to a site. Some of these settings can be defined at a site level under Design > Network Settings > Telemetry & Wireless. - Wired Endpoint Data Collection Enablement. - Controller Certificates. - SNMP Trap Server Definitions. - Syslog Server Definitions. - Application Visibility. - Application QoS Policy. - Wireless Service Assurance (WSA). - Wireless Telemetry. - DTLS Ciphersuite. - AP Impersonation. If Device Controllability is disabled, Catalyst Center does not configure any of the preceding credentials or settings on devices during discovery, at runtime, or during site assignment. However, the telemetry settings and related configuration are pushed when the device is provisioned or when the update Telemetry Settings action is performed. Catalyst Center identifies and automatically corrects the following telemetry configuration issues on the device. - SWIM certificate issue. - IOS WLC NA certificate issue. - PKCS12 certificate issue. - IOS telemetry configuration issu

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/networkDevices/deviceControllability/settings'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_network_devices_device_controllability_settings(self, content__type: Any) -> Dict[str, Any]:
        """Update device controllability settings

        Device Controllability is a system-level process on Catalyst Center that enforces state
synchronization for some device-layer features. Its purpose is to aid in the deployment of required
network settings that Catalyst Center needs to manage devices. Changes are made on network devices 
during discovery, when adding a device to Inventory, or when assigning a device to a site. If changes 
are made to any settings that are under the scope of this process, these changes are applied to the 
network devices during the Provision and Update Telemetry Settings operations, even if Device 
Controllability is disabled. The following device settings will be enabled as part of 
Device Controllability when devices are discovered. 

  - SNMP Credentials.
  - NETCONF Credentials.
  
Subsequent to discovery, devices will be added to Inventory. The following device settings will be 
enabled when devices are added to inventory.

  - Cisco TrustSec (CTS) Credentials.
  
The following device settings will be enabled when devices are assigned to a site. Some of these 
settings can be defined at a site level under Design > Network Settings > Telemetry & Wireless.

  - Wired Endpoint Data Collection Enablement.
  - Controller Certificates.
  - SNMP Trap Server Definitions.
  - Syslog Server Definitions.
  - Application Visibility.
  - Application QoS Policy.
  - Wireless Service Assurance (WSA).
  - Wireless Telemetry.
  - DTLS Ciphersuite.
  - AP Impersonation.
  
If Device Controllability is disabled, Catalyst Center does not configure any of the preceding 
credentials or settings on devices during discovery, at runtime, or during site assignment. However, 
the telemetry settings and related configuration are pushed when the device is provisioned or when the 
update Telemetry Settings action is performed. 

Catalyst Center identifies and automatically corrects the following telemetry configuration issues on 
the device.

  - SWIM certificate issue.
  - IOS WLC NA certificate issue.
  - PKCS12 certificate issue.
  - IOS telemetry configuration issue.
  
The autocorrect telemetry config feature is supported only when Device Controllability is enabled.


        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/networkDevices/deviceControllability/settings'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_device_device_id_chassis(self, device_id: Any) -> Dict[str, Any]:
        """Get Chassis Details for Device

        Returns chassis details for given device ID

        Args:
            device_id (Any): Device ID

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device/{device_id}/chassis'
        url = url.format(device_id=device_id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v2_buildings_id(self, content__type: Any, id: Any) -> Dict[str, Any]:
        """Updates a building

        Updates a building in the network hierarchy.

        Args:
            content__type (Any): Request body content type
            id (Any): Building Id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v2/buildings/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v2_buildings_id(self, id: Any) -> Dict[str, Any]:
        """Deletes a building

        Deletes building in the network hierarchy. This operations fails if there are any floors for this building, or if there are any devices assigned to this building.

        Args:
            id (Any): Building ID

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v2/buildings/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v2_buildings_id(self, id: Any) -> Dict[str, Any]:
        """Gets a building

        Gets a building in the network hierarchy.

        Args:
            id (Any): Building Id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v2/buildings/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_network_devices_unassign_from_site_apply(self, content__type: Any) -> Dict[str, Any]:
        """Unassign network devices from sites

        Unassign unprovisioned network devices from their site. If device controllability is enabled, it will be triggered once device unassigned from site successfully. Device Controllability can be enabled/disabled using `/dna/intent/api/v1/networkDevices/deviceControllability/settings`.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/networkDevices/unassignFromSite/apply'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_discovery_count(self) -> Dict[str, Any]:
        """Get count of all discovery jobs

        Returns the count of all available discovery jobs

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/discovery/count'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_data_view_groups_view_group_id(self, view_group_id: Any) -> Dict[str, Any]:
        """Get views for a given view group

        Gives a list of summary of all views in a viewgroup. Use "Get all view groups" API to get the viewGroupIds (required as a query param for this API) for available viewgroups.

        Args:
            view_group_id (Any): viewGroupId of viewgroup.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/data/view-groups/{view_group_id}'
        url = url.format(view_group_id=view_group_id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_onboarding_pnp_device_id(self, content__type: Any, id: Any) -> Dict[str, Any]:
        """Update Device

        Updates device details specified by device id in PnP database

        Args:
            content__type (Any): Request body content type
            id (Any): id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/onboarding/pnp-device/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_onboarding_pnp_device_id(self, id: Any) -> Dict[str, Any]:
        """Get Device by Id

        Returns device details specified by device id

        Args:
            id (Any): id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/onboarding/pnp-device/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_onboarding_pnp_device_id(self, id: Any) -> Dict[str, Any]:
        """Delete Device by Id from PnP

        Deletes specified device from PnP database

        Args:
            id (Any): id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/onboarding/pnp-device/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_sda_fabrics_fabric_id_vlan_to_ssids(self, content__type: Any, fabric_id: Any) -> Dict[str, Any]:
        """Add, Update or Remove SSID mapping to a VLAN

        Add, update, or remove SSID mappings to a VLAN. If the payload doesn't contain a 'vlanName' which has SSIDs mapping done earlier then all the mapped SSIDs of the 'vlanName' is cleared. The request must include all SSIDs currently mapped to a VLAN, as determined by the response from the GET operation for the same fabricId used in the request. If an already-mapped SSID is not included in the payload, its mapping will be removed by this API. Conversely, if a new SSID is provided, it will be added to the Mapping. Ensure that any new SSID added is a Fabric SSID. This API can also be used to add a VLAN and associate the relevant SSIDs with it. The 'vlanName' must be 'Fabric Wireless Enabled' and should be part of the Fabric Site representing 'Fabric ID' specified in the API request.

        Args:
            content__type (Any): Content Type
            fabric_id (Any): The 'fabricId' represents the Fabric ID of a particular Fabric Site

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sda/fabrics/{fabric_id}/vlanToSsids'
        url = url.format(fabric_id=fabric_id)
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sda_fabrics_fabric_id_vlan_to_ssids(self, content__type: Any, fabric_id: Any, limit: Optional[Any] = None, offset: Optional[Any] = None) -> Dict[str, Any]:
        """Retrieve the VLANs and SSIDs mapped to the VLAN within a Fabric Site.

        Retrieve the VLANs and SSIDs mapped to the VLAN, within a Fabric Site. The 'fabricId' represents the Fabric ID of a particular Fabric Site.

        Args:
            content__type (Any): Content Type
            fabric_id (Any): The 'fabricId' represents the Fabric ID of a particular Fabric Site
            limit (Any): The number of records to show for this page.
            offset (Any): The first record to show for this page; the first record is numbered 1.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sda/fabrics/{fabric_id}/vlanToSsids'
        url = url.format(fabric_id=fabric_id)
        params = {
            'limit': limit,
            'offset': offset,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_images_distribution_server_settings(self, content__type: Any) -> Dict[str, Any]:
        """Add image distribution server

        Add remote server for distributing software images. Upto two such distribution servers are supported.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/images/distributionServerSettings'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_images_distribution_server_settings(self) -> Dict[str, Any]:
        """Retrieve image distribution servers

        Retrieve the list of remote image distribution servers. There can be up to two remote servers.Product always acts as local distribution server, and it is not part of this API response.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/images/distributionServerSettings'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_app_policy_queuing_profile_id(self, id: Any) -> Dict[str, Any]:
        """Delete Application Policy Queuing Profile

        Delete existing custom application policy queuing profile by id

        Args:
            id (Any): Id of custom queuing profile to delete

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/app-policy-queuing-profile/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_tags_network_devices_members_associations(self, offset: Optional[Any] = None, limit: Optional[Any] = None) -> Dict[str, Any]:
        """Retrieve tags associated with network devices.

        Fetches the tags associated with network devices. Devices that don't have any tags associated will not be included in the response. A tag is a user-defined or system-defined construct to group resources. When a device is tagged, it is called a member of the tag.

        Args:
            offset (Any): The first record to show for this page; the first record is numbered 1. minimum: 1
            limit (Any): The number of records to show for this page. minimum: 1, maximum: 500

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/tags/networkDevices/membersAssociations'
        params = {
            'offset': offset,
            'limit': limit,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_template_programmer_template_deploy_status_deployment_id(self, deployment_id: Any) -> Dict[str, Any]:
        """Status of template deployment

        API to retrieve the status of template deployment.

        Args:
            deployment_id (Any): UUID of deployment to retrieve template deployment status

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/template-programmer/template/deploy/status/{deployment_id}'
        url = url.format(deployment_id=deployment_id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_onboarding_pnp_device_unclaim(self, content__type: Any) -> Dict[str, Any]:
        """Un-Claim Device

        Un-Claims one of more devices with specified workflow (Deprecated).

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/onboarding/pnp-device/unclaim'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_integration_settings_instances_itsm(self) -> Dict[str, Any]:
        """Create ITSM Integration setting

        Creates ITSM Integration setting

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/integration-settings/instances/itsm'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_system_issue_definitions_id(self, content__type: Any, id: Any, x__c_a_l_l_e_r__i_d: Optional[Any] = None) -> Dict[str, Any]:
        """Issue trigger definition update.

        Update issue trigger threshold, priority for the given id.

Also enable or disable issue trigger for the given id. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-issueAndHealthDefinitions-1.0.0-resolved.yaml

        Args:
            content__type (Any): Request body content type
            id (Any): Issue trigger definition id.
            x__c_a_l_l_e_r__i_d (Any): Caller ID is used to trace the origin of API calls and their associated queries executed on the database. It's an optional header parameter that can be added to an API request.


        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/intent/api/v1/systemIssueDefinitions/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_system_issue_definitions_id(self, id: Any, x__c_a_l_l_e_r__i_d: Optional[Any] = None) -> Dict[str, Any]:
        """Get issue trigger definition for given id.

        Get system issue defintion for the given id. Definition includes all properties from IssueTriggerDefinition schema by default. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-issueAndHealthDefinitions-1.0.0-resolved.yaml

        Args:
            id (Any): Issue trigger definition id.
            x__c_a_l_l_e_r__i_d (Any): Caller ID is used to trace the origin of API calls and their associated queries executed on the database. It's an optional header parameter that can be added to an API request.


        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/intent/api/v1/systemIssueDefinitions/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_data_api_v1_network_devices_trend_analytics(self, content__type: Any) -> Dict[str, Any]:
        """Gets the Trend analytics data.

        Gets the Trend analytics Network device data for the given time range. The data will be grouped based on the given trend time Interval. The required property for this API is `trendInterval`. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-AssuranceNetworkDevices-1.0.2-resolved.yaml

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/data/api/v1/networkDevices/trendAnalytics'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_sites_id_banner_settings(self, content__type: Any, id: Any) -> Dict[str, Any]:
        """Set banner settings for a site

        Set banner settings for a site; `null` values indicate that the setting will be inherited from the parent site; empty objects (`{}`) indicate that the settings is unset.

        Args:
            content__type (Any): Request body content type
            id (Any): Site Id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sites/{id}/bannerSettings'
        url = url.format(id=id)
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sites_id_banner_settings(self, id: Any, inherited: Optional[Any] = None) -> Dict[str, Any]:
        """Retrieve banner settings for a site

        Retrieve banner settings for a site; `null` values indicate that the setting will be inherited from the parent site; empty objects (`{}`) indicate that the setting is unset at a site.

        Args:
            id (Any): Site Id
            inherited (Any): Include settings explicitly set for this site and settings inherited from sites higher in the site hierarchy; when `false`, `null` values indicate that the site inherits that setting from the parent site or a site higher in the site hierarchy.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sites/{id}/bannerSettings'
        url = url.format(id=id)
        params = {
            '_inherited': inherited,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_devices_assigned_to_site(self, site_id: Any, offset: Optional[Any] = None, limit: Optional[Any] = None) -> Dict[str, Any]:
        """Get site assigned network devices

        Get all site assigned network devices. The items in the list are arranged in an order that corresponds with their internal identifiers.

        Args:
            site_id (Any): Site Id. It must be area Id or building Id or floor Id.
            offset (Any): The first record to show for this page; the first record is numbered 1.
            limit (Any): The number of records to show for this page.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/networkDevices/assignedToSite'
        params = {
            'siteId': site_id,
            'offset': offset,
            'limit': limit,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_event_snmp_config(self, content__type: Any) -> Dict[str, Any]:
        """Create SNMP Destination

        Create SNMP Destination

        Args:
            content__type (Any): Content Type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/event/snmp-config'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_event_snmp_config(self, content__type: Any) -> Dict[str, Any]:
        """Update SNMP Destination

        Update SNMP Destination

        Args:
            content__type (Any): Content Type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/event/snmp-config'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sites_id_device_credentials_status(self, id: Any) -> Dict[str, Any]:
        """Get network devices credentials sync status

        Get network devices credentials sync status at a given site.

        Args:
            id (Any): Site Id.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sites/{id}/deviceCredentials/status'
        url = url.format(id=id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_image_importation(self, image_uuid: Optional[Any] = None, name: Optional[Any] = None, family: Optional[Any] = None, application_type: Optional[Any] = None, image_integrity_status: Optional[Any] = None, version: Optional[Any] = None, image_series: Optional[Any] = None, image_name: Optional[Any] = None, is_tagged_golden: Optional[Any] = None, is_c_c_o_recommended: Optional[Any] = None, is_c_c_o_latest: Optional[Any] = None, created_time: Optional[Any] = None, image_size_greater_than: Optional[Any] = None, image_size_lesser_than: Optional[Any] = None, sort_by: Optional[Any] = None, sort_order: Optional[Any] = None, limit: Optional[Any] = None, offset: Optional[Any] = None) -> Dict[str, Any]:
        """Get software image details

        Returns software image list based on a filter criteria. For example: "filterbyName = cat3k%"

        Args:
            image_uuid (Any): imageUuid
            name (Any): name
            family (Any): family
            application_type (Any): applicationType
            image_integrity_status (Any): imageIntegrityStatus - FAILURE, UNKNOWN, VERIFIED
            version (Any): software Image Version
            image_series (Any): image Series
            image_name (Any): image Name
            is_tagged_golden (Any): is Tagged Golden
            is_c_c_o_recommended (Any): is recommended from cisco.com
            is_c_c_o_latest (Any): is latest from cisco.com
            created_time (Any): time in milliseconds (epoch format)
            image_size_greater_than (Any): size in bytes
            image_size_lesser_than (Any): size in bytes
            sort_by (Any): sort results by this field
            sort_order (Any): sort order - 'asc' or 'des'. Default is asc
            limit (Any): limit
            offset (Any): offset

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/image/importation'
        params = {
            'imageUuid': image_uuid,
            'name': name,
            'family': family,
            'applicationType': application_type,
            'imageIntegrityStatus': image_integrity_status,
            'version': version,
            'imageSeries': image_series,
            'imageName': image_name,
            'isTaggedGolden': is_tagged_golden,
            'isCCORecommended': is_c_c_o_recommended,
            'isCCOLatest': is_c_c_o_latest,
            'createdTime': created_time,
            'imageSizeGreaterThan': image_size_greater_than,
            'imageSizeLesserThan': image_size_lesser_than,
            'sortBy': sort_by,
            'sortOrder': sort_order,
            'limit': limit,
            'offset': offset,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_wireless_settings_interfaces_id(self, content__type: Any, id: Any) -> Dict[str, Any]:
        """Update Interface

        This API allows the user to update an interface by ID

        Args:
            content__type (Any): Content Type
            id (Any): Interface ID

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/wirelessSettings/interfaces/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_wireless_settings_interfaces_id(self, id: Any) -> Dict[str, Any]:
        """Delete Interface

        This API allows the user to delete an interface by ID

        Args:
            id (Any): Interface ID

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/wirelessSettings/interfaces/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_wireless_settings_interfaces_id(self, id: Any) -> Dict[str, Any]:
        """Get Interface by ID

        This API allows the user to get an interface by ID

        Args:
            id (Any): Interface ID

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/wirelessSettings/interfaces/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_sda_anycast_gateways(self, content__type: Any) -> Dict[str, Any]:
        """Update anycast gateways

        Updates anycast gateways based on user input.

        Args:
            content__type (Any): Request body content type.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sda/anycastGateways'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sda_anycast_gateways(self, id: Optional[Any] = None, fabric_id: Optional[Any] = None, virtual_network_name: Optional[Any] = None, ip_pool_name: Optional[Any] = None, vlan_name: Optional[Any] = None, vlan_id: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None) -> Dict[str, Any]:
        """Get anycast gateways

        Returns a list of anycast gateways that match the provided query parameters.

        Args:
            id (Any): ID of the anycast gateway.
            fabric_id (Any): ID of the fabric the anycast gateway is assigned to.
            virtual_network_name (Any): Name of the virtual network associated with the anycast gateways.
            ip_pool_name (Any): Name of the IP pool associated with the anycast gateways.
            vlan_name (Any): VLAN name of the anycast gateways.
            vlan_id (Any): VLAN ID of the anycast gateways. The allowed range for vlanId is [2-4093] except for reserved VLANs [1002-1005], 2046, and 4094.
            offset (Any): Starting record for pagination.
            limit (Any): Maximum number of records to return.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/anycastGateways'
        params = {
            'id': id,
            'fabricId': fabric_id,
            'virtualNetworkName': virtual_network_name,
            'ipPoolName': ip_pool_name,
            'vlanName': vlan_name,
            'vlanId': vlan_id,
            'offset': offset,
            'limit': limit,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_sda_anycast_gateways(self, content__type: Any) -> Dict[str, Any]:
        """Add anycast gateways

        Adds anycast gateways based on user input.

        Args:
            content__type (Any): Request body content type.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sda/anycastGateways'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v2_application_policy_application_set(self, attributes: Any, offset: Any, limit: Any, name: Optional[Any] = None) -> Dict[str, Any]:
        """Get Application Set/s

        Get application set/s by offset/limit or by name

        Args:
            attributes (Any): Attributes to retrieve, valid value applicationSet
            offset (Any): The starting point or index from where the paginated results should begin.
            limit (Any): The limit which is the maximum number of items to include in a single page of results, max value 500
            name (Any): Application set name

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v2/application-policy-application-set'
        params = {
            'attributes': attributes,
            'offset': offset,
            'limit': limit,
            'name': name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v2_application_policy_application_set(self, content__type: Any) -> Dict[str, Any]:
        """Create Application Set/s

        Create new custom application set/s

        Args:
            content__type (Any): content-type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v2/application-policy-application-set'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_tag_id_member(self, content__type: Any, id: Any) -> Dict[str, Any]:
        """Add members to the tag

        Adds members to the tag specified by id

        Args:
            content__type (Any): Request body content type
            id (Any): Tag ID

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/tag/{id}/member'
        url = url.format(id=id)
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_tag_id_member(self, id: Any, member_type: Any, offset: Optional[Any] = None, limit: Optional[Any] = None, member_association_type: Optional[Any] = None, level: Optional[Any] = None) -> Dict[str, Any]:
        """Get Tag members by Id

        Returns tag members specified by id

        Args:
            id (Any): Tag ID
            member_type (Any): Entity type of the member. Possible values can be retrieved by using /tag/member/type API
            offset (Any): Used for pagination. It indicates the starting row number out of available member records
            limit (Any): Used to Number of maximum members to return in the result
            member_association_type (Any): Indicates how the member is associated with the tag. Possible values and description. 1) DYNAMIC : The member is associated to the tag through rules. 2) STATIC – The member is associated to the tag manually. 3) MIXED – The member is associated manually and also satisfies the rule defined for the tag
            level (Any): level

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/tag/{id}/member'
        url = url.format(id=id)
        params = {
            'memberType': member_type,
            'offset': offset,
            'limit': limit,
            'memberAssociationType': member_association_type,
            'level': level,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sda_fabric_sites_count(self) -> Dict[str, Any]:
        """Get fabric site count

        Returns the count of fabric sites that match the provided query parameters.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/fabricSites/count'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_diagnostic_validation_sets(self, view: Optional[Any] = None) -> Dict[str, Any]:
        """Retrieves all the validation sets

        Retrieves all the validation sets and optionally the contained validations

        Args:
            view (Any): When the query parameter `view=DETAIL` is passed, all validation sets and associated validations will be returned. When the query parameter `view=DEFAULT` is passed, only validation sets metadata will be returned.


        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/diagnosticValidationSets'
        params = {
            'view': view,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_profiles_for_sites_profile_id_site_assignments(self, profile_id: Any, offset: Optional[Any] = None, limit: Optional[Any] = None) -> Dict[str, Any]:
        """Retrieves the list of sites that the given network profile for sites is assigned to

        Retrieves the list of sites that the given network profile for sites is assigned to.

The list includes the sites the profile has been directly assigned to, as well as child sites that have inherited the profile.


        Args:
            profile_id (Any): The `id` of the network profile, retrievable from `GET /intent/api/v1/networkProfilesForSites`
            offset (Any): The first record to show for this page; the first record is numbered 1.
            limit (Any): The number of records to show for this page.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/networkProfilesForSites/{profile_id}/siteAssignments'
        url = url.format(profile_id=profile_id)
        params = {
            'offset': offset,
            'limit': limit,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_network_profiles_for_sites_profile_id_site_assignments(self, content__type: Any, profile_id: Any) -> Dict[str, Any]:
        """Assign a network profile for sites to the given site

        Assigns a given network profile for sites to a given site. Also assigns the profile to child sites.

        Args:
            content__type (Any): Request body content type
            profile_id (Any): The `id` of the network profile, retrievable from `GET /intent/api/v1/networkProfilesForSites`

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/networkProfilesForSites/{profile_id}/siteAssignments'
        url = url.format(profile_id=profile_id)
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sda_fabric_devices_layer2_handoffs_count(self, fabric_id: Any, network_device_id: Optional[Any] = None) -> Dict[str, Any]:
        """Get fabric devices layer 2 handoffs count

        Returns the count of layer 2 handoffs of fabric devices that match the provided query parameters.

        Args:
            fabric_id (Any): ID of the fabric this device belongs to.
            network_device_id (Any): Network device ID of the fabric device.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/fabricDevices/layer2Handoffs/count'
        params = {
            'fabricId': fabric_id,
            'networkDeviceId': network_device_id,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_wireless_access_points_provision(self, content__type: Any) -> Dict[str, Any]:
        """AP Provision

        This API is used to provision access points

        Args:
            content__type (Any): Content Type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/wirelessAccessPoints/provision'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_event_subscription_count(self, event_ids: Any) -> Dict[str, Any]:
        """Count of Event Subscriptions

        Returns the Count of EventSubscriptions

        Args:
            event_ids (Any): List of subscriptions related to the respective eventIds

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/event/subscription/count'
        params = {
            'eventIds': event_ids,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_sites_site_id_wireless_settings_ssids(self, content__type: Any, site_id: Any) -> Dict[str, Any]:
        """Create SSID

        This API allows the user to create an SSID (Service Set Identifier) at the Global site

        Args:
            content__type (Any): Content Type
            site_id (Any): Site UUID of Global site

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sites/{site_id}/wirelessSettings/ssids'
        url = url.format(site_id=site_id)
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sites_site_id_wireless_settings_ssids(self, site_id: Any, limit: Optional[Any] = None, offset: Optional[Any] = None) -> Dict[str, Any]:
        """Get SSID by Site

        This API allows the user to get all SSIDs (Service Set Identifier) at the given site

        Args:
            site_id (Any): Site UUID
            limit (Any): Limit
            offset (Any): Offset

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sites/{site_id}/wirelessSettings/ssids'
        url = url.format(site_id=site_id)
        params = {
            'limit': limit,
            'offset': offset,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_integration_settings_instances_itsm_instance_id(self, instance_id: Any) -> Dict[str, Any]:
        """Get ITSM Integration setting by Id

        Fetches ITSM Integration setting by ID

        Args:
            instance_id (Any): Instance Id of the Integration setting instance

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/integration-settings/instances/itsm/{instance_id}'
        url = url.format(instance_id=instance_id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_integration_settings_instances_itsm_instance_id(self, instance_id: Any) -> Dict[str, Any]:
        """Update ITSM Integration setting

        Updates the ITSM Integration setting

        Args:
            instance_id (Any): Instance Id of the Integration setting instance

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/integration-settings/instances/itsm/{instance_id}'
        url = url.format(instance_id=instance_id)
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_integration_settings_instances_itsm_instance_id(self, instance_id: Any) -> Dict[str, Any]:
        """Delete ITSM Integration setting

         Deletes the ITSM Integration setting

        Args:
            instance_id (Any): Instance Id of the Integration setting instance

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/integration-settings/instances/itsm/{instance_id}'
        url = url.format(instance_id=instance_id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_data_api_v1_assurance_events_id(self, id: Any, x__c_a_l_l_e_r__i_d: Optional[Any] = None, attribute: Optional[Any] = None, view: Optional[Any] = None) -> Dict[str, Any]:
        """Get details of a single assurance event

        API to fetch the details of an assurance event using event `id`. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-AssuranceEvents-1.0.0-resolved.yaml

        Args:
            id (Any): Unique identifier for the event
            x__c_a_l_l_e_r__i_d (Any): Caller ID is used to trace the origin of API calls and their associated queries executed on the database. It's an optional header parameter that can be added to an API request.

            attribute (Any): The list of attributes that needs to be included in the response. If this parameter is not provided, then basic attributes (`id`, `name`, `timestamp`, `details`, `messageType`, `siteHierarchyId`, `siteHierarchy`, `deviceFamily`, `networkDeviceId`, `networkDeviceName`, `managementIpAddress`) would be part of the response.
 Examples:

`attribute=name` (single attribute requested)

`attribute=name&attribute=networkDeviceName` (multiple attribute requested)

            view (Any): The list of events views. Please refer to `EventViews` for the supported list
 Examples:

`view=network` (single view requested)

`view=network&view=ap` (multiple view requested)


        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/data/api/v1/assuranceEvents/{id}'
        url = url.format(id=id)
        params = {
            'attribute': attribute,
            'view': view,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_image_importation_source_file(self, content__type: Any, is_third_party: Optional[Any] = None, third_party_vendor: Optional[Any] = None, third_party_image_family: Optional[Any] = None, third_party_application_type: Optional[Any] = None) -> Dict[str, Any]:
        """Import local software image

        Fetches a software image from local file system and uploads to DNA Center. Supported software image files extensions are bin, img, tar, smu, pie, aes, iso, ova, tar_gz and qcow2

        Args:
            content__type (Any): Request body content type
            is_third_party (Any): Third party Image check
            third_party_vendor (Any): Third Party Vendor
            third_party_image_family (Any): Third Party image family
            third_party_application_type (Any): Third Party Application Type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/image/importation/source/file'
        params = {
            'isThirdParty': is_third_party,
            'thirdPartyVendor': third_party_vendor,
            'thirdPartyImageFamily': third_party_image_family,
            'thirdPartyApplicationType': third_party_application_type,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_template_programmer_clone_name_name_project_project_id_template_template_id(self, content__type: Any, name: Any, template_id: Any, project_id: Optional[Any] = None) -> Dict[str, Any]:
        """Creates a clone of the given template

        API to clone template

        Args:
            content__type (Any): Request body content type
            name (Any): Template name to clone template(Name should be different than existing template name within same project)
            template_id (Any): UUID of the template to clone it
            project_id (Any): UUID of the project in which the template needs to be created

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/template-programmer/clone/name/{name}/project/{projectId}/template/{template_id}'
        url = url.format(name=name, template_id=template_id)
        params = {
            'projectId': project_id,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_wireless_settings_rf_profiles(self, limit: Optional[Any] = None, offset: Optional[Any] = None) -> Dict[str, Any]:
        """Get RF Profiles

        This API allows the user to get all RF Profiles

        Args:
            limit (Any): Limit
            offset (Any): Offset

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/wirelessSettings/rfProfiles'
        params = {
            'limit': limit,
            'offset': offset,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_wireless_settings_rf_profiles(self, content__type: Any) -> Dict[str, Any]:
        """Create RF Profile

        This API allows the user to create a custom RF Profile

        Args:
            content__type (Any): 

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/wirelessSettings/rfProfiles'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sites_id_telemetry_settings(self, id: Any, inherited: Optional[Any] = None) -> Dict[str, Any]:
        """Retrieve Telemetry settings for a site

        Retrieves telemetry settings for the given site. `null` values indicate that the setting will be inherited from the parent site.

        Args:
            id (Any): Site Id, retrievable from the `id` attribute in `/dna/intent/api/v1/sites`
            inherited (Any): Include settings explicitly set for this site and settings inherited from sites higher in the site hierarchy; when `false`, `null` values indicate that the site inherits that setting from the parent site or a site higher in the site hierarchy.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sites/{id}/telemetrySettings'
        url = url.format(id=id)
        params = {
            '_inherited': inherited,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_sites_id_telemetry_settings(self, content__type: Any, id: Any) -> Dict[str, Any]:
        """Set Telemetry settings for a site

        Sets telemetry settings for the given site; `null` values indicate that the setting will be inherited from the parent site.

        Args:
            content__type (Any): Request body content type
            id (Any): Site Id, retrievable from the `id` attribute in `/dna/intent/api/v1/sites`

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sites/{id}/telemetrySettings'
        url = url.format(id=id)
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_device_user_defined_field(self, id: Optional[Any] = None, name: Optional[Any] = None) -> Dict[str, Any]:
        """Get All User-Defined-Fields

        Gets existing global User Defined Fields. If no input is given, it fetches ALL the Global UDFs. Filter/search is supported by UDF Id(s) or UDF name(s) or both.

        Args:
            id (Any): Comma-seperated id(s) used for search/filtering
            name (Any): Comma-seperated name(s) used for search/filtering

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device/user-defined-field'
        params = {
            'id': id,
            'name': name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_network_device_user_defined_field(self) -> Dict[str, Any]:
        """Create User-Defined-Field

        Creates a new global User Defined Field, which can be assigned to devices

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device/user-defined-field'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_data_api_v1_assurance_events(self, device_family: Any, x__c_a_l_l_e_r__i_d: Optional[Any] = None, start_time: Optional[Any] = None, end_time: Optional[Any] = None, message_type: Optional[Any] = None, severity: Optional[Any] = None, site_id: Optional[Any] = None, site_hierarchy_id: Optional[Any] = None, network_device_name: Optional[Any] = None, network_device_id: Optional[Any] = None, ap_mac: Optional[Any] = None, client_mac: Optional[Any] = None, attribute: Optional[Any] = None, view: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None, sort_by: Optional[Any] = None, order: Optional[Any] = None) -> Dict[str, Any]:
        """Query assurance events

        Returns the list of events discovered by Catalyst Center, determined by the complex filters. Please refer to the 'API Support Documentation' section to understand which fields are supported. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-AssuranceEvents-1.0.0-resolved.yaml

        Args:
            device_family (Any): Device family. Please note that multiple families across network device type and client type is not allowed. For example, choosing `Routers` along with `Wireless Client` or `Unified AP` is not supported.
Examples:

`deviceFamily=Switches and Hubs` (single deviceFamily requested)

`deviceFamily=Switches and Hubs&deviceFamily=Routers` (multiple deviceFamily requested)

            x__c_a_l_l_e_r__i_d (Any): Caller ID is used to trace the origin of API calls and their associated queries executed on the database. It's an optional header parameter that can be added to an API request.

            start_time (Any): Start time from which API queries the data set related to the resource. It must be specified in UNIX epochtime in milliseconds. Value is inclusive.

If `startTime` is not provided, API will default to current time minus 24 hours.

            end_time (Any): End time to which API queries the data set related to the resource. It must be specified in UNIX epochtime in milliseconds. Value is inclusive.

If `endTime` is not provided, API will default to current time.

            message_type (Any): Message type for the event.

Examples:

`messageType=Syslog` (single messageType requested)

`messageType=Trap&messageType=Syslog` (multiple messageType requested)

            severity (Any): Severity of the event between 0 and 6. This is applicable only for events related to network devices (other than AP) and `Wired Client` events.

| Value | Severity    |
| ----- | ----------- |
| 0     | Emergency   |
| 1     | Alert       |
| 2     | Critical    |
| 3     | Error       |
| 4     | Warning     |
| 5     | Notice      |
| 6     | Info        |

Examples:

`severity=0` (single severity requested)

`severity=0&severity=1` (multiple severity requested)

            site_id (Any): The UUID of the site. (Ex. `flooruuid`)

Examples:

`?siteId=id1` (single siteId requested)

`?siteId=id1&siteId=id2&siteId=id3` (multiple siteId requested)

            site_hierarchy_id (Any): The full hierarchy breakdown of the site tree in id form starting from Global site UUID and ending with the specific site UUID. (Ex. `globalUuid/areaUuid/buildingUuid/floorUuid`)

This field supports wildcard asterisk (`*`) character search support. E.g. `*uuid*, *uuid, uuid*`

Examples:

`?siteHierarchyId=globalUuid/areaUuid/buildingUuid/floorUuid `(single siteHierarchyId requested)

`?siteHierarchyId=globalUuid/areaUuid/buildingUuid/floorUuid&siteHierarchyId=globalUuid/areaUuid2/buildingUuid2/floorUuid2` (multiple siteHierarchyId requested)

            network_device_name (Any): Network device name. This parameter is applicable for network device related families.
This field supports wildcard (`*`) character-based search. Ex: `*Branch*` or `Branch*` or `*Branch`
Examples:

`networkDeviceName=Branch-3-Gateway` (single networkDeviceName requested)

`networkDeviceName=Branch-3-Gateway&networkDeviceName=Branch-3-Switch` (multiple networkDeviceName requested)

            network_device_id (Any): The list of Network Device Uuids. (Ex. `6bef213c-19ca-4170-8375-b694e251101c`)

Examples:

`networkDeviceId=6bef213c-19ca-4170-8375-b694e251101c` (single networkDeviceId requested)

`networkDeviceId=6bef213c-19ca-4170-8375-b694e251101c&networkDeviceId=32219612-819e-4b5e-a96b-cf22aca13dd9&networkDeviceId=2541e9a7-b80d-4955-8aa2-79b233318ba0` (multiple networkDeviceId with & separator)

            ap_mac (Any): MAC address of the access point. This parameter is applicable for `Unified AP` and `Wireless Client` events.

This field supports wildcard (`*`) character-based search. Ex: `*50:0F*` or `50:0F*` or `*50:0F`

Examples:

`apMac=50:0F:80:0F:F7:E0` (single apMac requested)

`apMac=50:0F:80:0F:F7:E0&apMac=18:80:90:AB:7E:A0` (multiple apMac requested)

            client_mac (Any): MAC address of the client. This parameter is applicable for `Wired Client` and `Wireless Client` events.

This field supports wildcard (`*`) character-based search. Ex: `*66:2B*` or `66:2B*` or `*66:2B`

Examples:

`clientMac=66:2B:B8:D2:01:56` (single clientMac requested)

`clientMac=66:2B:B8:D2:01:56&clientMac=DC:A6:32:F5:5A:89` (multiple clientMac requested)

            attribute (Any): The list of attributes that needs to be included in the response. If this parameter is not provided, then basic attributes (`id`, `name`, `timestamp`, `details`, `messageType`, `siteHierarchyId`, `siteHierarchy`, `deviceFamily`, `networkDeviceId`, `networkDeviceName`, `managementIpAddress`) would be part of the response.
 Examples:

`attribute=name` (single attribute requested)

`attribute=name&attribute=networkDeviceName` (multiple attribute requested)

            view (Any): The list of events views. Please refer to `EventViews` for the supported list
 Examples:

`view=network` (single view requested)

`view=network&view=ap` (multiple view requested)

            offset (Any): Specifies the starting point within all records returned by the API. It's one based offset. The starting value is 1.
            limit (Any): Maximum number of records to return
            sort_by (Any): A field within the response to sort by.
            order (Any): The sort order of the field ascending or descending.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/data/api/v1/assuranceEvents'
        params = {
            'deviceFamily': device_family,
            'startTime': start_time,
            'endTime': end_time,
            'messageType': message_type,
            'severity': severity,
            'siteId': site_id,
            'siteHierarchyId': site_hierarchy_id,
            'networkDeviceName': network_device_name,
            'networkDeviceId': network_device_id,
            'apMac': ap_mac,
            'clientMac': client_mac,
            'attribute': attribute,
            'view': view,
            'offset': offset,
            'limit': limit,
            'sortBy': sort_by,
            'order': order,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v2_floors_settings(self) -> Dict[str, Any]:
        """Updates floor settings

        Updates UI user preference for floor unit system. Unit sytem change will effect for all floors across all sites.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v2/floors/settings'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v2_floors_settings(self) -> Dict[str, Any]:
        """Get floor settings

        Gets UI user preference for floor unit system.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v2/floors/settings'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_data_api_v1_assurance_issues_count(self, x__c_a_l_l_e_r__i_d: Optional[Any] = None, start_time: Optional[Any] = None, end_time: Optional[Any] = None, is_global: Optional[Any] = None, priority: Optional[Any] = None, severity: Optional[Any] = None, status: Optional[Any] = None, entity_type: Optional[Any] = None, category: Optional[Any] = None, device_type: Optional[Any] = None, name: Optional[Any] = None, issue_id: Optional[Any] = None, entity_id: Optional[Any] = None, updated_by: Optional[Any] = None, site_hierarchy: Optional[Any] = None, site_hierarchy_id: Optional[Any] = None, site_name: Optional[Any] = None, site_id: Optional[Any] = None, fabric_site_id: Optional[Any] = None, fabric_vn_name: Optional[Any] = None, fabric_transit_site_id: Optional[Any] = None, network_device_id: Optional[Any] = None, network_device_ip_address: Optional[Any] = None, mac_address: Optional[Any] = None, ai_driven: Optional[Any] = None, fabric_driven: Optional[Any] = None, fabric_site_driven: Optional[Any] = None, fabric_vn_driven: Optional[Any] = None, fabric_transit_driven: Optional[Any] = None) -> Dict[str, Any]:
        """Get the total number of issues for given set of filters

        Returns the total number issues for given set of filters. If there is no start and/or end time, then end time will be defaulted to current time and start time will be defaulted to 24-hours ago from end time. https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-IssuesList-1.0.0-resolved.yaml

        Args:
            x__c_a_l_l_e_r__i_d (Any): Caller ID can be used to trace the caller for queries executed on database. The caller id is like a optional attribute which can be added to API invocation like ui, python, postman, test-automation etc
            start_time (Any): Start time from which API queries the data set related to the resource. It must be specified in UNIX epochtime in milliseconds. Value is inclusive.

If `startTime` is not provided, API will default to current time.

            end_time (Any): End time to which API queries the data set related to the resource. It must be specified in UNIX epochtime in milliseconds. Value is inclusive.

            is_global (Any): Global issues are those issues which impacts across many devices, sites. They are also displayed on Issue Dashboard in Catalyst Center UI. Non-Global issues are displayed only on Client 360 or Device 360 pages. If this flag is 'true', only global issues are returned. If it if 'false', all issues are returned.

            priority (Any): Priority of the issue. Supports single priority and multiple priorities Examples: priority=P1 (single priority requested) priority=P1&priority=P2&priority=P3 (multiple priorities requested)

            severity (Any): Severity of the issue. Supports single severity and multiple severities.
Examples:
severity=high (single severity requested)
severity=high&severity=medium (multiple severities requested)

            status (Any): Status of the issue. Supports single status and multiple statuses. Examples: status=active (single status requested) status=active&status=resolved (multiple statuses requested)

            entity_type (Any): Entity type of the issue. Supports single entity type and multiple entity types. Examples: entityType=networkDevice (single entity type requested) entityType=network device&entityType=client (multiple entity types requested)

            category (Any): Categories of the issue. Supports single category and multiple categories. Examples: category=availability (single status requested) category=availability&category=onboarding (multiple categories requested)

            device_type (Any): Device Type of the device to which this issue belongs to. Supports single device type and multiple device types.
Examples: deviceType=wireless controller (single device type requested) deviceType=wireless controller&deviceType=core (multiple device types requested)

            name (Any): The name of the issue
Examples:
name=ap_down (single issue name requested)
name=ap_down&name=wlc_monitor (multiple issue names requested)
Issue names can be retrieved using the API - /data/api/v1/assuranceIssueConfigurations

            issue_id (Any): UUID of the issue Examples: issueId=e52aecfe-b142-4287-a587-11a16ba6dd26 (single issue id requested) issueId=e52aecfe-b142-4287-a587-11a16ba6dd26&issueId=864d0421-02c0-43a6-9c52-81cad45f66d8 (multiple issue ids requested)

            entity_id (Any): Id of the entity for which this issue belongs to. For example, it
    could be mac address of AP or UUID of Sensor
  example: 68:ca:e4:79:3f:20 4de02167-901b-43cf-8822-cffd3caa286f
Examples: entityId=68:ca:e4:79:3f:20 (single entity id requested) entityId=68:ca:e4:79:3f:20&entityId=864d0421-02c0-43a6-9c52-81cad45f66d8 (multiple entity ids requested)

            updated_by (Any): The user who last updated this issue. Examples: updatedBy=admin (single updatedBy requested) updatedBy=admin&updatedBy=john (multiple updatedBy requested)

            site_hierarchy (Any): The full hierarchical breakdown of the site tree starting from Global site name and ending with the specific site name. The Root site is named "Global" (Ex. `Global/AreaName/BuildingName/FloorName`)

This field supports wildcard asterisk (*) character search support. E.g. */San*, */San, /San*

Examples:

`?siteHierarchy=Global/AreaName/BuildingName/FloorName` (single siteHierarchy requested)

`?siteHierarchy=Global/AreaName/BuildingName/FloorName&siteHierarchy=Global/AreaName2/BuildingName2/FloorName2` (multiple siteHierarchies requested)

            site_hierarchy_id (Any): The full hierarchy breakdown of the site tree in id form starting from Global site UUID and ending with the specific site UUID. (Ex. `globalUuid/areaUuid/buildingUuid/floorUuid`)

This field supports wildcard asterisk (*) character search support. E.g. `*uuid*, *uuid, uuid*

Examples:

`?siteHierarchyId=globalUuid/areaUuid/buildingUuid/floorUuid `(single siteHierarchyId requested)

`?siteHierarchyId=globalUuid/areaUuid/buildingUuid/floorUuid&siteHierarchyId=globalUuid/areaUuid2/buildingUuid2/floorUuid2` (multiple siteHierarchyIds requested)

            site_name (Any): The name of the site. (Ex. `FloorName`)

This field supports wildcard asterisk (*) character search support. E.g. *San*, *San, San*

Examples:

`?siteName=building1` (single siteName requested)

`?siteName=building1&siteName=building2&siteName=building3` (multiple siteNames requested)

            site_id (Any): The UUID of the site. (Ex. `flooruuid`)

This field supports wildcard asterisk (*) character search support. E.g.*flooruuid*, *flooruuid, flooruuid*

Examples:

`?siteId=id1` (single id requested)

`?siteId=id1&siteId=id2&siteId=id3` (multiple ids requested)

            fabric_site_id (Any): The UUID of the fabric site. (Ex. "flooruuid")
Examples: fabricSiteId=e52aecfe-b142-4287-a587-11a16ba6dd26 (single id requested) fabricSiteId=e52aecfe-b142-4287-a587-11a16ba6dd26,864d0421-02c0-43a6-9c52-81cad45f66d8 (multiple ids requested)

            fabric_vn_name (Any): The name of the fabric virtual network
Examples: fabricVnName=name1 (single fabric virtual network name requested) fabricVnName=name1&fabricVnName=name2&fabricVnName=name3 (multiple fabric virtual network names requested)

            fabric_transit_site_id (Any): The UUID of the fabric transit site. (Ex. "flooruuid")
Examples: fabricTransitSiteId=e52aecfe-b142-4287-a587-11a16ba6dd26 (single id requested) fabricTransitSiteId=e52aecfe-b142-4287-a587-11a16ba6dd26&fabricTransitSiteId=864d0421-02c0-43a6-9c52-81cad45f66d8 (multiple ids requested)

            network_device_id (Any): The list of Network Device Uuids. (Ex. `6bef213c-19ca-4170-8375-b694e251101c`)

Examples:

`networkDeviceId=6bef213c-19ca-4170-8375-b694e251101c` (single networkDeviceId requested)

`networkDeviceId=6bef213c-19ca-4170-8375-b694e251101c&networkDeviceId=32219612-819e-4b5e-a96b-cf22aca13dd9&networkDeviceId=2541e9a7-b80d-4955-8aa2-79b233318ba0` (multiple networkDeviceIds with & separator)

            network_device_ip_address (Any): The list of Network Device management IP Address. (Ex. `121.1.1.10`)

This field supports wildcard (`*`) character-based search. 
Ex: `*1.1*` or `1.1*` or `*1.1`

Examples:

`networkDeviceIpAddress=121.1.1.10`

`networkDeviceIpAddress=121.1.1.10&networkDeviceIpAddress=172.20.1.10&networkDeviceIpAddress=10.10.20.10` (multiple networkDevice IP Address with & separator)

            mac_address (Any): The macAddress of the network device or client
This field supports wildcard (`*`) character-based search. 
Ex: `*AB:AB:AB*` or `AB:AB:AB*` or `*AB:AB:AB`
Examples:

`macAddress=AB:AB:AB:CD:CD:CD` (single macAddress requested)

`macAddress=AB:AB:AB:CD:CD:DC&macAddress=AB:AB:AB:CD:CD:FE` (multiple macAddress requested)

            ai_driven (Any): Flag whether the issue is AI driven issue
            fabric_driven (Any): Flag whether the issue is related to a Fabric site, a virtual network or a transit.
            fabric_site_driven (Any): Flag whether the issue is Fabric site driven issue
            fabric_vn_driven (Any): Flag whether the issue is Fabric Virtual Network driven issue
            fabric_transit_driven (Any): Flag whether the issue is Fabric Transit driven issue

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/data/api/v1/assuranceIssues/count'
        params = {
            'startTime': start_time,
            'endTime': end_time,
            'isGlobal': is_global,
            'priority': priority,
            'severity': severity,
            'status': status,
            'entityType': entity_type,
            'category': category,
            'deviceType': device_type,
            'name': name,
            'issueId': issue_id,
            'entityId': entity_id,
            'updatedBy': updated_by,
            'siteHierarchy': site_hierarchy,
            'siteHierarchyId': site_hierarchy_id,
            'siteName': site_name,
            'siteId': site_id,
            'fabricSiteId': fabric_site_id,
            'fabricVnName': fabric_vn_name,
            'fabricTransitSiteId': fabric_transit_site_id,
            'networkDeviceId': network_device_id,
            'networkDeviceIpAddress': network_device_ip_address,
            'macAddress': mac_address,
            'aiDriven': ai_driven,
            'fabricDriven': fabric_driven,
            'fabricSiteDriven': fabric_site_driven,
            'fabricVnDriven': fabric_vn_driven,
            'fabricTransitDriven': fabric_transit_driven,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_tag(self, content__type: Any) -> Dict[str, Any]:
        """Create Tag

        Creates tag with specified tag attributes

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/tag'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_tag(self, content__type: Any) -> Dict[str, Any]:
        """Update Tag

        Updates a tag specified by id

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/tag'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_tag(self, name: Optional[Any] = None, additional_info_name_space: Optional[Any] = None, additional_info_attributes: Optional[Any] = None, level: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None, size: Optional[Any] = None, field: Optional[Any] = None, sort_by: Optional[Any] = None, order: Optional[Any] = None, system_tag: Optional[Any] = None) -> Dict[str, Any]:
        """Get Tag

        Returns the tags for given filter criteria

        Args:
            name (Any): Tag name is mandatory when filter operation is used.
            additional_info_name_space (Any): nameSpace
            additional_info_attributes (Any): attributeName
            level (Any): levelArg
            offset (Any): offset
            limit (Any): limit
            size (Any): size in kilobytes(KB)
            field (Any): Available field names are :'name,id,parentId,type,additionalInfo.nameSpace,additionalInfo.attributes'
            sort_by (Any): Only supported attribute is name. SortyBy is mandatory when order is used.
            order (Any): Available values are asc and des
            system_tag (Any): systemTag

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/tag'
        params = {
            'name': name,
            'additionalInfo.nameSpace': additional_info_name_space,
            'additionalInfo.attributes': additional_info_attributes,
            'level': level,
            'offset': offset,
            'limit': limit,
            'size': size,
            'field': field,
            'sortBy': sort_by,
            'order': order,
            'systemTag': system_tag,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_lan_automation_id(self, content__type: Any, id: Any) -> Dict[str, Any]:
        """LAN Automation Stop and Update Devices

        Invoke this API to stop LAN Automation and Update Loopback0 IP Address of Devices, discovered in the current session

        Args:
            content__type (Any): Request body content type
            id (Any): LAN Automation id can be obtained from /dna/intent/api/v1/lan-automation/status.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/lan-automation/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_lan_automation_id(self, id: Any) -> Dict[str, Any]:
        """LAN Automation Stop

        Invoke this API to stop LAN Automation for the given site. 

        Args:
            id (Any): LAN Automation id can be obtained from /dna/intent/api/v1/lan-automation/status.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/lan-automation/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_sda_layer2_virtual_networks(self, content__type: Any) -> Dict[str, Any]:
        """Update layer 2 virtual networks

        Updates layer 2 virtual networks based on user input.

        Args:
            content__type (Any): Request body content type.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sda/layer2VirtualNetworks'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sda_layer2_virtual_networks(self, id: Optional[Any] = None, fabric_id: Optional[Any] = None, vlan_name: Optional[Any] = None, vlan_id: Optional[Any] = None, traffic_type: Optional[Any] = None, associated_layer3_virtual_network_name: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None) -> Dict[str, Any]:
        """Get layer 2 virtual networks

        Returns a list of layer 2 virtual networks that match the provided query parameters.

        Args:
            id (Any): ID of the layer 2 virtual network.
            fabric_id (Any): ID of the fabric the layer 2 virtual network is assigned to.
            vlan_name (Any): The vlan name of the layer 2 virtual network.
            vlan_id (Any): The vlan ID of the layer 2 virtual network.
            traffic_type (Any): The traffic type of the layer 2 virtual network.
            associated_layer3_virtual_network_name (Any): Name of the associated layer 3 virtual network.
            offset (Any): Starting record for pagination.
            limit (Any): Maximum number of records to return.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/layer2VirtualNetworks'
        params = {
            'id': id,
            'fabricId': fabric_id,
            'vlanName': vlan_name,
            'vlanId': vlan_id,
            'trafficType': traffic_type,
            'associatedLayer3VirtualNetworkName': associated_layer3_virtual_network_name,
            'offset': offset,
            'limit': limit,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_sda_layer2_virtual_networks(self, fabric_id: Any, vlan_name: Optional[Any] = None, vlan_id: Optional[Any] = None, traffic_type: Optional[Any] = None, associated_layer3_virtual_network_name: Optional[Any] = None) -> Dict[str, Any]:
        """Delete layer 2 virtual networks

        Deletes layer 2 virtual networks based on user input.

        Args:
            fabric_id (Any): ID of the fabric the layer 2 virtual network is assigned to.
            vlan_name (Any): The vlan name of the layer 2 virtual network.
            vlan_id (Any): The vlan ID of the layer 2 virtual network.
            traffic_type (Any): The traffic type of the layer 2 virtual network.
            associated_layer3_virtual_network_name (Any): Name of the associated layer 3 virtual network.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/layer2VirtualNetworks'
        params = {
            'fabricId': fabric_id,
            'vlanName': vlan_name,
            'vlanId': vlan_id,
            'trafficType': traffic_type,
            'associatedLayer3VirtualNetworkName': associated_layer3_virtual_network_name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_sda_layer2_virtual_networks(self, content__type: Any) -> Dict[str, Any]:
        """Add layer 2 virtual networks

        Adds layer 2 virtual networks based on user input.

        Args:
            content__type (Any): Request body content type.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sda/layer2VirtualNetworks'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sda_fabric_zones_count(self) -> Dict[str, Any]:
        """Get fabric zone count

        Returns the count of fabric zones that match the provided query parameters.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/fabricZones/count'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_event_webhook(self, content__type: Any) -> Dict[str, Any]:
        """Update Webhook Destination

        Update Webhook Destination

        Args:
            content__type (Any): Content Type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/event/webhook'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_event_webhook(self, webhook_ids: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None, sort_by: Optional[Any] = None, order: Optional[Any] = None) -> Dict[str, Any]:
        """Get Webhook Destination

        Get Webhook Destination

        Args:
            webhook_ids (Any): List of webhook configurations
            offset (Any): The number of webhook configuration's to offset in the resultset whose default value 0
            limit (Any): The number of webhook configuration's to limit in the resultset whose default value 10
            sort_by (Any): SortBy field name
            order (Any): order(asc/desc)

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/event/webhook'
        params = {
            'webhookIds': webhook_ids,
            'offset': offset,
            'limit': limit,
            'sortBy': sort_by,
            'order': order,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_event_webhook(self, content__type: Any) -> Dict[str, Any]:
        """Create Webhook Destination

        Create Webhook Destination

        Args:
            content__type (Any): Content Type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/event/webhook'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_sites_id_time_zone_settings(self, content__type: Any, id: Any) -> Dict[str, Any]:
        """Set time zone for a site

        Set time zone settings for a site; `null` values indicate that the setting will be inherited from the parent site; empty objects (`{}`) indicate that the settings is unset.

        Args:
            content__type (Any): Request body content type
            id (Any): Site Id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sites/{id}/timeZoneSettings'
        url = url.format(id=id)
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sites_id_time_zone_settings(self, id: Any, inherited: Optional[Any] = None) -> Dict[str, Any]:
        """Retrieve time zone settings for a site

        Retrieve time zone settings for a site; `null` values indicate that the setting will be inherited from the parent site; empty objects (`{}`) indicate that the setting is unset at a site.

        Args:
            id (Any): Site Id
            inherited (Any): Include settings explicitly set for this site and settings inherited from sites higher in the site hierarchy; when `false`, `null` values indicate that the site inherits that setting from the parent site or a site higher in the site hierarchy.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sites/{id}/timeZoneSettings'
        url = url.format(id=id)
        params = {
            '_inherited': inherited,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_network_device_id(self, id: Any, clean_config: Optional[Any] = None) -> Dict[str, Any]:
        """Delete Device by Id

        This API allows any network device that is not currently provisioned to be removed from the inventory. Important: Devices currently provisioned cannot be deleted. To delete a provisioned device, the device must be first deprovisioned.

        Args:
            id (Any): Device ID
            clean_config (Any): Selecting the clean up configuration option will attempt to remove device settings that were configured during the addition of the device to the inventory and site assignment. Please note that this operation is different from deprovisioning. It does not remove configurations that were pushed during device provisioning.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device/{id}'
        url = url.format(id=id)
        params = {
            'cleanConfig': clean_config,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_device_id(self, id: Any) -> Dict[str, Any]:
        """Get Device by ID

        Returns the network device details for the given device ID

        Args:
            id (Any): Device ID

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_app_policy_queuing_profile(self, name: Optional[Any] = None) -> Dict[str, Any]:
        """Get Application Policy Queuing Profile

        Get all or by name, existing application policy queuing profiles

        Args:
            name (Any): queuing profile name

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/app-policy-queuing-profile'
        params = {
            'name': name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_app_policy_queuing_profile(self, content__type: Any) -> Dict[str, Any]:
        """Create Application Policy Queuing Profile

        Create new custom application queuing profile

        Args:
            content__type (Any): content-type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/app-policy-queuing-profile'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_app_policy_queuing_profile(self, content__type: Any) -> Dict[str, Any]:
        """Update Application Policy Queuing Profile

        Update existing custom application queuing profile

        Args:
            content__type (Any): content-type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/app-policy-queuing-profile'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_event_syslog_config(self, content__type: Any) -> Dict[str, Any]:
        """Create Syslog Destination

        Create Syslog Destination

        Args:
            content__type (Any): Content Type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/event/syslog-config'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_event_syslog_config(self, config_id: Optional[Any] = None, name: Optional[Any] = None, protocol: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None, sort_by: Optional[Any] = None, order: Optional[Any] = None) -> Dict[str, Any]:
        """Get Syslog Destination

        Get Syslog Destination

        Args:
            config_id (Any): Config id of syslog server
            name (Any): Name of syslog server
            protocol (Any): Protocol of syslog server
            offset (Any): The number of syslog configuration's to offset in the resultset whose default value 0
            limit (Any): The number of syslog configuration's to limit in the resultset whose default value 10
            sort_by (Any): SortBy field name
            order (Any): order(asc/desc)

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/event/syslog-config'
        params = {
            'configId': config_id,
            'name': name,
            'protocol': protocol,
            'offset': offset,
            'limit': limit,
            'sortBy': sort_by,
            'order': order,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_event_syslog_config(self, content__type: Any) -> Dict[str, Any]:
        """Update Syslog Destination

        Update Syslog Destination

        Args:
            content__type (Any): Content Type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/event/syslog-config'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_wireless_settings_dot11be_profiles(self, limit: Optional[Any] = None, offset: Optional[Any] = None) -> Dict[str, Any]:
        """Get all 802.11be Profiles

        This API allows the user to get all 802.11be Profile(s) configured under Wireless Settings

        Args:
            limit (Any): Limit
            offset (Any): Offset	

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/wirelessSettings/dot11beProfiles'
        params = {
            'limit': limit,
            'offset': offset,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_wireless_settings_dot11be_profiles(self, content__type: Any) -> Dict[str, Any]:
        """Create a 802.11be Profile

        This API allows the user to create a 802.11be Profile.Catalyst Center will push this profile to device's "default-dot11be-profile”.Also please note , 802.11be Profile is supported only on IOS-XE controllers since device version 17.15

        Args:
            content__type (Any): Content Type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/wirelessSettings/dot11beProfiles'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_onboarding_pnp_device_sacct_domain_vacct_name_sync_result(self, domain: Any, name: Any) -> Dict[str, Any]:
        """Get Sync Result for Virtual Account

        Returns the summary of devices synced from the given smart account & virtual account with PnP (Deprecated)

        Args:
            domain (Any): Smart Account Domain
            name (Any): Virtual Account Name

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/onboarding/pnp-device/sacct/{domain}/vacct/{name}/sync-result'
        url = url.format(domain=domain, name=name)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_onboarding_pnp_settings_savacct(self, content__type: Any) -> Dict[str, Any]:
        """Add Virtual Account

        Registers a Smart Account, Virtual Account and the relevant server profile info with the PnP System & database. The devices present in the registered virtual account are synced with the PnP database as well. The response payload returns the new profile

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/onboarding/pnp-settings/savacct'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_onboarding_pnp_settings_savacct(self, content__type: Any) -> Dict[str, Any]:
        """Update PnP Server Profile

        Updates the PnP Server profile in a registered Virtual Account in the PnP database. The response payload returns the updated smart & virtual account info

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/onboarding/pnp-settings/savacct'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_custom_issue_definitions(self, x__c_a_l_l_e_r__i_d: Optional[Any] = None, id: Optional[Any] = None, profile_id: Optional[Any] = None, name: Optional[Any] = None, priority: Optional[Any] = None, is_enabled: Optional[Any] = None, severity: Optional[Any] = None, facility: Optional[Any] = None, mnemonic: Optional[Any] = None, limit: Optional[Any] = None, offset: Optional[Any] = None, sort_by: Optional[Any] = None, order: Optional[Any] = None) -> Dict[str, Any]:
        """Get all the custom issue definitions based on the given filters.

        Retrieve the existing syslog-based custom issue definitions. The supported filters are id, name, profileId,  definition enable status, priority, severity, facility and mnemonic. The issue definition configurations may vary across profiles, hence specifying the profile Id in the query parameter is important and the default profile is global.

  The assurance profile definitions can be obtain via the API endpoint: /api/v1/siteprofile?namespace=assurance. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-AssuranceUserDefinedIssueAPIs-1.0.0-resolved.yaml

        Args:
            x__c_a_l_l_e_r__i_d (Any): Caller ID can be used to trace the caller for queries executed on database. The caller id is like a optional attribute which can be added to API invocation like ui, python, postman, test-automation etc	
            id (Any): The custom issue definition identifier and unique identifier across the profile.Examples: id=6bef213c-19ca-4170-8375-b694e251101c (single entity uuid requested) id=6bef213c-19ca-4170-8375-b694e251101c&id=19ca-4170-8375-b694e251101c-6bef213c (multiple Id request in the query param)

            profile_id (Any): The profile identifier to fetch the profile associated custom issue definitions. The default is global. For the custom profile, it is profile UUID. Example : 3fa85f64-5717-4562-b3fc-2c963f66afa6

            name (Any): The list of UDI issue names
            priority (Any): The Issue priority value, possible values are P1, P2, P3, P4. P1: A critical issue that needs immediate attention and can have a wide impact on network operations. P2: A major issue that can potentially impact multiple devices or clients. P3: A minor issue that has a localized or minimal impact. P4: A warning issue that may not be an immediate problem but addressing it can optimize the network performance
            is_enabled (Any): The enable status of the custom issue definition, either true or false.
            severity (Any): The syslog severity level. 0: Emergency 1: Alert, 2: Critical. 3: Error, 4: Warning, 5: Notice, 6: Info. Examples:severity=1&severity=2 (multi value support with & separator)

            facility (Any): The syslog facility name
            mnemonic (Any): The syslog mnemonic name
            limit (Any): The maximum number of records to return
            offset (Any): Specifies the starting point within all records returned by the API. It's one based offset. The starting value is 1.
            sort_by (Any): A field within the response to sort by.
            order (Any): The sort order of the field ascending or descending.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/intent/api/v1/customIssueDefinitions'
        params = {
            'id': id,
            'profileId': profile_id,
            'name': name,
            'priority': priority,
            'isEnabled': is_enabled,
            'severity': severity,
            'facility': facility,
            'mnemonic': mnemonic,
            'limit': limit,
            'offset': offset,
            'sortBy': sort_by,
            'order': order,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_custom_issue_definitions(self, content__type: Any, x__c_a_l_l_e_r__i_d: Optional[Any] = None) -> Dict[str, Any]:
        """Creates a new user-defined issue definitions.

        Create a new custom issue definition using the provided input request data. The unique identifier for this issue definition is id. Please note that the issue names cannot be duplicated. The definition is based on the syslog. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-AssuranceUserDefinedIssueAPIs-1.0.0-resolved.yaml

        Args:
            content__type (Any): Request body content type
            x__c_a_l_l_e_r__i_d (Any): Caller ID is used to trace the origin of API calls and their associated queries executed on the database. It's an optional header parameter that can be added to an API request.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/intent/api/v1/customIssueDefinitions'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_template_programmer_template_deploy(self, content__type: Any) -> Dict[str, Any]:
        """Deploy Template

        API to deploy a template.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/template-programmer/template/deploy'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_authentication_policy_servers_id(self, id: Any) -> Dict[str, Any]:
        """Delete Authentication and Policy Server Access Configuration

        API to delete AAA/ISE server access configuration.

        Args:
            id (Any): Authentication and Policy Server Identifier. Use 'Get Authentication and Policy Servers' intent API to find the identifier.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/authentication-policy-servers/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_authentication_policy_servers_id(self, id: Any) -> Dict[str, Any]:
        """Edit Authentication and Policy Server Access Configuration

        API to edit AAA/ISE server access configuration. After edit, use ‘Cisco ISE Server Integration Status’ Intent API to check the integration status.

        Args:
            id (Any): Authentication and Policy Server Identifier. Use 'Get Authentication and Policy Servers' intent API to find the identifier.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/authentication-policy-servers/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_sda_multicast_virtual_networks_id(self, id: Any) -> Dict[str, Any]:
        """Delete multicast virtual network by id

        Deletes a multicast configuration for a virtual network based on id.

        Args:
            id (Any): ID of the multicast configuration.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/multicast/virtualNetworks/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_app_policy_default(self) -> Dict[str, Any]:
        """Get Application Policy Default

        Get default application policy

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/app-policy-default'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_wireless_controllers_network_device_id_primary_managed_ap_locations(self, network_device_id: Any, limit: Optional[Any] = None, offset: Optional[Any] = None) -> Dict[str, Any]:
        """Get Primary Managed AP Locations for specific Wireless Controller

        Retrieves all the details of Primary Managed AP locations associated with the specific Wireless Controller.

        Args:
            network_device_id (Any): Obtain the network device ID value by using the API call GET: /dna/intent/api/v1/network-device/ip-address/${ipAddress}.
            limit (Any): The number of records to show for this page.
            offset (Any): The first record to show for this page; the first record is numbered 1.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/wirelessControllers/{network_device_id}/primaryManagedApLocations'
        url = url.format(network_device_id=network_device_id)
        params = {
            'limit': limit,
            'offset': offset,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_device_module_id(self, id: Any) -> Dict[str, Any]:
        """Get Module Info by Id

        Returns Module info by 'module id'

        Args:
            id (Any): Module id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device/module/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_health_score_definitions_bulk_update(self, content__type: Any, x__c_a_l_l_e_r__i_d: Optional[Any] = None) -> Dict[str, Any]:
        """Update health score definitions.

        Update health thresholds, include status of overall health status for each metric.

And also to synchronize with global profile issue thresholds of the definition for given metric. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-issueAndHealthDefinitions-1.0.0-resolved.yaml


        Args:
            content__type (Any): Request body content type
            x__c_a_l_l_e_r__i_d (Any): Caller ID is used to trace the origin of API calls and their associated queries executed on the database. It's an optional header parameter that can be added to an API request.


        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/intent/api/v1/healthScoreDefinitions/bulkUpdate'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sda_fabric_devices_layer3_handoffs_sda_transits(self, fabric_id: Any, network_device_id: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None) -> Dict[str, Any]:
        """Get fabric devices layer 3 handoffs with sda transit

        Returns a list of layer 3 handoffs with sda transit of fabric devices that match the provided query parameters.

        Args:
            fabric_id (Any): ID of the fabric this device belongs to.
            network_device_id (Any): Network device ID of the fabric device.
            offset (Any): Starting record for pagination.
            limit (Any): Maximum number of records to return.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/fabricDevices/layer3Handoffs/sdaTransits'
        params = {
            'fabricId': fabric_id,
            'networkDeviceId': network_device_id,
            'offset': offset,
            'limit': limit,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_sda_fabric_devices_layer3_handoffs_sda_transits(self, content__type: Any) -> Dict[str, Any]:
        """Add fabric devices layer 3 handoffs with sda transit

        Adds layer 3 handoffs with sda transit in fabric devices based on user input.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sda/fabricDevices/layer3Handoffs/sdaTransits'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_sda_fabric_devices_layer3_handoffs_sda_transits(self, fabric_id: Any, network_device_id: Any) -> Dict[str, Any]:
        """Delete fabric device layer 3 handoffs with sda transit

        Deletes layer 3 handoffs with sda transit of a fabric device based on user input.

        Args:
            fabric_id (Any): ID of the fabric this device belongs to.
            network_device_id (Any): Network device ID of the fabric device.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/fabricDevices/layer3Handoffs/sdaTransits'
        params = {
            'fabricId': fabric_id,
            'networkDeviceId': network_device_id,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_sda_fabric_devices_layer3_handoffs_sda_transits(self, content__type: Any) -> Dict[str, Any]:
        """Update fabric devices layer 3 handoffs with sda transit

        Updates layer 3 handoffs with sda transit of fabric devices based on user input.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sda/fabricDevices/layer3Handoffs/sdaTransits'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_sda_fabric_devices_layer3_handoffs_ip_transits(self, content__type: Any) -> Dict[str, Any]:
        """Add fabric devices layer 3 handoffs with ip transit

        Adds layer 3 handoffs with ip transit in fabric devices based on user input.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sda/fabricDevices/layer3Handoffs/ipTransits'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_sda_fabric_devices_layer3_handoffs_ip_transits(self, fabric_id: Any, network_device_id: Any) -> Dict[str, Any]:
        """Delete fabric device layer 3 handoffs with ip transit

        Deletes layer 3 handoffs with ip transit of a fabric device based on user input.

        Args:
            fabric_id (Any): ID of the fabric this device belongs to.
            network_device_id (Any): Network device ID of the fabric device.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/fabricDevices/layer3Handoffs/ipTransits'
        params = {
            'fabricId': fabric_id,
            'networkDeviceId': network_device_id,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sda_fabric_devices_layer3_handoffs_ip_transits(self, fabric_id: Any, network_device_id: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None) -> Dict[str, Any]:
        """Get fabric devices layer 3 handoffs with ip transit

        Returns a list of layer 3 handoffs with ip transit of fabric devices that match the provided query parameters.

        Args:
            fabric_id (Any): ID of the fabric this device belongs to.
            network_device_id (Any): Network device ID of the fabric device.
            offset (Any): Starting record for pagination.
            limit (Any): Maximum number of records to return.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/fabricDevices/layer3Handoffs/ipTransits'
        params = {
            'fabricId': fabric_id,
            'networkDeviceId': network_device_id,
            'offset': offset,
            'limit': limit,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_sda_fabric_devices_layer3_handoffs_ip_transits(self, content__type: Any) -> Dict[str, Any]:
        """Update fabric devices layer 3 handoffs with ip transit

        Updates layer 3 handoffs with ip transit of fabric devices based on user input.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sda/fabricDevices/layer3Handoffs/ipTransits'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_site_wise_product_names(self, site_id: Optional[Any] = None, product_name: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None) -> Dict[str, Any]:
        """Returns network device product names for a site

        Provides network device product names for a site. The default value of `siteId` is global. The response will include the network device count and image summary.

        Args:
            site_id (Any): Site identifier to get the list of all available products under the site. The default value is the global site.  See https://developer.cisco.com/docs/dna-center/get-site for siteId
            product_name (Any): Filter with network device product name. Supports partial case-insensitive search. A minimum of 3 characters are required for search
            offset (Any): The first record to show for this page; the first record is numbered 1. The minimum value is 1
            limit (Any): The number of records to show for this page. The minimum and maximum values are 1 and 500, respectively

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/siteWiseProductNames'
        params = {
            'siteId': site_id,
            'productName': product_name,
            'offset': offset,
            'limit': limit,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_event_event_series_count(self, event_ids: Optional[Any] = None, start_time: Optional[Any] = None, end_time: Optional[Any] = None, category: Optional[Any] = None, type: Optional[Any] = None, severity: Optional[Any] = None, domain: Optional[Any] = None, sub_domain: Optional[Any] = None, source: Optional[Any] = None) -> Dict[str, Any]:
        """Count of Notifications

        Get the Count of Published Notifications

        Args:
            event_ids (Any): The registered EventId should be provided
            start_time (Any): Start Time in milliseconds
            end_time (Any): End Time in milliseconds
            category (Any): Category
            type (Any): Type
            severity (Any): Severity
            domain (Any): Domain
            sub_domain (Any): Sub Domain
            source (Any): Source

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/event/event-series/count'
        params = {
            'eventIds': event_ids,
            'startTime': start_time,
            'endTime': end_time,
            'category': category,
            'type': type,
            'severity': severity,
            'domain': domain,
            'subDomain': sub_domain,
            'source': source,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_images_image_id_site_wise_product_names_product_name_ordinal(self, content__type: Any, image_id: Any, product_name_ordinal: Any) -> Dict[str, Any]:
        """Update the list of sites for the network device product name assigned to the software image

        Update the list of sites for the network device product name assigned to the software image. Refer to `/dna/intent/api/v1/images` and `/dna/intent/api/v1/images/{imageId}/siteWiseProductNames` GET APIs for obtaining  `imageId` and `productNameOrdinal` respectively.

        Args:
            content__type (Any): Request body content type
            image_id (Any): Software image identifier. Refer `/dna/intent/api/v1/images` API for obtaining `imageId`
            product_name_ordinal (Any): Product name ordinal is unique value for each network device product. Refer `/dna/intent/api/v1/images/{imageId}/siteWiseProductNames` GET API for obtaining `productNameOrdinal`.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/images/{image_id}/siteWiseProductNames/{product_name_ordinal}'
        url = url.format(image_id=image_id, product_name_ordinal=product_name_ordinal)
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_images_image_id_site_wise_product_names_product_name_ordinal(self, image_id: Any, product_name_ordinal: Any) -> Dict[str, Any]:
        """Unassign network device product name from the given software image

        This API unassigns the network device product name from all the sites for the given software image.
        Refer to `/dna/intent/api/v1/images` and `/dna/intent/api/v1/images/{imageId}/siteWiseProductNames` GET APIs for obtaining  `imageId` and `productNameOrdinal` respectively.

        Args:
            image_id (Any): Software image identifier. Refer `/dna/intent/api/v1/images` API for obtaining `imageId`
            product_name_ordinal (Any): The product name ordinal is a unique value for each network device product. Refer `/dna/intent/api/v1/images/{imageId}/siteWiseProductNames` GET API for obtaining `productNameOrdinal`

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/images/{image_id}/siteWiseProductNames/{product_name_ordinal}'
        url = url.format(image_id=image_id, product_name_ordinal=product_name_ordinal)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def post_dna_intent_api_v2_credential_to_site_site_id(self, site_id: Any) -> Dict[str, Any]:
        """Assign Device Credential To Site V2

        API to assign Device Credential to a site.

        Args:
            site_id (Any): Site Id to assign credential.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v2/credential-to-site/{site_id}'
        url = url.format(site_id=site_id)
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_data_reports_report_id(self, report_id: Any) -> Dict[str, Any]:
        """Delete a scheduled report

        Delete a scheduled report configuration. Deletes the report executions also.

        Args:
            report_id (Any): reportId of report

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/data/reports/{report_id}'
        url = url.format(report_id=report_id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_data_reports_report_id(self, report_id: Any) -> Dict[str, Any]:
        """Get a scheduled report

        Get scheduled report configuration by reportId

        Args:
            report_id (Any): reportId of report

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/data/reports/{report_id}'
        url = url.format(report_id=report_id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_site_health(self, site_type: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None, timestamp: Optional[Any] = None) -> Dict[str, Any]:
        """Get Site Health

        Returns Overall Health information for all sites

        Args:
            site_type (Any): site type: AREA or BUILDING (case insensitive)
            offset (Any): Offset of the first returned data set entry (Multiple of 'limit' + 1)
            limit (Any): Max number of data entries in the returned data set [1,50].  Default is 25
            timestamp (Any): Epoch time(in milliseconds) when the Site Hierarchy data is required

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/site-health'
        params = {
            'siteType': site_type,
            'offset': offset,
            'limit': limit,
            'timestamp': timestamp,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_device_device_uuid_interface_poe_detail(self, device_uuid: Any, interface_name_list: Optional[Any] = None) -> Dict[str, Any]:
        """Returns POE interface details for the device.

        Returns POE interface details for the device, where deviceuuid is mandatory & accepts comma seperated interface names which is optional and returns information for that particular interfaces where(operStatus = operationalStatus)

        Args:
            device_uuid (Any): uuid of the device
            interface_name_list (Any): comma seperated interface names

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device/{device_uuid}/interface/poe-detail'
        url = url.format(device_uuid=device_uuid)
        params = {
            'interfaceNameList': interface_name_list,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sites_count(self, name: Optional[Any] = None) -> Dict[str, Any]:
        """Get sites count

        Get sites count.

        Args:
            name (Any): Site name.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sites/count'
        params = {
            'name': name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_diagnostic_validation_workflows(self, start_time: Optional[Any] = None, end_time: Optional[Any] = None, run_status: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None) -> Dict[str, Any]:
        """Retrieves the list of validation workflows

        Retrieves the workflows that have been successfully submitted and are currently available. This is sorted by `submitTime`

        Args:
            start_time (Any): Workflows started after the given time (as milliseconds since UNIX epoch).
            end_time (Any):  Workflows started before the given time (as milliseconds since UNIX epoch).
            run_status (Any): Execution status of the workflow. If the workflow is successfully submitted, runStatus is `PENDING`. If the workflow execution has started, runStatus is `IN_PROGRESS`. If the workflow executed is completed with all validations executed, runStatus is `COMPLETED`. If the workflow execution fails while running validations, runStatus is `FAILED`.
            offset (Any): The first record to show for this page; the first record is numbered 1.
            limit (Any): The number of records to show for this page.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/diagnosticValidationWorkflows'
        params = {
            'startTime': start_time,
            'endTime': end_time,
            'runStatus': run_status,
            'offset': offset,
            'limit': limit,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_diagnostic_validation_workflows(self, content__type: Any) -> Dict[str, Any]:
        """Submits the workflow for executing validations

        Submits the workflow for executing the validations for the given validation specifications


        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/diagnosticValidationWorkflows'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_interface_interface_uuid_operation(self, interface_uuid: Any, content__type: Optional[Any] = None, deployment_mode: Optional[Any] = None) -> Dict[str, Any]:
        """Clear Mac-Address table

        Clear mac-address on an individual port. In request body, operation needs to be specified as 'ClearMacAddress'. In the future more possible operations will be added to this API

        Args:
            interface_uuid (Any): Interface Id
            content__type (Any): Request body content type
            deployment_mode (Any): Preview/Deploy ['Preview' means the configuration is not pushed to the device. 'Deploy' makes the configuration pushed to the device]

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/interface/{interface_uuid}/operation'
        url = url.format(interface_uuid=interface_uuid)
        params = {
            'deploymentMode': deployment_mode,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def post_data_api_v1_network_devices_query_count(self, content__type: Any) -> Dict[str, Any]:
        """Gets the total number Network Devices based on the provided complex filters and aggregation functions.

        Gets the total number Network Devices based on the provided complex filters and aggregation functions. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-AssuranceNetworkDevices-1.0.2-resolved.yaml


        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/data/api/v1/networkDevices/query/count'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_lan_automation_update_device(self, content__type: Any, feature: Any) -> Dict[str, Any]:
        """LAN Automation Device Update

         Invoke this API to perform a DAY-N update on LAN Automation-related devices. Supported features include Loopback0 IP update, hostname update, link addition, and link deletion. 

        Args:
            content__type (Any): Request body content type
            feature (Any): Feature ID for the update. Supported feature IDs include: LOOPBACK0_IPADDRESS_UPDATE, HOSTNAME_UPDATE, LINK_ADD, and LINK_DELETE. 

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/lan-automation/updateDevice'
        params = {
            'feature': feature,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_global_credential_snmpv2_write_community(self, content__type: Any) -> Dict[str, Any]:
        """Update SNMP write community

        Updates global SNMP write community

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/global-credential/snmpv2-write-community'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_global_credential_snmpv2_write_community(self, content__type: Any) -> Dict[str, Any]:
        """Create SNMP write community

        Adds global SNMP write community

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/global-credential/snmpv2-write-community'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def post_dna_data_api_v1_site_health_summaries_summary_analytics(self, content__type: Any, x__c_a_l_l_e_r__i_d: Optional[Any] = None, site_hierarchy: Optional[Any] = None, site_hierarchy_id: Optional[Any] = None, site_type: Optional[Any] = None, id: Optional[Any] = None) -> Dict[str, Any]:
        """Query an aggregated summary of site health data.

        Query an aggregated summary of all site health
This API provides the latest health data from a given `endTime`
If data is not ready for the provided endTime, the request will fail, and the error message will indicate the recommended endTime to use to retrieve a complete data set.
This behavior may occur if the provided endTime=currentTime, since we are not a real time system.
When `endTime` is not provided, the API returns the latest data.
This API also provides issue data. The `startTime` query param can be used to specify the beginning point of time range to retrieve the active issue counts in. When this param is not provided, the default `startTime` will be 24 hours before endTime.

 Aggregated response data will NOT have unique identifier data populated.

 List of unique identifier data: [`id`, `siteHierarchy`,
`siteHierarchyId`, `siteType`, `latitude`, `longitude`]
Please refer to the 'API Support Documentation' section to understand which fields are supported. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-siteHealthSummaries-1.0.3-resolved.yaml


        Args:
            content__type (Any): Request body content type
            x__c_a_l_l_e_r__i_d (Any): Caller ID is used to trace the origin of API calls and their associated queries executed on the database. It's an optional header parameter that can be added to an API request.

            site_hierarchy (Any): The full hierarchical breakdown of the site tree starting from Global site name and ending with the specific site name. The Root site is named "Global" (Ex. `Global/AreaName/BuildingName/FloorName`)

This field supports wildcard asterisk (`*`) character search support. E.g. `*/San*, */San, /San*`

Examples:

`?siteHierarchy=Global/AreaName/BuildingName/FloorName` (single siteHierarchy requested)

`?siteHierarchy=Global/AreaName/BuildingName/FloorName&siteHierarchy=Global/AreaName2/BuildingName2/FloorName2` (multiple siteHierarchies requested)

            site_hierarchy_id (Any): The full hierarchy breakdown of the site tree in id form starting from Global site UUID and ending with the specific site UUID. (Ex. `globalUuid/areaUuid/buildingUuid/floorUuid`)

This field supports wildcard asterisk (`*`) character search support. E.g. `*uuid*, *uuid, uuid*`

Examples:

`?siteHierarchyId=globalUuid/areaUuid/buildingUuid/floorUuid `(single siteHierarchyId requested)

`?siteHierarchyId=globalUuid/areaUuid/buildingUuid/floorUuid&siteHierarchyId=globalUuid/areaUuid2/buildingUuid2/floorUuid2` (multiple siteHierarchyIds requested)

            site_type (Any): The type of the site. A site can be an area, building, or floor.

Default when not provided will be `[floor,building,area]`

Examples:

`?siteType=area` (single siteType requested)

`?siteType=area&siteType=building&siteType=floor` (multiple siteTypes requested)

            id (Any): The list of entity Uuids. (Ex."6bef213c-19ca-4170-8375-b694e251101c")
Examples: id=6bef213c-19ca-4170-8375-b694e251101c (single entity uuid requested)
id=6bef213c-19ca-4170-8375-b694e251101c&id=32219612-819e-4b5e-a96b-cf22aca13dd9&id=2541e9a7-b80d-4955-8aa2-79b233318ba0 (multiple entity uuid with '&' separator)


        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/data/api/v1/siteHealthSummaries/summaryAnalytics'
        params = {
            'siteHierarchy': site_hierarchy,
            'siteHierarchyId': site_hierarchy_id,
            'siteType': site_type,
            'id': id,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_data_api_v1_site_health_summaries_summary_analytics(self, x__c_a_l_l_e_r__i_d: Optional[Any] = None, start_time: Optional[Any] = None, end_time: Optional[Any] = None, site_hierarchy: Optional[Any] = None, site_hierarchy_id: Optional[Any] = None, site_type: Optional[Any] = None, id: Optional[Any] = None, view: Optional[Any] = None, attribute: Optional[Any] = None) -> Dict[str, Any]:
        """Read an aggregated summary of site health data.

        Get an aggregated summary of all site health or use the query params to get an aggregated summary of health for a subset of sites.
This API provides the latest health data from a given `endTime`
If data is not ready for the provided endTime, the request will fail, and the error message will indicate the recommended endTime to use to retrieve a complete data set.
This behavior may occur if the provided endTime=currentTime, since we are not a real time system.
When `endTime` is not provided, the API returns the latest data.
This API also provides issue data. The `startTime` query param can be used to specify the beginning point of time range to retrieve the active issue counts in. When this param is not provided, the default `startTime` will be 24 hours before endTime.
Aggregated response data will NOT have unique identifier data populated.
List of unique identifier data: [`id`, `siteHierarchy`, `siteHierarchyId`, `siteType`, `latitude`, `longitude`]. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-siteHealthSummaries-1.0.3-resolved.yaml


        Args:
            x__c_a_l_l_e_r__i_d (Any): Caller ID is used to trace the origin of API calls and their associated queries executed on the database. It's an optional header parameter that can be added to an API request.

            start_time (Any): Start time from which API queries the data set related to the resource. It must be specified in UNIX epochtime in milliseconds. Value is inclusive.

If `startTime` is not provided, API will default to current time.

            end_time (Any): End time to which API queries the data set related to the resource. It must be specified in UNIX epochtime in milliseconds. Value is inclusive.

            site_hierarchy (Any): The full hierarchical breakdown of the site tree starting from Global site name and ending with the specific site name. The Root site is named "Global" (Ex. `Global/AreaName/BuildingName/FloorName`)

This field supports wildcard asterisk (`*`) character search support. E.g. `*/San*, */San, /San*`

Examples:

`?siteHierarchy=Global/AreaName/BuildingName/FloorName` (single siteHierarchy requested)

`?siteHierarchy=Global/AreaName/BuildingName/FloorName&siteHierarchy=Global/AreaName2/BuildingName2/FloorName2` (multiple siteHierarchies requested)

            site_hierarchy_id (Any): The full hierarchy breakdown of the site tree in id form starting from Global site UUID and ending with the specific site UUID. (Ex. `globalUuid/areaUuid/buildingUuid/floorUuid`)

This field supports wildcard asterisk (`*`) character search support. E.g. `*uuid*, *uuid, uuid*`

Examples:

`?siteHierarchyId=globalUuid/areaUuid/buildingUuid/floorUuid `(single siteHierarchyId requested)

`?siteHierarchyId=globalUuid/areaUuid/buildingUuid/floorUuid&siteHierarchyId=globalUuid/areaUuid2/buildingUuid2/floorUuid2` (multiple siteHierarchyIds requested)

            site_type (Any): The type of the site. A site can be an area, building, or floor.

Default when not provided will be `[floor,building,area]`

Examples:

`?siteType=area` (single siteType requested)

`?siteType=area&siteType=building&siteType=floor` (multiple siteTypes requested)

            id (Any): The list of entity Uuids. (Ex."6bef213c-19ca-4170-8375-b694e251101c")
Examples: id=6bef213c-19ca-4170-8375-b694e251101c (single entity uuid requested)
id=6bef213c-19ca-4170-8375-b694e251101c&id=32219612-819e-4b5e-a96b-cf22aca13dd9&id=2541e9a7-b80d-4955-8aa2-79b233318ba0 (multiple entity uuid with '&' separator)

            view (Any): The specific summary view being requested. This is an optional parameter which can be passed to get one or more of the specific health data summaries associated with sites.

### Response data proviced by each view:  

1. **site**
[id, siteHierarchy, siteHierarchyId, siteType, latitude, longitude]  

2. **network**
[id, networkDeviceCount, networkDeviceGoodHealthCount,wirelessDeviceCount, wirelessDeviceGoodHealthCount, accessDeviceCount, accessDeviceGoodHealthCount, coreDeviceCount, coreDeviceGoodHealthCount, distributionDeviceCount, distributionDeviceGoodHealthCount, routerDeviceCount, routerDeviceGoodHealthCount, apDeviceCount, apDeviceGoodHealthCount, wlcDeviceCount, wlcDeviceGoodHealthCount, switchDeviceCount, switchDeviceGoodHealthCount, networkDeviceGoodHealthPercentage, accessDeviceGoodHealthPercentage, coreDeviceGoodHealthPercentage, distributionDeviceGoodHealthPercentage, routerDeviceGoodHealthPercentage, apDeviceGoodHealthPercentage, wlcDeviceGoodHealthPercentage, switchDeviceGoodHealthPercentage, wirelessDeviceGoodHealthPercentage]  

3. **client**
[id, clientCount, clientGoodHealthCount, wiredClientCount, wirelessClientCount, wiredClientGoodHealthCount, wirelessClientGoodHealthCount, clientGoodHealthPercentage, wiredClientGoodHealthPercentage, wirelessClientGoodHealthPercentage, clientDataUsage]  

4. **issue**
[id, p1IssueCount, p2IssueCount, p3IssueCount, p4IssueCount, issueCount]  

When this query parameter is not added the default summaries are:  

**[site,client,network,issue]**

Examples:

view=client (single view requested)

view=client&view=network&view=issue (multiple views requested)

            attribute (Any): Supported Attributes:

[id, siteHierarchy, siteHierarchyId, siteType, latitude, longitude, networkDeviceCount, networkDeviceGoodHealthCount,wirelessDeviceCount, wirelessDeviceGoodHealthCount, accessDeviceCount, accessDeviceGoodHealthCount, coreDeviceCount, coreDeviceGoodHealthCount, distributionDeviceCount, distributionDeviceGoodHealthCount, routerDeviceCount, routerDeviceGoodHealthCount, apDeviceCount, apDeviceGoodHealthCount, wlcDeviceCount, wlcDeviceGoodHealthCount, switchDeviceCount, switchDeviceGoodHealthCount, networkDeviceGoodHealthPercentage, accessDeviceGoodHealthPercentage, coreDeviceGoodHealthPercentage, distributionDeviceGoodHealthPercentage, routerDeviceGoodHealthPercentage, apDeviceGoodHealthPercentage, wlcDeviceGoodHealthPercentage, switchDeviceGoodHealthPercentage, wirelessDeviceGoodHealthPercentage, clientCount, clientGoodHealthCount, wiredClientCount, wirelessClientCount, wiredClientGoodHealthCount, wirelessClientGoodHealthCount, clientGoodHealthPercentage, wiredClientGoodHealthPercentage, wirelessClientGoodHealthPercentage, clientDataUsage, p1IssueCount, p2IssueCount, p3IssueCount, p4IssueCount, issueCount]

If length of attribute list is too long, please use 'view' param instead.

Examples:

attribute=siteHierarchy (single attribute requested)

attribute=siteHierarchy&attribute=clientCount (multiple attributes requested)


        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/data/api/v1/siteHealthSummaries/summaryAnalytics'
        params = {
            'startTime': start_time,
            'endTime': end_time,
            'siteHierarchy': site_hierarchy,
            'siteHierarchyId': site_hierarchy_id,
            'siteType': site_type,
            'id': id,
            'view': view,
            'attribute': attribute,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sites_site_id_profile_assignments_count(self, site_id: Any) -> Dict[str, Any]:
        """Retrieves the count of profiles that the given site has been assigned

        Retrieves the count of profiles that the given site has been assigned.  These profiles may either be directly assigned to this site, or were assigned to a parent site and have been inherited.


        Args:
            site_id (Any): The `id` of the site, retrievable from `/dna/intent/api/v1/sites`

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sites/{site_id}/profileAssignments/count'
        url = url.format(site_id=site_id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v2_site_count(self, id: Optional[Any] = None) -> Dict[str, Any]:
        """Get Site Count V2

        Get the site count of the specified site's sub-hierarchy (inclusive of the provided site)

        Args:
            id (Any): Site instance UUID

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v2/site/count'
        params = {
            'id': id,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_images_count(self, site_id: Optional[Any] = None, product_name_ordinal: Optional[Any] = None, supervisor_product_name_ordinal: Optional[Any] = None, imported: Optional[Any] = None, name: Optional[Any] = None, version: Optional[Any] = None, golden: Optional[Any] = None, integrity: Optional[Any] = None, has_addon_images: Optional[Any] = None, is_addon_images: Optional[Any] = None) -> Dict[str, Any]:
        """Returns count of software images

        Returns the count of software images for given `siteId`. The default value of siteId is global

        Args:
            site_id (Any): Site identifier to get the list of all available products under the site. The default value is the global site.  See https://developer.cisco.com/docs/dna-center/get-site for siteId
            product_name_ordinal (Any): The product name ordinal is a unique value for each network device product. The productNameOrdinal can be obtained from the response of the API `/dna/intent/api/v1/siteWiseProductNames`.
            supervisor_product_name_ordinal (Any): The supervisor engine module ordinal is a unique value for each supervisor module. The `supervisorProductNameOrdinal` can be obtained from the response of API `/dna/intent/api/v1/siteWiseProductNames`
            imported (Any): When the value is set to `true`, it will include physically imported images. Conversely, when the value is set to `false`, it will include image records from the cloud. The identifier for cloud images can be utilised to download images from Cisco.com to the disk.
            name (Any): Filter with software image or add-on name. Supports partial case-insensitive search. A minimum of 3 characters is required for the search
            version (Any): Filter with image version. Supports partial case-insensitive search. A minimum of 3 characters is required for the search
            golden (Any): When set to `true`, it will retrieve the images marked tagged golden. When set to `false`, it will retrieve the images marked not tagged golden.
            integrity (Any): Filter with verified images using Integrity Verification Available values: UNKNOWN, VERIFIED
            has_addon_images (Any): When set to `true`, it will retrieve the images which have add-on images. When set to `false`, it will retrieve the images which do not have add-on images.
            is_addon_images (Any): When set to `true`, it will retrieve the images that an add-on image.  When set to `false`, it will retrieve the images that are not add-on images

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/images/count'
        params = {
            'siteId': site_id,
            'productNameOrdinal': product_name_ordinal,
            'supervisorProductNameOrdinal': supervisor_product_name_ordinal,
            'imported': imported,
            'name': name,
            'version': version,
            'golden': golden,
            'integrity': integrity,
            'hasAddonImages': has_addon_images,
            'isAddonImages': is_addon_images,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_sda_extranet_policies(self, content__type: Any) -> Dict[str, Any]:
        """Add extranet policy

        Adds an extranet policy based on user input.


        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sda/extranetPolicies'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sda_extranet_policies(self, extranet_policy_name: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None) -> Dict[str, Any]:
        """Get extranet policies

        Returns a list of extranet policies that match the provided query parameters.

        Args:
            extranet_policy_name (Any): Name of the extranet policy.
            offset (Any): Starting record for pagination.
            limit (Any): Maximum number of records to return.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/extranetPolicies'
        params = {
            'extranetPolicyName': extranet_policy_name,
            'offset': offset,
            'limit': limit,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_sda_extranet_policies(self, content__type: Any) -> Dict[str, Any]:
        """Update extranet policy

        Updates an extranet policy based on user input.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sda/extranetPolicies'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_sda_extranet_policies(self, extranet_policy_name: Optional[Any] = None) -> Dict[str, Any]:
        """Delete extranet policies

        Deletes extranet policies based on user input.

        Args:
            extranet_policy_name (Any): Name of the extranet policy.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/extranetPolicies'
        params = {
            'extranetPolicyName': extranet_policy_name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_certificate(self, content__type: Any, pk_password: Optional[Any] = None, list_of_users: Optional[Any] = None) -> Dict[str, Any]:
        """importCertificate

        This API enables a user to import a PEM certificate and its key for the controller and/or disaster recovery.

        Args:
            content__type (Any): Request body content type
            pk_password (Any): Password for encrypted private key
            list_of_users (Any): Specify whether the certificate will be used for controller ("server"), disaster recovery ("ipsec") or both ("server, ipsec"). If no value is provided, the default value taken will be "server"

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/certificate'
        params = {
            'pkPassword': pk_password,
            'listOfUsers': list_of_users,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_wireless_profiles_id(self, id: Any) -> Dict[str, Any]:
        """Delete Wireless Profile

        This API allows the user to delete Wireless Network Profile by ID

        Args:
            id (Any): Wireless Profile Id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/wirelessProfiles/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_wireless_profiles_id(self, content__type: Any, id: Any) -> Dict[str, Any]:
        """Update Wireless Profile

        This API allows the user to update a Wireless Network Profile by ID

        Args:
            content__type (Any): Content Type
            id (Any): Wireless Profile Id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/wirelessProfiles/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_wireless_profiles_id(self, id: Any) -> Dict[str, Any]:
        """Get Wireless Profile by ID

        This API allows the user to get a Wireless Network Profile by ID

        Args:
            id (Any): Wireless Profile Id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/wirelessProfiles/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_telemetry_settings_apply(self, content__type: Any) -> Dict[str, Any]:
        """Update a device(s) telemetry settings to conform to the telemetry settings for its site

        Update a device(s) telemetry settings to conform to the telemetry settings for its site.  One Task is created to track the update, for more granular status tracking, split your devices into multiple requests.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/telemetrySettings/apply'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_data_api_v1_flexible_report_schedule_report_id(self, content__type: Any, report_id: Any) -> Dict[str, Any]:
        """Get flexible report schedule by report id

        Get flexible report schedule by report id

        Args:
            content__type (Any): Request body content type
            report_id (Any): Id of the report

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/data/api/v1/flexible-report/schedule/{report_id}'
        url = url.format(report_id=report_id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_data_api_v1_flexible_report_schedule_report_id(self, content__type: Any, report_id: Any) -> Dict[str, Any]:
        """Update schedule of flexible report

        Update schedule of flexible report

        Args:
            content__type (Any): Request body content type
            report_id (Any): Id of the report

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/data/api/v1/flexible-report/schedule/{report_id}'
        url = url.format(report_id=report_id)
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def post_api_v1_onboarding_pnp_device_authorize(self, content__type: Optional[Any] = None) -> Dict[str, Any]:
        """Authorize Device

        Authorizes one of more devices. A device can only be authorized if Authorization is set in Device Settings.

        Args:
            content__type (Any): 

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/api/v1/onboarding/pnp-device/authorize'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_sda_port_channels(self, content__type: Any) -> Dict[str, Any]:
        """Add port channels

        Adds port channels based on user input.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sda/portChannels'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sda_port_channels(self, fabric_id: Optional[Any] = None, network_device_id: Optional[Any] = None, port_channel_name: Optional[Any] = None, connected_device_type: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None) -> Dict[str, Any]:
        """Get port channels

        Returns a list of port channels that match the provided query parameters.

        Args:
            fabric_id (Any): ID of the fabric the device is assigned to.
            network_device_id (Any): ID of the network device.
            port_channel_name (Any): Name of the port channel.
            connected_device_type (Any): Connected device type of the port channel. The allowed values are [TRUNK, EXTENDED_NODE].
            offset (Any): Starting record for pagination.
            limit (Any): Maximum number of records to return.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/portChannels'
        params = {
            'fabricId': fabric_id,
            'networkDeviceId': network_device_id,
            'portChannelName': port_channel_name,
            'connectedDeviceType': connected_device_type,
            'offset': offset,
            'limit': limit,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_sda_port_channels(self, content__type: Any) -> Dict[str, Any]:
        """Update port channels

        Updates port channels based on user input.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sda/portChannels'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_sda_port_channels(self, fabric_id: Any, network_device_id: Any, port_channel_name: Optional[Any] = None, connected_device_type: Optional[Any] = None) -> Dict[str, Any]:
        """Delete port channels

        Deletes port channels based on user input.

        Args:
            fabric_id (Any): ID of the fabric the device is assigned to.
            network_device_id (Any): ID of the network device.
            port_channel_name (Any): Name of the port channel.
            connected_device_type (Any): Connected device type of the port channel. The allowed values are [TRUNK, EXTENDED_NODE].

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/portChannels'
        params = {
            'fabricId': fabric_id,
            'networkDeviceId': network_device_id,
            'portChannelName': port_channel_name,
            'connectedDeviceType': connected_device_type,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_file_name_space(self, name_space: Any) -> Dict[str, Any]:
        """uploadFile

        Uploads a new file within a specific nameSpace

        Args:
            name_space (Any): 

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/file/{name_space}'
        url = url.format(name_space=name_space)
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def post_dna_data_api_v1_network_devices_summary_analytics(self, content__type: Any) -> Dict[str, Any]:
        """Gets the summary analytics data related to network devices.

        Gets the summary analytics data related to network devices based on the provided input data. This endpoint helps to obtain the consolidated insights into the performance and status of the monitored network devices. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-AssuranceNetworkDevices-1.0.2-resolved.yaml

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/data/api/v1/networkDevices/summaryAnalytics'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_wireless_settings_rf_profiles_id(self, id: Any) -> Dict[str, Any]:
        """Delete RF Profile

        This API allows the user to delete a custom RF Profile

        Args:
            id (Any): RF Profile ID

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/wirelessSettings/rfProfiles/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_wireless_settings_rf_profiles_id(self, id: Any) -> Dict[str, Any]:
        """Get RF Profile by ID

        This API allows the user to get a RF Profile by RF Profile ID



        Args:
            id (Any): RF Profile ID

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/wirelessSettings/rfProfiles/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_wireless_settings_rf_profiles_id(self, content__type: Any, id: Any) -> Dict[str, Any]:
        """Update RF Profile

        This API allows the user to update a custom RF Profile

        Args:
            content__type (Any): 
            id (Any): RF Profile ID

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/wirelessSettings/rfProfiles/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_global_credential_netconf(self, content__type: Any) -> Dict[str, Any]:
        """Create Netconf credentials

        Adds global netconf credentials

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/global-credential/netconf'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_global_credential_netconf(self, content__type: Any) -> Dict[str, Any]:
        """Update Netconf credentials

        Updates global netconf credentials

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/global-credential/netconf'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_template_programmer_template(self, content__type: Any) -> Dict[str, Any]:
        """Update Template

        API to update a template.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/template-programmer/template'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_template_programmer_template(self, project_id: Optional[Any] = None, software_type: Optional[Any] = None, software_version: Optional[Any] = None, product_family: Optional[Any] = None, product_series: Optional[Any] = None, product_type: Optional[Any] = None, filter_conflicting_templates: Optional[Any] = None, tags: Optional[Any] = None, project_names: Optional[Any] = None, un_committed: Optional[Any] = None, sort_order: Optional[Any] = None) -> Dict[str, Any]:
        """Gets the templates available

        List the templates available

        Args:
            project_id (Any): Filter template(s) based on project UUID
            software_type (Any): Filter template(s) based software type
            software_version (Any): Filter template(s) based softwareVersion
            product_family (Any): Filter template(s) based on device family
            product_series (Any): Filter template(s) based on device series
            product_type (Any): Filter template(s) based on device type
            filter_conflicting_templates (Any): Filter template(s) based on confliting templates
            tags (Any): Filter template(s) based on tags
            project_names (Any): Filter template(s) based on project names
            un_committed (Any): Filter template(s) based on template commited or not
            sort_order (Any): Sort Order Ascending (asc) or Descending (des)

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/template-programmer/template'
        params = {
            'projectId': project_id,
            'softwareType': software_type,
            'softwareVersion': software_version,
            'productFamily': product_family,
            'productSeries': product_series,
            'productType': product_type,
            'filterConflictingTemplates': filter_conflicting_templates,
            'tags': tags,
            'projectNames': project_names,
            'unCommitted': un_committed,
            'sortOrder': sort_order,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_event_subscription_details_syslog(self, name: Optional[Any] = None, instance_id: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None, sort_by: Optional[Any] = None, order: Optional[Any] = None) -> Dict[str, Any]:
        """Get Syslog Subscription Details

        Gets the list of subscription details for specified connectorType

        Args:
            name (Any): Name of the specific configuration
            instance_id (Any): Instance Id of the specific configuration
            offset (Any): The number of Syslog Subscription detail's to offset in the resultset whose default value 0
            limit (Any): The number of Syslog Subscription detail's to limit in the resultset whose default value 10
            sort_by (Any): SortBy field name
            order (Any): order(asc/desc)

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/event/subscription-details/syslog'
        params = {
            'name': name,
            'instanceId': instance_id,
            'offset': offset,
            'limit': limit,
            'sortBy': sort_by,
            'order': order,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_system_issue_definitions(self, x__c_a_l_l_e_r__i_d: Optional[Any] = None, device_type: Optional[Any] = None, profile_id: Optional[Any] = None, id: Optional[Any] = None, name: Optional[Any] = None, priority: Optional[Any] = None, issue_enabled: Optional[Any] = None, attribute: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None, sort_by: Optional[Any] = None, order: Optional[Any] = None) -> Dict[str, Any]:
        """Returns all issue trigger definitions for given filters.

        Get all system issue defintions. The supported filters are id, name, profileId and definition enable status. An issue trigger definition can be different across the profile and device type. So, `profileId` and `deviceType` in the query param is important and default is global profile and all device type. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-issueAndHealthDefinitions-1.0.0-resolved.yaml


        Args:
            x__c_a_l_l_e_r__i_d (Any): Caller ID is used to trace the origin of API calls and their associated queries executed on the database. It's an optional header parameter that can be added to an API request.

            device_type (Any): These are the device families/types supported for system issue definitions. If no input is made on device type, all device types are considered.
            profile_id (Any): The profile identier to fetch the profile associated issue defintions. The default is `global`. Please refer Network design profiles documentation for more details.
            id (Any): The definition identifier.

Examples:

id=015d9cba-4f53-4087-8317-7e49e5ffef46 (single entity id request)

id=015d9cba-4f53-4087-8317-7e49e5ffef46&id=015d9cba-4f53-4087-8317-7e49e5ffef47 (multiple ids in the query param)

            name (Any): The list of system defined issue names. (Ex."BGP_Down")

Examples:

name=BGP_Down (single entity uuid requested)

name=BGP_Down&name=BGP_Flap (multiple issue names separated by & operator)

            priority (Any): Issue priority, possible values are P1, P2, P3, P4.

`P1`: A critical issue that needs immediate attention and can have a wide impact on network operations.

`P2`: A major issue that can potentially impact multiple devices or clients.

`P3`: A minor issue that has a localized or minimal impact.

`P4`: A warning issue that may not be an immediate problem but addressing it can optimize the network performance.

            issue_enabled (Any): The enablement status of the issue definition, either true or false.
            attribute (Any): These are the attributes supported in system issue definitions response. By default, all properties are sent in response.

            offset (Any): Specifies the starting point within all records returned by the API. It's one based offset. The starting value is 1.
            limit (Any): Maximum number of records to return
            sort_by (Any): A field within the response to sort by.
            order (Any): The sort order of the field ascending or descending.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/intent/api/v1/systemIssueDefinitions'
        params = {
            'deviceType': device_type,
            'profileId': profile_id,
            'id': id,
            'name': name,
            'priority': priority,
            'issueEnabled': issue_enabled,
            'attribute': attribute,
            'offset': offset,
            'limit': limit,
            'sortBy': sort_by,
            'order': order,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_data_reports(self, view_group_id: Optional[Any] = None, view_id: Optional[Any] = None) -> Dict[str, Any]:
        """Get list of scheduled reports

        Get list of scheduled report configurations.

        Args:
            view_group_id (Any): viewGroupId of viewgroup for report
            view_id (Any): viewId of view for report

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/data/reports'
        params = {
            'viewGroupId': view_group_id,
            'viewId': view_id,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_data_reports(self, content__type: Any) -> Dict[str, Any]:
        """Create or Schedule a report

        Create/Schedule a report configuration. Use "Get view details for a given view group & view" API to get the metadata required to configure a report.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/data/reports'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_system_api_v1_users_external_servers_aaa_attribute(self) -> Dict[str, Any]:
        """Get AAA Attribute API

        Get the current value of the custom AAA attribute.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/system/api/v1/users/external-servers/aaa-attribute'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_system_api_v1_users_external_servers_aaa_attribute(self, content__type: Any) -> Dict[str, Any]:
        """Add and Update AAA Attribute API

        Add or update the custom AAA attribute for external authentication. Note that if you decide not to set the custom AAA attribute, a default AAA attribute will be used for authentication based on the protocol supported by your server. For TACACS servers it will be "cisco-av-pair" and for RADIUS servers it will be "Cisco-AVPair".

        Args:
            content__type (Any): The format of the payload.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/system/api/v1/users/external-servers/aaa-attribute'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def delete_dna_system_api_v1_users_external_servers_aaa_attribute(self) -> Dict[str, Any]:
        """Delete AAA Attribute API

        Delete the custom AAA attribute that was added. Note that by deleting the AAA attribute, a default AAA attribute will be used for authentication based on the protocol supported by your server. For TACACS servers it will be "cisco-av-pair" and for RADIUS servers it will be "Cisco-AVPair".

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/system/api/v1/users/external-servers/aaa-attribute'
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_client_detail(self, mac_address: Any, timestamp: Optional[Any] = None) -> Dict[str, Any]:
        """Get Client Detail

        Returns detailed Client information retrieved by Mac Address for any given point of time. 

        Args:
            mac_address (Any): MAC Address of the client
            timestamp (Any): Epoch time(in milliseconds) when the Client health data is required

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/client-detail'
        params = {
            'macAddress': mac_address,
            'timestamp': timestamp,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_data_api_v1_assurance_events_count(self, device_family: Any, x__c_a_l_l_e_r__i_d: Optional[Any] = None, start_time: Optional[Any] = None, end_time: Optional[Any] = None, message_type: Optional[Any] = None, severity: Optional[Any] = None, site_id: Optional[Any] = None, site_hierarchy_id: Optional[Any] = None, network_device_name: Optional[Any] = None, network_device_id: Optional[Any] = None, ap_mac: Optional[Any] = None, client_mac: Optional[Any] = None) -> Dict[str, Any]:
        """Count the number of events

        API to fetch the count of assurance events that match the filter criteria. Please refer to the 'API Support Documentation' section to understand which fields are supported. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-AssuranceEvents-1.0.0-resolved.yaml

        Args:
            device_family (Any): Device family. Please note that multiple families across network device type and client type is not allowed. For example, choosing `Routers` along with `Wireless Client` or `Unified AP` is not supported.
Examples:

`deviceFamily=Switches and Hubs` (single deviceFamily requested)

`deviceFamily=Switches and Hubs&deviceFamily=Routers` (multiple deviceFamily requested)

            x__c_a_l_l_e_r__i_d (Any): Caller ID is used to trace the origin of API calls and their associated queries executed on the database. It's an optional header parameter that can be added to an API request.

            start_time (Any): Start time from which API queries the data set related to the resource. It must be specified in UNIX epochtime in milliseconds. Value is inclusive.

If `startTime` is not provided, API will default to current time minus 24 hours.

            end_time (Any): End time to which API queries the data set related to the resource. It must be specified in UNIX epochtime in milliseconds. Value is inclusive.

If `endTime` is not provided, API will default to current time.

            message_type (Any): Message type for the event.

Examples:

`messageType=Syslog` (single messageType requested)

`messageType=Trap&messageType=Syslog` (multiple messageType requested)

            severity (Any): Severity of the event between 0 and 6. This is applicable only for events related to network devices (other than AP) and `Wired Client` events.

| Value | Severity    |
| ----- | ----------- |
| 0     | Emergency   |
| 1     | Alert       |
| 2     | Critical    |
| 3     | Error       |
| 4     | Warning     |
| 5     | Notice      |
| 6     | Info        |

Examples:

`severity=0` (single severity requested)

`severity=0&severity=1` (multiple severity requested)

            site_id (Any): The UUID of the site. (Ex. `flooruuid`)

Examples:

`?siteId=id1` (single siteId requested)

`?siteId=id1&siteId=id2&siteId=id3` (multiple siteId requested)

            site_hierarchy_id (Any): The full hierarchy breakdown of the site tree in id form starting from Global site UUID and ending with the specific site UUID. (Ex. `globalUuid/areaUuid/buildingUuid/floorUuid`)

This field supports wildcard asterisk (`*`) character search support. E.g. `*uuid*, *uuid, uuid*`

Examples:

`?siteHierarchyId=globalUuid/areaUuid/buildingUuid/floorUuid `(single siteHierarchyId requested)

`?siteHierarchyId=globalUuid/areaUuid/buildingUuid/floorUuid&siteHierarchyId=globalUuid/areaUuid2/buildingUuid2/floorUuid2` (multiple siteHierarchyId requested)

            network_device_name (Any): Network device name. This parameter is applicable for network device related families.
This field supports wildcard (`*`) character-based search. Ex: `*Branch*` or `Branch*` or `*Branch`
Examples:

`networkDeviceName=Branch-3-Gateway` (single networkDeviceName requested)

`networkDeviceName=Branch-3-Gateway&networkDeviceName=Branch-3-Switch` (multiple networkDeviceName requested)

            network_device_id (Any): The list of Network Device Uuids. (Ex. `6bef213c-19ca-4170-8375-b694e251101c`)

Examples:

`networkDeviceId=6bef213c-19ca-4170-8375-b694e251101c` (single networkDeviceId requested)

`networkDeviceId=6bef213c-19ca-4170-8375-b694e251101c&networkDeviceId=32219612-819e-4b5e-a96b-cf22aca13dd9&networkDeviceId=2541e9a7-b80d-4955-8aa2-79b233318ba0` (multiple networkDeviceId requested)

            ap_mac (Any): MAC address of the access point. This parameter is applicable for `Unified AP` and `Wireless Client` events.

This field supports wildcard (`*`) character-based search. Ex: `*50:0F*` or `50:0F*` or `*50:0F`

Examples:

`apMac=50:0F:80:0F:F7:E0` (single apMac requested)

`apMac=50:0F:80:0F:F7:E0&apMac=18:80:90:AB:7E:A0` (multiple apMac requested)

            client_mac (Any): MAC address of the client. This parameter is applicable for `Wired Client` and `Wireless Client` events.

This field supports wildcard (`*`) character-based search. Ex: `*66:2B*` or `66:2B*` or `*66:2B`

Examples:

`clientMac=66:2B:B8:D2:01:56` (single clientMac requested)

`clientMac=66:2B:B8:D2:01:56&clientMac=DC:A6:32:F5:5A:89` (multiple clientMac requested)


        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/data/api/v1/assuranceEvents/count'
        params = {
            'deviceFamily': device_family,
            'startTime': start_time,
            'endTime': end_time,
            'messageType': message_type,
            'severity': severity,
            'siteId': site_id,
            'siteHierarchyId': site_hierarchy_id,
            'networkDeviceName': network_device_name,
            'networkDeviceId': network_device_id,
            'apMac': ap_mac,
            'clientMac': client_mac,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_global_credential_snmpv3(self, content__type: Any) -> Dict[str, Any]:
        """Update SNMPv3 credentials

        Updates global SNMPv3 credential

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/global-credential/snmpv3'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_global_credential_snmpv3(self, content__type: Any) -> Dict[str, Any]:
        """Create SNMPv3 credentials

        Adds global SNMPv3 credentials

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/global-credential/snmpv3'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_eox_status_device(self) -> Dict[str, Any]:
        """Get EoX Status For All Devices

        Retrieves EoX status for all devices in the network

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/eox-status/device'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_tag_id_member_count(self, id: Any, member_type: Any, member_association_type: Optional[Any] = None) -> Dict[str, Any]:
        """Get Tag Member count

        Returns the number of members in a given tag

        Args:
            id (Any): Tag ID
            member_type (Any): memberType
            member_association_type (Any): memberAssociationType

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/tag/{id}/member/count'
        url = url.format(id=id)
        params = {
            'memberType': member_type,
            'memberAssociationType': member_association_type,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_ipam_server_setting(self, content__type: Any) -> Dict[str, Any]:
        """Creates configuration details of the external IPAM server.

        Creates configuration details of the external IPAM server. You should only create one external IPAM server; delete any existing external server before creating a new one.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/ipam/serverSetting'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_ipam_server_setting(self) -> Dict[str, Any]:
        """Retrieves configuration details of the external IPAM server.

        Retrieves configuration details of the external IPAM server.  If an external IPAM server has not been created, this resource will return a `404` response.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/ipam/serverSetting'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_ipam_server_setting(self, content__type: Any) -> Dict[str, Any]:
        """Updates configuration details of the external IPAM server.

        Updates configuration details of the external IPAM server.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/ipam/serverSetting'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_ipam_server_setting(self) -> Dict[str, Any]:
        """Deletes configuration details of the external IPAM server.

        Deletes configuration details of the external IPAM server.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/ipam/serverSetting'
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_data_view_groups_view_group_id_views_view_id(self, view_group_id: Any, view_id: Any) -> Dict[str, Any]:
        """Get view details for a given view group & view

        Gives complete information of the view that is required to configure a report. Use "Get views for a given view group" API to get the viewIds  (required as a query param for this API) for available views.

        Args:
            view_group_id (Any): viewGroupId of viewgroup
            view_id (Any): view id of view

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/data/view-groups/{view_group_id}/views/{view_id}'
        url = url.format(view_group_id=view_group_id, view_id=view_id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_device_device_uuid_equipment(self, device_uuid: Any, type: Optional[Any] = None) -> Dict[str, Any]:
        """Get the Details of Physical Components of the Given Device.

        Return all types of equipment details like PowerSupply, Fan, Chassis, Backplane, Module, PROCESSOR, Other and SFP for the Given device.

        Args:
            device_uuid (Any): DeviceUuid
            type (Any): Type value can be PowerSupply, Fan, Chassis, Backplane, Module, PROCESSOR, Other, SFP. If no type is mentioned, All equipments are fetched for the device.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device/{device_uuid}/equipment'
        url = url.format(device_uuid=device_uuid)
        params = {
            'type': type,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_interface_network_device_device_id_start_index_records_to_return(self, device_id: Any, start_index: Any, records_to_return: Any) -> Dict[str, Any]:
        """Get Device Interfaces by specified range

        Returns the list of interfaces for the device for the specified range

        Args:
            device_id (Any): Device ID
            start_index (Any): Start index
            records_to_return (Any): Number of records to return

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/interface/network-device/{device_id}/{start_index}/{records_to_return}'
        url = url.format(device_id=device_id, start_index=start_index, records_to_return=records_to_return)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_networkprofile_network_profile_id_site_site_id(self, content__type: Any, network_profile_id: Any, site_id: Any) -> Dict[str, Any]:
        """Associate

        Associate Site to a Network Profile

        Args:
            content__type (Any): 
            network_profile_id (Any): Network-Profile Id to be associated
            site_id (Any): Site Id to be associated

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/networkprofile/{network_profile_id}/site/{site_id}'
        url = url.format(network_profile_id=network_profile_id, site_id=site_id)
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_networkprofile_network_profile_id_site_site_id(self, content__type: Any, network_profile_id: Any, site_id: Any) -> Dict[str, Any]:
        """Disassociate

        Disassociate a Site from a Network Profile

        Args:
            content__type (Any): 
            network_profile_id (Any): Network-Profile Id to be associated
            site_id (Any): Site Id to be associated

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/networkprofile/{network_profile_id}/site/{site_id}'
        url = url.format(network_profile_id=network_profile_id, site_id=site_id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_device_collection_schedule_global(self) -> Dict[str, Any]:
        """Get Polling Interval for all devices

        Returns polling interval of all devices

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device/collection-schedule/global'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_data_api_v1_assurance_issues_top_n_analytics(self, content__type: Any, accept__language: Optional[Any] = None, x__c_a_l_l_e_r__i_d: Optional[Any] = None) -> Dict[str, Any]:
        """Get Top N analytics data of issues

        Gets the Top N analytics data related to issues based on given filters and group by field. This data can be used to find top sites which has most issues or top device types with most issue etc,. https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-IssuesList-1.0.0-resolved.yaml

        Args:
            content__type (Any): Request body content type
            accept__language (Any): This header parameter can be used to specify the language in which issue display name need to be returned. Available options are - 'en' (English), 'ja' (Japanese), 'ko' (Korean), 'zh' (Chinese). If this parameter is not present the issue display name is returned in English language.
            x__c_a_l_l_e_r__i_d (Any): Caller ID can be used to trace the caller for queries executed on database. The caller id is like a optional attribute which can be added to API invocation like ui, python, postman, test-automation etc

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        if accept__language is not None:
            request_headers['Accept-Language'] = str(accept__language)
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/data/api/v1/assuranceIssues/topNAnalytics'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_device(self, hostname: Optional[Any] = None, management_ip_address: Optional[Any] = None, mac_address: Optional[Any] = None, location_name: Optional[Any] = None, serial_number: Optional[Any] = None, location: Optional[Any] = None, family: Optional[Any] = None, type: Optional[Any] = None, series: Optional[Any] = None, collection_status: Optional[Any] = None, collection_interval: Optional[Any] = None, not_synced_for_minutes: Optional[Any] = None, error_code: Optional[Any] = None, error_description: Optional[Any] = None, software_version: Optional[Any] = None, software_type: Optional[Any] = None, platform_id: Optional[Any] = None, role: Optional[Any] = None, reachability_status: Optional[Any] = None, up_time: Optional[Any] = None, associated_wlc_ip: Optional[Any] = None, license_name: Optional[Any] = None, license_type: Optional[Any] = None, license_status: Optional[Any] = None, module_name: Optional[Any] = None, module_equpimenttype: Optional[Any] = None, module_servicestate: Optional[Any] = None, module_vendorequipmenttype: Optional[Any] = None, module_partnumber: Optional[Any] = None, module_operationstatecode: Optional[Any] = None, id: Optional[Any] = None, device_support_level: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None) -> Dict[str, Any]:
        """Get Device list

        Returns list of network devices based on filter criteria such as management IP address, mac address, hostname, etc. You can use the .* in any value to conduct a wildcard search.
For example, to find all hostnames beginning with myhost in the IP address range 192.25.18.n, issue the following request:
GET /dna/intent/api/v1/network-device?hostname=myhost.*&managementIpAddress=192.25.18..*

If id parameter is provided with comma separated ids, it will return the list of network-devices for the given ids and ignores the other request parameters. You can also specify offset & limit to get the required list.

        Args:
            hostname (Any): hostname
            management_ip_address (Any): managementIpAddress
            mac_address (Any): macAddress
            location_name (Any): locationName
            serial_number (Any): serialNumber
            location (Any): location
            family (Any): family
            type (Any): type
            series (Any): series
            collection_status (Any): collectionStatus
            collection_interval (Any): collectionInterval
            not_synced_for_minutes (Any): notSyncedForMinutes
            error_code (Any): errorCode
            error_description (Any): errorDescription
            software_version (Any): softwareVersion
            software_type (Any): softwareType
            platform_id (Any): platformId
            role (Any): role
            reachability_status (Any): reachabilityStatus
            up_time (Any): upTime
            associated_wlc_ip (Any): associatedWlcIp
            license_name (Any): licenseName
            license_type (Any): licenseType
            license_status (Any): licenseStatus
            module_name (Any): moduleName
            module_equpimenttype (Any): moduleEqupimentType
            module_servicestate (Any): moduleServiceState
            module_vendorequipmenttype (Any): moduleVendorEquipmentType
            module_partnumber (Any): modulePartNumber
            module_operationstatecode (Any): moduleOperationStateCode
            id (Any): Accepts comma separated ids and return list of network-devices for the given ids. If invalid or not-found ids are provided, null entry will be returned in the list.
            device_support_level (Any): deviceSupportLevel
            offset (Any): offset >= 1 [X gives results from Xth device onwards]
            limit (Any): 1 <= limit <= 500 [max. no. of devices to be returned in the result]

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device'
        params = {
            'hostname': hostname,
            'managementIpAddress': management_ip_address,
            'macAddress': mac_address,
            'locationName': location_name,
            'serialNumber': serial_number,
            'location': location,
            'family': family,
            'type': type,
            'series': series,
            'collectionStatus': collection_status,
            'collectionInterval': collection_interval,
            'notSyncedForMinutes': not_synced_for_minutes,
            'errorCode': error_code,
            'errorDescription': error_description,
            'softwareVersion': software_version,
            'softwareType': software_type,
            'platformId': platform_id,
            'role': role,
            'reachabilityStatus': reachability_status,
            'upTime': up_time,
            'associatedWlcIp': associated_wlc_ip,
            'license.name': license_name,
            'license.type': license_type,
            'license.status': license_status,
            'module+name': module_name,
            'module+equpimenttype': module_equpimenttype,
            'module+servicestate': module_servicestate,
            'module+vendorequipmenttype': module_vendorequipmenttype,
            'module+partnumber': module_partnumber,
            'module+operationstatecode': module_operationstatecode,
            'id': id,
            'deviceSupportLevel': device_support_level,
            'offset': offset,
            'limit': limit,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_network_device(self, content__type: Any) -> Dict[str, Any]:
        """Add Device

        Adds the device with given credential

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/network-device'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_network_device(self, content__type: Any) -> Dict[str, Any]:
        """Update Device Details

        Update the credentials, management IP address of a given device (or a set of devices) in Catalyst Center and trigger an inventory sync.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/network-device'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_certificate_p12(self, content__type: Any, p12_password: Any, pk_password: Optional[Any] = None, list_of_users: Optional[Any] = None) -> Dict[str, Any]:
        """importCertificateP12

        This API enables a user to import a PKCS12 certificate bundle for the controller and/or disaster recovery.

        Args:
            content__type (Any): Request body content type
            p12_password (Any): The password for PKCS12 certificate bundle
            pk_password (Any): Password for encrypted private key
            list_of_users (Any): Specify whether the certificate will be used for controller ("server"), disaster recovery ("ipsec") or both ("server, ipsec"). If no value is provided, the default value taken will be "server"

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/certificate-p12'
        params = {
            'p12Password': p12_password,
            'pkPassword': pk_password,
            'listOfUsers': list_of_users,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_device_poller_cli_legit_reads(self) -> Dict[str, Any]:
        """Get all keywords of CLIs accepted by command runner

        Get valid keywords

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device-poller/cli/legit-reads'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_network_device_sync(self, content__type: Any, force_sync: Optional[Any] = None) -> Dict[str, Any]:
        """Sync Devices

        Synchronizes the devices. If forceSync param is false (default) then the sync would run in normal priority thread. If forceSync param is true then the sync would run in high priority thread if available, else the sync will fail. Result can be seen in the child task of each device

        Args:
            content__type (Any): Request body content type
            force_sync (Any): forceSync

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/network-device/sync'
        params = {
            'forceSync': force_sync,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_onboarding_pnp_settings_vacct(self, domain: Any, name: Any) -> Dict[str, Any]:
        """Deregister Virtual Account

        Deregisters the specified smart account & virtual account info and the associated device information from the PnP System & database. The devices associated with the deregistered virtual account are removed from the PnP database as well. The response payload contains the deregistered smart & virtual account information

        Args:
            domain (Any): Smart Account Domain
            name (Any): Virtual Account Name

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/onboarding/pnp-settings/vacct'
        params = {
            'domain': domain,
            'name': name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_qos_device_interface_info(self, content__type: Any) -> Dict[str, Any]:
        """Create Qos Device Interface Info

        Create qos device interface infos associate with network device id to allow the user to mark specific interfaces as WAN, to associate WAN interfaces with specific SP Profile and to be able to define a shaper on WAN interfaces

        Args:
            content__type (Any): content-type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/qos-device-interface-info'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_qos_device_interface_info(self, network_device_id: Optional[Any] = None) -> Dict[str, Any]:
        """Get Qos Device Interface Info

        Get all or by network device id, existing qos device interface infos

        Args:
            network_device_id (Any): network device id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/qos-device-interface-info'
        params = {
            'networkDeviceId': network_device_id,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_qos_device_interface_info(self, content__type: Any) -> Dict[str, Any]:
        """Update Qos Device Interface Info

        Update existing qos device interface infos associate with network device id

        Args:
            content__type (Any): content-type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/qos-device-interface-info'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_tags_interfaces_members_associations_count(self) -> Dict[str, Any]:
        """Retrieve the count of interfaces that are associated with at least one tag.

        Fetches the count of interfaces that are associated with at least one tag. A tag is a user-defined or system-defined construct to group resources. When an interface is tagged, it is called a member of the tag.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/tags/interfaces/membersAssociations/count'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_image_importation_device_family_identifiers(self, accept: Optional[Any] = None) -> Dict[str, Any]:
        """Get Device Family Identifiers

        API to get Device Family Identifiers for all Device Families that can be used for tagging an image golden.

        Args:
            accept (Any): MIME type / MIME subtype

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if accept is not None:
            request_headers['Accept'] = str(accept)
        url = self.base_url + '/dna/intent/api/v1/image/importation/device-family-identifiers'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_onboarding_pnp_device_import(self, content__type: Any) -> Dict[str, Any]:
        """Import Devices in bulk

        Add devices to PnP in bulk

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/onboarding/pnp-device/import'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_task_count(self, start_time: Optional[Any] = None, end_time: Optional[Any] = None, data: Optional[Any] = None, error_code: Optional[Any] = None, service_type: Optional[Any] = None, username: Optional[Any] = None, progress: Optional[Any] = None, is_error: Optional[Any] = None, failure_reason: Optional[Any] = None, parent_id: Optional[Any] = None) -> Dict[str, Any]:
        """Get task count

        Returns Task count

        Args:
            start_time (Any): This is the epoch start time from which tasks need to be fetched
            end_time (Any): This is the epoch end time upto which audit records need to be fetched
            data (Any): Fetch tasks that contains this data
            error_code (Any): Fetch tasks that have this error code
            service_type (Any): Fetch tasks with this service type
            username (Any): Fetch tasks with this username
            progress (Any): Fetch tasks that contains this progress
            is_error (Any): Fetch tasks ended as success or failure. Valid values: true, false
            failure_reason (Any): Fetch tasks that contains this failure reason
            parent_id (Any): Fetch tasks that have this parent Id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/task/count'
        params = {
            'startTime': start_time,
            'endTime': end_time,
            'data': data,
            'errorCode': error_code,
            'serviceType': service_type,
            'username': username,
            'progress': progress,
            'isError': is_error,
            'failureReason': failure_reason,
            'parentId': parent_id,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_device_health(self, device_role: Optional[Any] = None, site_id: Optional[Any] = None, health: Optional[Any] = None, start_time: Optional[Any] = None, end_time: Optional[Any] = None, limit: Optional[Any] = None, offset: Optional[Any] = None) -> Dict[str, Any]:
        """Devices

        Intent API for accessing DNA Assurance Device object for generating reports, creating dashboards or creating additional value added services.

        Args:
            device_role (Any): CORE, ACCESS, DISTRIBUTION, ROUTER, WLC, or AP (case insensitive)
            site_id (Any): DNAC site UUID
            health (Any): DNAC health catagory: POOR, FAIR, or GOOD (case insensitive)
            start_time (Any): UTC epoch time in milliseconds
            end_time (Any): UTC epoch time in milliseconds
            limit (Any): Max number of device entries in the response (default to 50. Max at 500)
            offset (Any): The offset of the first device in the returned data (Mutiple of 'limit' + 1)

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/device-health'
        params = {
            'deviceRole': device_role,
            'siteId': site_id,
            'health': health,
            'startTime': start_time,
            'endTime': end_time,
            'limit': limit,
            'offset': offset,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_wireless_controllers_network_device_id_ssid_details_count(self, network_device_id: Any, admin_status: Optional[Any] = None, managed: Optional[Any] = None) -> Dict[str, Any]:
        """Get SSID Count for specific Wireless Controller

        Retrieves the count of SSIDs associated with the specific Wireless Controller.

        Args:
            network_device_id (Any): Obtain the network device ID value by using the API call GET: /dna/intent/api/v1/network-device/ip-address/${ipAddress}.
            admin_status (Any): Utilize this query parameter to obtain the number of SSIDs according to their administrative status. A 'true' value signifies that the admin status of the SSID is enabled, while a 'false' value indicates that the admin status of the SSID is disabled.
            managed (Any): If value is 'true' means SSIDs are configured through design.If the value is 'false' means out of band configuration from the Wireless Controller.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/wirelessControllers/{network_device_id}/ssidDetails/count'
        url = url.format(network_device_id=network_device_id)
        params = {
            'adminStatus': admin_status,
            'managed': managed,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_diagnostic_validation_sets_id(self, id: Any) -> Dict[str, Any]:
        """Retrieves validation details for a validation set

        Retrieves validation details for the given validation set id


        Args:
            id (Any): Validation set id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/diagnosticValidationSets/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_onboarding_pnp_settings_sacct(self) -> Dict[str, Any]:
        """Get Smart Account List

        Returns the list of Smart Account domains

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/onboarding/pnp-settings/sacct'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sda_layer3_virtual_networks(self, virtual_network_name: Optional[Any] = None, fabric_id: Optional[Any] = None, anchored_site_id: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None) -> Dict[str, Any]:
        """Get layer 3 virtual networks

        Returns a list of layer 3 virtual networks that match the provided query parameters.


        Args:
            virtual_network_name (Any): Name of the layer 3 virtual network.
            fabric_id (Any): ID of the fabric the layer 3 virtual network is assigned to.
            anchored_site_id (Any): Fabric ID of the fabric site the layer 3 virtual network is anchored at.
            offset (Any): Starting record for pagination.
            limit (Any): Maximum number of records to return.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/layer3VirtualNetworks'
        params = {
            'virtualNetworkName': virtual_network_name,
            'fabricId': fabric_id,
            'anchoredSiteId': anchored_site_id,
            'offset': offset,
            'limit': limit,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_sda_layer3_virtual_networks(self, virtual_network_name: Optional[Any] = None) -> Dict[str, Any]:
        """Delete layer 3 virtual networks

        Deletes layer 3 virtual networks based on user input.

        Args:
            virtual_network_name (Any): Name of the layer 3 virtual network.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/layer3VirtualNetworks'
        params = {
            'virtualNetworkName': virtual_network_name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_sda_layer3_virtual_networks(self, content__type: Any) -> Dict[str, Any]:
        """Add layer 3 virtual networks

        Adds layer 3 virtual networks based on user input.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sda/layer3VirtualNetworks'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_sda_layer3_virtual_networks(self, content__type: Any) -> Dict[str, Any]:
        """Update layer 3 virtual networks

        Updates layer 3 virtual networks based on user input.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sda/layer3VirtualNetworks'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_file_namespace(self) -> Dict[str, Any]:
        """Get list of available namespaces

        Returns list of available namespaces

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/file/namespace'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_sites_site_id_wireless_settings_ssids_id(self, content__type: Any, site_id: Any, id: Any) -> Dict[str, Any]:
        """Update SSID

        This API allows the user to update an SSID (Service Set Identifier) at the given site

        Args:
            content__type (Any): 
            site_id (Any): Site UUID
            id (Any): SSID ID. Inputs containing special characters should be encoded

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sites/{site_id}/wirelessSettings/ssids/{id}'
        url = url.format(site_id=site_id, id=id)
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sites_site_id_wireless_settings_ssids_id(self, site_id: Any, id: Any) -> Dict[str, Any]:
        """Get SSID by ID

        This API allows the user to get an SSID (Service Set Identifier) by ID at the given site

        Args:
            site_id (Any): Site UUID
            id (Any): SSID ID.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sites/{site_id}/wirelessSettings/ssids/{id}'
        url = url.format(site_id=site_id, id=id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_sites_site_id_wireless_settings_ssids_id(self, site_id: Any, id: Any) -> Dict[str, Any]:
        """Delete SSID

        This API allows the user to delete an SSID (Service Set Identifier) at the global level, if the SSID is not mapped to any Wireless Profile

        Args:
            site_id (Any): Site UUID where SSID is to be deleted
            id (Any): SSID ID

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sites/{site_id}/wirelessSettings/ssids/{id}'
        url = url.format(site_id=site_id, id=id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_product_names_product_name_ordinal(self, product_name_ordinal: Any) -> Dict[str, Any]:
        """Retrieve network device product name

        Get the network device product name, its ordinal, and supported PIDs.

        Args:
            product_name_ordinal (Any): Product name ordinal is unique value for each network device product.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/productNames/{product_name_ordinal}'
        url = url.format(product_name_ordinal=product_name_ordinal)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_data_api_v1_flexible_report_report_report_id_executions(self, content__type: Any, report_id: Any) -> Dict[str, Any]:
        """Get Execution Id by Report Id

        Get Execution Id by Report Id

        Args:
            content__type (Any): Request body content type
            report_id (Any): Id of the report

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/data/api/v1/flexible-report/report/{report_id}/executions'
        url = url.format(report_id=report_id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_wireless_controllers_wireless_mobility_groups_count(self) -> Dict[str, Any]:
        """Get MobilityGroups Count

        Retrieves count of mobility groups configured

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/wirelessControllers/wirelessMobilityGroups/count'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_tasks_id_detail(self, id: Any) -> Dict[str, Any]:
        """Get task details by ID

        Returns the task details for the given task ID

        Args:
            id (Any): the `id` of the task to retrieve details for

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/tasks/{id}/detail'
        url = url.format(id=id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_network_devices_resync_interval_settings(self) -> Dict[str, Any]:
        """Update global resync interval

        Updates the resync interval (in minutes) globally for devices which do not have custom resync interval. To override this setting for all network devices refer to [/networkDevices/resyncIntervalSettings/override]

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/networkDevices/resyncIntervalSettings'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_device_custom_prompt(self) -> Dict[str, Any]:
        """Custom-prompt support GET API

        Returns supported custom prompts by Catalyst Center

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device/custom-prompt'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_network_device_custom_prompt(self, content__type: Any) -> Dict[str, Any]:
        """Custom Prompt POST API

        Save custom prompt added by user in Catalyst Center. API will always override the existing prompts. User should provide all the custom prompt in case of any update

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/network-device/custom-prompt'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_security_advisory_advisory(self) -> Dict[str, Any]:
        """Get Advisories List

        Retrieves list of advisories on the network

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/security-advisory/advisory'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_device_replacement_workflow(self, content__type: Any) -> Dict[str, Any]:
        """Deploy device replacement workflow

        API to trigger RMA workflow that will replace faulty device with replacement device with same configuration and images

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/device-replacement/workflow'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_device_id_vlan(self, id: Any, interface_type: Optional[Any] = None) -> Dict[str, Any]:
        """Get Device Interface VLANs

        Returns Device Interface VLANs. If parameter value is null or empty, it won't return any value in response.

        Args:
            id (Any): deviceUUID
            interface_type (Any): Vlan associated with sub-interface. If no interfaceType mentioned it will return all types of Vlan interfaces. If interfaceType is selected but not specified then it will take default value.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device/{id}/vlan'
        url = url.format(id=id)
        params = {
            'interfaceType': interface_type,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_file_namespace_name_space(self, name_space: Any) -> Dict[str, Any]:
        """Get list of files

        Returns list of files under a specific namespace

        Args:
            name_space (Any): A listing of fileId's

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/file/namespace/{name_space}'
        url = url.format(name_space=name_space)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_images_distribution_server_settings_id(self, content__type: Any, id: Any) -> Dict[str, Any]:
        """Update remote image distribution server

        Update remote image distribution server details.

        Args:
            content__type (Any): Request body content type
            id (Any): Remote server identifier.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/images/distributionServerSettings/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_images_distribution_server_settings_id(self, id: Any) -> Dict[str, Any]:
        """Remove image distribution server

        Delete remote image distribution server.

        Args:
            id (Any): Remote server identifier.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/images/distributionServerSettings/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_images_distribution_server_settings_id(self, id: Any) -> Dict[str, Any]:
        """Retrieve specific image distribution server

        Retrieve image distribution server for the given server identifier

        Args:
            id (Any): Server identifier

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/images/distributionServerSettings/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_app_policy(self, policy_scope: Optional[Any] = None) -> Dict[str, Any]:
        """Get Application Policy

        Get all existing application policies

        Args:
            policy_scope (Any): policy scope name

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/app-policy'
        params = {
            'policyScope': policy_scope,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_template_programmer_template_preview(self, content__type: Any) -> Dict[str, Any]:
        """Preview Template

        API to preview a template.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/template-programmer/template/preview'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_sda_extranet_policies_id(self, id: Any) -> Dict[str, Any]:
        """Delete extranet policy by id

        Deletes an extranet policy based on id.

        Args:
            id (Any): ID of the extranet policy.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/extranetPolicies/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_onboarding_pnp_workflow_id(self, content__type: Any, id: Any) -> Dict[str, Any]:
        """Update Workflow

        Updates an existing workflow

        Args:
            content__type (Any): Request body content type
            id (Any): id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/onboarding/pnp-workflow/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_onboarding_pnp_workflow_id(self, id: Any) -> Dict[str, Any]:
        """Get Workflow by Id

        Returns a workflow specified by id

        Args:
            id (Any): id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/onboarding/pnp-workflow/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_onboarding_pnp_workflow_id(self, id: Any) -> Dict[str, Any]:
        """Delete Workflow By Id

        Deletes a workflow specified by id

        Args:
            id (Any): id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/onboarding/pnp-workflow/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_security_advisory_advisory_aggregate(self) -> Dict[str, Any]:
        """Get Advisories Summary

        Retrieves summary of advisories on the network.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/security-advisory/advisory/aggregate'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_network_devices_resync_interval_settings_override(self) -> Dict[str, Any]:
        """Override resync interval

        Overrides the global resync interval on all network devices. This essentially removes device specific intervals if set.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/networkDevices/resyncIntervalSettings/override'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_tag_member_type(self) -> Dict[str, Any]:
        """Get Tag resource types

        Returns list of supported resource types

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/tag/member/type'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sda_port_assignments_count(self, fabric_id: Optional[Any] = None, network_device_id: Optional[Any] = None, interface_name: Optional[Any] = None, data_vlan_name: Optional[Any] = None, voice_vlan_name: Optional[Any] = None) -> Dict[str, Any]:
        """Get port assignment count

        Returns the count of port assignments that match the provided query parameters.

        Args:
            fabric_id (Any): ID of the fabric the device is assigned to.
            network_device_id (Any): Network device ID of the port assignment.
            interface_name (Any): Interface name of the port assignment.
            data_vlan_name (Any): Data VLAN name of the port assignment.
            voice_vlan_name (Any): Voice VLAN name of the port assignment.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/portAssignments/count'
        params = {
            'fabricId': fabric_id,
            'networkDeviceId': network_device_id,
            'interfaceName': interface_name,
            'dataVlanName': data_vlan_name,
            'voiceVlanName': voice_vlan_name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_discovery_start_index_records_to_return(self, start_index: Any, records_to_return: Any) -> Dict[str, Any]:
        """Get Discoveries by range

        Returns the discoveries by specified range

        Args:
            start_index (Any): Starting index for the records
            records_to_return (Any): Number of records to fetch from the starting index

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/discovery/{start_index}/{records_to_return}'
        url = url.format(start_index=start_index, records_to_return=records_to_return)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_global_credential_snmpv2_read_community(self, content__type: Any) -> Dict[str, Any]:
        """Update SNMP read community

        Updates global SNMP read community

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/global-credential/snmpv2-read-community'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_global_credential_snmpv2_read_community(self, content__type: Any) -> Dict[str, Any]:
        """Create SNMP read community

        Adds global SNMP read community

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/global-credential/snmpv2-read-community'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_integration_settings_itsm_instances(self) -> Dict[str, Any]:
        """Get all ITSM Integration settings

        Fetches all ITSM Integration settings

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/integration-settings/itsm/instances'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_licenses_usage_smart_account_smart_account_id_virtual_account_virtual_account_name(self, smart_account_id: Any, virtual_account_name: Any, device_type: Any) -> Dict[str, Any]:
        """License Usage Details

        Get count of purchased and in use Cisco DNA and Network licenses.

        Args:
            smart_account_id (Any): Id of smart account
            virtual_account_name (Any): Name of virtual account. Putting "All" will give license term detail for all virtual accounts.
            device_type (Any): Type of device like router, switch, wireless or ise

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/licenses/usage/smartAccount/{smart_account_id}/virtualAccount/{virtual_account_name}'
        url = url.format(smart_account_id=smart_account_id, virtual_account_name=virtual_account_name)
        params = {
            'device_type': device_type,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_areas_id(self, id: Any) -> Dict[str, Any]:
        """Deletes an area

        Deletes an area in the network hierarchy. This operations fails if there are any child areas or buildings for this area.

        Args:
            id (Any): Area ID

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/areas/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_areas_id(self, id: Any) -> Dict[str, Any]:
        """Gets an area

        Gets an area in the network hierarchy.

        Args:
            id (Any): Area Id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/areas/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_areas_id(self, content__type: Any, id: Any) -> Dict[str, Any]:
        """Updates an area

        Updates an area in the network hierarchy.

        Args:
            content__type (Any): Request body content type
            id (Any): Area Id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/areas/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_intent_api_v1_health_score_definitions_count(self, x__c_a_l_l_e_r__i_d: Optional[Any] = None, device_type: Optional[Any] = None, id: Optional[Any] = None, include_for_overall_health: Optional[Any] = None) -> Dict[str, Any]:
        """Get the count of health score definitions based on provided filters.

        Get the count of health score definitions based on provided filters. Supported filters are id, name and overall health include status. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-issueAndHealthDefinitions-1.0.0-resolved.yaml


        Args:
            x__c_a_l_l_e_r__i_d (Any): Caller ID is used to trace the origin of API calls and their associated queries executed on the database. It's an optional header parameter that can be added to an API request.

            device_type (Any): These are the device families supported for health score definitions. If no input is made on device family, all device families are considered.
            id (Any): The definition identifier.

Examples:

id=015d9cba-4f53-4087-8317-7e49e5ffef46 (single entity id request)

id=015d9cba-4f53-4087-8317-7e49e5ffef46&id=015d9cba-4f53-4087-8317-7e49e5ffef47 (multiple ids in the query param)

            include_for_overall_health (Any): The inclusion status of the issue definition, either true or false. true indicates that particular health metric is included in overall health computation, otherwise false. By default it's set to true.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/intent/api/v1/healthScoreDefinitions/count'
        params = {
            'deviceType': device_type,
            'id': id,
            'includeForOverallHealth': include_for_overall_health,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sda_extranet_policies_count(self) -> Dict[str, Any]:
        """Get extranet policy count

        Returns the count of extranet policies that match the provided query parameters.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/extranetPolicies/count'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_devices_id_resync_interval_settings(self, id: Any) -> Dict[str, Any]:
        """Get resync interval for the network device

        Fetch the reysnc interval for the given network device id.

        Args:
            id (Any): The id of the network device.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/networkDevices/{id}/resyncIntervalSettings'
        url = url.format(id=id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_network_devices_id_resync_interval_settings(self, id: Any) -> Dict[str, Any]:
        """Update resync interval for the network device

        Update the resync interval (in minutes) for the given network device id.

To disable periodic resync, set interval as `0`.

To use global settings, set interval as `null`.


        Args:
            id (Any): The id of the network device.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/networkDevices/{id}/resyncIntervalSettings'
        url = url.format(id=id)
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_wireless_settings_interfaces(self, limit: Optional[Any] = None, offset: Optional[Any] = None) -> Dict[str, Any]:
        """Get Interfaces

        This API allows the user to get all Interfaces

        Args:
            limit (Any): Limit
            offset (Any): Offset

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/wirelessSettings/interfaces'
        params = {
            'limit': limit,
            'offset': offset,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_wireless_settings_interfaces(self, content__type: Any) -> Dict[str, Any]:
        """Create Interface

        This API allows the user to create an interface

        Args:
            content__type (Any): Content Type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/wirelessSettings/interfaces'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_data_view_groups(self) -> Dict[str, Any]:
        """Get all view groups

        Gives a list of summary of all view groups.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/data/view-groups'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_events(self, tags: Any, event_id: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None, sort_by: Optional[Any] = None, order: Optional[Any] = None) -> Dict[str, Any]:
        """Get Events

        Gets the list of registered Events with provided eventIds or tags as mandatory

        Args:
            tags (Any): The registered Tags should be provided
            event_id (Any): The registered EventId should be provided
            offset (Any): The number of Registries to offset in the resultset whose default value 0
            limit (Any): The number of Registries to limit in the resultset whose default value 10
            sort_by (Any): SortBy field name
            order (Any): order(asc/desc)

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/events'
        params = {
            'tags': tags,
            'eventId': event_id,
            'offset': offset,
            'limit': limit,
            'sortBy': sort_by,
            'order': order,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_event_subscription_email(self, event_ids: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None, sort_by: Optional[Any] = None, order: Optional[Any] = None, domain: Optional[Any] = None, sub_domain: Optional[Any] = None, category: Optional[Any] = None, type: Optional[Any] = None, name: Optional[Any] = None) -> Dict[str, Any]:
        """Get Email Event Subscriptions

        Gets the list of email Subscriptions's based on provided query params

        Args:
            event_ids (Any): List of email subscriptions related to the respective eventIds (Comma separated event ids)
            offset (Any): The number of Subscriptions's to offset in the resultset whose default value 0
            limit (Any): The number of Subscriptions's to limit in the resultset whose default value 10
            sort_by (Any): SortBy field name
            order (Any): order(asc/desc)
            domain (Any): List of email subscriptions related to the respective domain
            sub_domain (Any): List of email subscriptions related to the respective sub-domain
            category (Any): List of email subscriptions related to the respective category
            type (Any): List of email subscriptions related to the respective type
            name (Any): List of email subscriptions related to the respective name

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/event/subscription/email'
        params = {
            'eventIds': event_ids,
            'offset': offset,
            'limit': limit,
            'sortBy': sort_by,
            'order': order,
            'domain': domain,
            'subDomain': sub_domain,
            'category': category,
            'type': type,
            'name': name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_event_subscription_email(self, content__type: Any) -> Dict[str, Any]:
        """Create Email Event Subscription

        Create Email Subscription Endpoint for list of registered events.

        Args:
            content__type (Any): Content Type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/event/subscription/email'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_event_subscription_email(self, content__type: Any) -> Dict[str, Any]:
        """Update Email Event Subscription

        Update Email Subscription Endpoint for list of registered events

        Args:
            content__type (Any): Content Type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/event/subscription/email'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_sda_layer3_virtual_networks_id(self, id: Any) -> Dict[str, Any]:
        """Delete layer 3 virtual network by id

        Deletes a layer 3 virtual network based on id.

        Args:
            id (Any): ID of the layer 3 virtual network.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/layer3VirtualNetworks/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_event_subscription_details_email(self, name: Optional[Any] = None, instance_id: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None, sort_by: Optional[Any] = None, order: Optional[Any] = None) -> Dict[str, Any]:
        """Get Email Subscription Details

        Gets the list of subscription details for specified connectorType

        Args:
            name (Any): Name of the specific configuration
            instance_id (Any): Instance Id of the specific configuration
            offset (Any): The number of Email Subscription detail's to offset in the resultset whose default value 0
            limit (Any): The number of Email Subscription detail's to limit in the resultset whose default value 10
            sort_by (Any): SortBy field name
            order (Any): order(asc/desc)

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/event/subscription-details/email'
        params = {
            'name': name,
            'instanceId': instance_id,
            'offset': offset,
            'limit': limit,
            'sortBy': sort_by,
            'order': order,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_assurance_issues_ignore(self, content__type: Any, x__c_a_l_l_e_r__i_d: Optional[Any] = None) -> Dict[str, Any]:
        """Ignore the given list of issues

        Ignores the given list of issues. The response contains the list of issues which were successfully ignored as well as the issues which are failed to ignore. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-IssuesLifecycle-1.0.0-resolved.yaml

        Args:
            content__type (Any): Request body content type
            x__c_a_l_l_e_r__i_d (Any): Caller ID can be used to trace the caller for queries executed on database. The caller id is like a optional attribute which can be added to API invocation like ui, python, postman, test-automation etc

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/intent/api/v1/assuranceIssues/ignore'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_tag_member(self, content__type: Any) -> Dict[str, Any]:
        """Update tag membership

        Update tag membership. As part of the request payload through this API, only the specified members are added / retained to the given input tags. Possible values of memberType attribute in the request payload can be queried by using the /tag/member/type API

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/tag/member'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sites_id_aaa_settings(self, id: Any, inherited: Optional[Any] = None) -> Dict[str, Any]:
        """Retrieve AAA settings for a site

        Retrieve AAA settings for a site; `null` values indicate that the setting will be inherited from the parent site; empty objects (`{}`) indicate that the setting is unset at a site.

        Args:
            id (Any): Site Id
            inherited (Any): Include settings explicitly set for this site and settings inherited from sites higher in the site hierarchy; when `false`, `null` values indicate that the site inherits that setting from the parent site or a site higher in the site hierarchy.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sites/{id}/aaaSettings'
        url = url.format(id=id)
        params = {
            '_inherited': inherited,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_sites_id_aaa_settings(self, content__type: Any, id: Any) -> Dict[str, Any]:
        """Set AAA settings for a site

        Set AAA settings for a site; `null` values indicate that the settings will be inherited from the parent site; empty objects (`{}`) indicate that the settings is unset.

        Args:
            content__type (Any): Request body content type
            id (Any): Site Id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sites/{id}/aaaSettings'
        url = url.format(id=id)
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_interface_network_device_device_id_interface_name(self, device_id: Any, name: Any) -> Dict[str, Any]:
        """Get Interface details by device Id and interface name

        Returns interface by specified device Id and interface name

        Args:
            device_id (Any): Device ID
            name (Any): Interface name

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/interface/network-device/{device_id}/interface-name'
        url = url.format(device_id=device_id)
        params = {
            'name': name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v2_global_credential(self) -> Dict[str, Any]:
        """Create Global Credentials V2

        API to create new global credentials. Multiple credentials of various types can be passed at once. Please refer sample Request Body for more information.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v2/global-credential'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v2_global_credential(self) -> Dict[str, Any]:
        """Get All Global Credentials V2

        API to get device credentials' details. It fetches all global credentials of all types at once, without the need to pass any input parameters.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v2/global-credential'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v2_global_credential(self) -> Dict[str, Any]:
        """Update Global Credentials V2

        API to update device credentials. Multiple credentials can be passed at once, but only a single credential of a given type can be passed at once. Please refer sample Request Body for more information.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v2/global-credential'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_wireless_access_points_factory_reset_request_status(self, task_id: Any) -> Dict[str, Any]:
        """Get Access Point(s) Factory Reset status

        This API returns each AP Factory Reset initiation status.

        Args:
            task_id (Any): provide the task id which is returned in the response of ap factory reset post api

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/wirelessAccessPoints/factoryResetRequestStatus'
        params = {
            'taskId': task_id,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_discovery_id_summary(self, id: Any, task_id: Optional[Any] = None, sort_by: Optional[Any] = None, sort_order: Optional[Any] = None, ip_address: Optional[Any] = None, ping_status: Optional[Any] = None, snmp_status: Optional[Any] = None, cli_status: Optional[Any] = None, netconf_status: Optional[Any] = None, http_status: Optional[Any] = None) -> Dict[str, Any]:
        """Get network devices from Discovery

        Returns the devices discovered in the given discovery based on given filters. Discovery ID can be obtained using the "Get Discoveries by range" API.

        Args:
            id (Any): Discovery ID
            task_id (Any): taskId
            sort_by (Any): Sort by field. Available values are pingStatus, cliStatus,snmpStatus, httpStatus and netconfStatus
            sort_order (Any): Order of sorting based on sortBy. Available values are 'asc' and 'des'
            ip_address (Any): IP Address of the device
            ping_status (Any): Ping status for the IP during the job run. Available values are 'SUCCESS', 'FAILURE', 'NOT-PROVIDED' and 'NOT-VALIDATED'
            snmp_status (Any): SNMP status for the IP during the job run. Available values are 'SUCCESS', 'FAILURE', 'NOT-PROVIDED' and 'NOT-VALIDATED'
            cli_status (Any): CLI status for the IP during the job run. Available values are 'SUCCESS', 'FAILURE', 'NOT-PROVIDED' and 'NOT-VALIDATED'
            netconf_status (Any): NETCONF status for the IP during the job run. Available values are 'SUCCESS', 'FAILURE', 'NOT-PROVIDED' and 'NOT-VALIDATED'
            http_status (Any): HTTP staus for the IP during the job run. Available values are 'SUCCESS', 'FAILURE', 'NOT-PROVIDED' and 'NOT-VALIDATED'

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/discovery/{id}/summary'
        url = url.format(id=id)
        params = {
            'taskId': task_id,
            'sortBy': sort_by,
            'sortOrder': sort_order,
            'ipAddress': ip_address,
            'pingStatus': ping_status,
            'snmpStatus': snmp_status,
            'cliStatus': cli_status,
            'netconfStatus': netconf_status,
            'httpStatus': http_status,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sites(self, name: Optional[Any] = None, name_hierarchy: Optional[Any] = None, type: Optional[Any] = None, units_of_measure: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None) -> Dict[str, Any]:
        """Get sites

        Get sites.

        Args:
            name (Any): Site name.
            name_hierarchy (Any): Site name hierarchy.
            type (Any): Site type.
            units_of_measure (Any): Floor units of measure
            offset (Any): The first record to show for this page; the first record is numbered 1.
            limit (Any): The number of records to show for this page.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sites'
        params = {
            'name': name,
            'nameHierarchy': name_hierarchy,
            'type': type,
            '_unitsOfMeasure': units_of_measure,
            'offset': offset,
            'limit': limit,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sda_fabrics_vlan_to_ssids_count(self) -> Dict[str, Any]:
        """Return the count of all the fabric site which has SSID to IP Pool mapping 

        Return the count of all the fabric site which has SSID to IP Pool mapping 

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/fabrics/vlanToSsids/count'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_event_subscription(self, content__type: Any) -> Dict[str, Any]:
        """Create Event Subscriptions

        Subscribe SubscriptionEndpoint to list of registered events (Deprecated)

        Args:
            content__type (Any): Content Type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/event/subscription'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_event_subscription(self, content__type: Any) -> Dict[str, Any]:
        """Update Event Subscriptions

        Update SubscriptionEndpoint to list of registered events(Deprecated)

        Args:
            content__type (Any): Content Type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/event/subscription'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_event_subscription(self, content__type: Any, subscriptions: Any) -> Dict[str, Any]:
        """Delete Event Subscriptions

        Delete EventSubscriptions

        Args:
            content__type (Any): Content Type
            subscriptions (Any): List of EventSubscriptionId's for removal

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/event/subscription'
        params = {
            'subscriptions': subscriptions,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_event_subscription(self, event_ids: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None, sort_by: Optional[Any] = None, order: Optional[Any] = None) -> Dict[str, Any]:
        """Get Event Subscriptions

        Gets the list of Subscriptions's based on provided offset and limit (Deprecated)

        Args:
            event_ids (Any): List of subscriptions related to the respective eventIds
            offset (Any): The number of Subscriptions's to offset in the resultset whose default value 0
            limit (Any): The number of Subscriptions's to limit in the resultset whose default value 10
            sort_by (Any): SortBy field name
            order (Any): order(asc/desc)

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/event/subscription'
        params = {
            'eventIds': event_ids,
            'offset': offset,
            'limit': limit,
            'sortBy': sort_by,
            'order': order,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_data_api_v1_site_health_summaries_id(self, id: Any, x__c_a_l_l_e_r__i_d: Optional[Any] = None, start_time: Optional[Any] = None, end_time: Optional[Any] = None, view: Optional[Any] = None, attribute: Optional[Any] = None) -> Dict[str, Any]:
        """Read site health summary data by site id.

        Get a health summary for a specific site by providing the unique site id in the url path.
This API provides the latest health data from a given `endTime`
If data is not ready for the provided endTime, the request will fail, and the error message will indicate the recommended endTime to use to retrieve a complete data set.
This behavior may occur if the provided endTime=currentTime, since we are not a real time system.
When `endTime` is not provided, the API returns the latest data.
This API also provides issue data. The `startTime` query param can be used to specify the beginning point of time range to retrieve the active issue counts in. When this param is not provided, the default `startTime` will be 24 hours before endTime. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-siteHealthSummaries-1.0.3-resolved.yaml


        Args:
            id (Any): unique site uuid
            x__c_a_l_l_e_r__i_d (Any): Caller ID is used to trace the origin of API calls and their associated queries executed on the database. It's an optional header parameter that can be added to an API request.

            start_time (Any): Start time from which API queries the data set related to the resource. It must be specified in UNIX epochtime in milliseconds. Value is inclusive.

If `startTime` is not provided, API will default to current time.

            end_time (Any): End time to which API queries the data set related to the resource. It must be specified in UNIX epochtime in milliseconds. Value is inclusive.

            view (Any): The specific summary view being requested. This is an optional parameter which can be passed to get one or more of the specific health data summaries associated with sites.

### Response data proviced by each view:  

1. **site**
[id, siteHierarchy, siteHierarchyId, siteType, latitude, longitude]  

2. **network**
[id, networkDeviceCount, networkDeviceGoodHealthCount,wirelessDeviceCount, wirelessDeviceGoodHealthCount, accessDeviceCount, accessDeviceGoodHealthCount, coreDeviceCount, coreDeviceGoodHealthCount, distributionDeviceCount, distributionDeviceGoodHealthCount, routerDeviceCount, routerDeviceGoodHealthCount, apDeviceCount, apDeviceGoodHealthCount, wlcDeviceCount, wlcDeviceGoodHealthCount, switchDeviceCount, switchDeviceGoodHealthCount, networkDeviceGoodHealthPercentage, accessDeviceGoodHealthPercentage, coreDeviceGoodHealthPercentage, distributionDeviceGoodHealthPercentage, routerDeviceGoodHealthPercentage, apDeviceGoodHealthPercentage, wlcDeviceGoodHealthPercentage, switchDeviceGoodHealthPercentage, wirelessDeviceGoodHealthPercentage]  

3. **client**
[id, clientCount, clientGoodHealthCount, wiredClientCount, wirelessClientCount, wiredClientGoodHealthCount, wirelessClientGoodHealthCount, clientGoodHealthPercentage, wiredClientGoodHealthPercentage, wirelessClientGoodHealthPercentage, clientDataUsage]  

4. **issue**
[id, p1IssueCount, p2IssueCount, p3IssueCount, p4IssueCount, issueCount]  

When this query parameter is not added the default summaries are:  

**[site,client,network,issue]**

Examples:

view=client (single view requested)

view=client&view=network&view=issue (multiple views requested)

            attribute (Any): Supported Attributes:

[id, siteHierarchy, siteHierarchyId, siteType, latitude, longitude, networkDeviceCount, networkDeviceGoodHealthCount,wirelessDeviceCount, wirelessDeviceGoodHealthCount, accessDeviceCount, accessDeviceGoodHealthCount, coreDeviceCount, coreDeviceGoodHealthCount, distributionDeviceCount, distributionDeviceGoodHealthCount, routerDeviceCount, routerDeviceGoodHealthCount, apDeviceCount, apDeviceGoodHealthCount, wlcDeviceCount, wlcDeviceGoodHealthCount, switchDeviceCount, switchDeviceGoodHealthCount, networkDeviceGoodHealthPercentage, accessDeviceGoodHealthPercentage, coreDeviceGoodHealthPercentage, distributionDeviceGoodHealthPercentage, routerDeviceGoodHealthPercentage, apDeviceGoodHealthPercentage, wlcDeviceGoodHealthPercentage, switchDeviceGoodHealthPercentage, wirelessDeviceGoodHealthPercentage, clientCount, clientGoodHealthCount, wiredClientCount, wirelessClientCount, wiredClientGoodHealthCount, wirelessClientGoodHealthCount, clientGoodHealthPercentage, wiredClientGoodHealthPercentage, wirelessClientGoodHealthPercentage, clientDataUsage, p1IssueCount, p2IssueCount, p3IssueCount, p4IssueCount, issueCount]

If length of attribute list is too long, please use 'view' param instead.

Examples:

attribute=siteHierarchy (single attribute requested)

attribute=siteHierarchy&attribute=clientCount (multiple attributes requested)


        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/data/api/v1/siteHealthSummaries/{id}'
        url = url.format(id=id)
        params = {
            'startTime': start_time,
            'endTime': end_time,
            'view': view,
            'attribute': attribute,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_floors_floor_id_planned_access_points(self, content__type: Any, floor_id: Any) -> Dict[str, Any]:
        """Update Planned Access Point for Floor

        Allows updating a planned access point on an existing floor map including its planned radio and antenna details.  Use the Get variant of this API to fetch the existing planned access points for the floor.  The payload to update a planned access point is in the same format, albeit a single object instead of a list, of that API.

        Args:
            content__type (Any): Request body content type
            floor_id (Any): The instance UUID of the floor hierarchy element

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/floors/{floor_id}/planned-access-points'
        url = url.format(floor_id=floor_id)
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_floors_floor_id_planned_access_points(self, floor_id: Any, limit: Optional[Any] = None, offset: Optional[Any] = None, radios: Optional[Any] = None) -> Dict[str, Any]:
        """Get Planned Access Points for Floor

        Provides a list of Planned Access Points for the Floor it is requested for

        Args:
            floor_id (Any): The instance UUID of the floor hierarchy element
            limit (Any): The page size limit for the response, e.g. limit=100 will return a maximum of 100 records
            offset (Any): The page offset for the response. E.g. if limit=100, offset=0 will return first 100 records, offset=1 will return next 100 records, etc.
            radios (Any): Whether to include the planned radio details of the planned access points

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/floors/{floor_id}/planned-access-points'
        url = url.format(floor_id=floor_id)
        params = {
            'limit': limit,
            'offset': offset,
            'radios': radios,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_floors_floor_id_planned_access_points(self, content__type: Any, floor_id: Any) -> Dict[str, Any]:
        """Create Planned Access Point for Floor

        Allows creation of a new planned access point on an existing floor map including its planned radio and antenna details.  Use the Get variant of this API to fetch any existing planned access points for the floor.  The payload to create a planned access point is in the same format, albeit a single object instead of a list, of that API.

        Args:
            content__type (Any): Request body content type
            floor_id (Any): The instance UUID of the floor hierarchy element

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/floors/{floor_id}/planned-access-points'
        url = url.format(floor_id=floor_id)
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_device_replacement(self, content__type: Any) -> Dict[str, Any]:
        """UnMark device for replacement

        UnMarks device for replacement

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/device-replacement'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_device_replacement(self, content__type: Any) -> Dict[str, Any]:
        """Mark device for replacement

        Marks device for replacement

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/device-replacement'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_device_replacement(self, faulty_device_name: Optional[Any] = None, faulty_device_platform: Optional[Any] = None, replacement_device_platform: Optional[Any] = None, faulty_device_serial_number: Optional[Any] = None, replacement_device_serial_number: Optional[Any] = None, replacement_status: Optional[Any] = None, family: Optional[Any] = None, sort_by: Optional[Any] = None, sort_order: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None) -> Dict[str, Any]:
        """Return list of replacement devices with replacement details

        Get list of replacement devices with replacement details and it can filter replacement devices based on Faulty Device Name,Faulty Device Platform, Replacement Device Platform, Faulty Device Serial Number,Replacement Device Serial Number, Device Replacement status, Product Family.

        Args:
            faulty_device_name (Any): Faulty Device Name
            faulty_device_platform (Any): Faulty Device Platform
            replacement_device_platform (Any): Replacement Device Platform
            faulty_device_serial_number (Any): Faulty Device Serial Number
            replacement_device_serial_number (Any): Replacement Device Serial Number
            replacement_status (Any): Device Replacement status [READY-FOR-REPLACEMENT, REPLACEMENT-IN-PROGRESS, REPLACEMENT-SCHEDULED, REPLACED, ERROR, NETWORK_READINESS_REQUESTED, NETWORK_READINESS_FAILED]
            family (Any): List of families[Routers, Switches and Hubs, AP]
            sort_by (Any): SortBy this field. SortBy is mandatory when order is used.
            sort_order (Any): Order on displayName[ASC,DESC]
            offset (Any): offset
            limit (Any): limit

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/device-replacement'
        params = {
            'faultyDeviceName': faulty_device_name,
            'faultyDevicePlatform': faulty_device_platform,
            'replacementDevicePlatform': replacement_device_platform,
            'faultyDeviceSerialNumber': faulty_device_serial_number,
            'replacementDeviceSerialNumber': replacement_device_serial_number,
            'replacementStatus': replacement_status,
            'family': family,
            'sortBy': sort_by,
            'sortOrder': sort_order,
            'offset': offset,
            'limit': limit,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_discovery_id(self, id: Any) -> Dict[str, Any]:
        """Delete discovery by Id

        Stops the discovery for the given Discovery ID and removes it. Discovery ID can be obtained using the "Get Discoveries by range" API.

        Args:
            id (Any): Discovery ID

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/discovery/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_discovery_id(self, id: Any) -> Dict[str, Any]:
        """Get Discovery by Id

        Returns discovery by Discovery ID. Discovery ID can be obtained using the "Get Discoveries by range" API.

        Args:
            id (Any): Discovery ID

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/discovery/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_device_config(self, device_id: Optional[Any] = None, file_type: Optional[Any] = None, created_time: Optional[Any] = None, created_by: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None) -> Dict[str, Any]:
        """Get configuration archive details

        Returns the historical device configurations (running configuration , startup configuration , vlan if applicable) by specified criteria

        Args:
            device_id (Any): comma separated device id for example cf35b0a1-407f-412f-b2f4-f0c3156695f9,aaa38191-0c22-4158-befd-779a09d7cec1 . if device id is not provided it will fetch for all devices
            file_type (Any): Config File Type can be RUNNINGCONFIG or STARTUPCONFIG
            created_time (Any): Supported with logical filters GT,GTE,LT,LTE & BT : time in milliseconds (epoc format)
            created_by (Any): Comma separated values for createdBy - SCHEDULED, USER, CONFIG_CHANGE_EVENT, SCHEDULED_FIRST_TIME, DR_CALL_BACK, PRE_DEPLOY
            offset (Any): offset
            limit (Any): limit

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device-config'
        params = {
            'deviceId': device_id,
            'fileType': file_type,
            'createdTime': created_time,
            'createdBy': created_by,
            'offset': offset,
            'limit': limit,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_global_credential_http_write(self, content__type: Any) -> Dict[str, Any]:
        """Create HTTP write credentials

        Adds global HTTP write credentials

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/global-credential/http-write'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_global_credential_http_write(self, content__type: Any) -> Dict[str, Any]:
        """Update HTTP write credentials

        Updates global HTTP write credentials

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/global-credential/http-write'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_security_advisory_device_device_id_advisory(self, device_id: Any) -> Dict[str, Any]:
        """Get Advisories Per Device

        Retrieves list of advisories for a device

        Args:
            device_id (Any): Device instance UUID

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/security-advisory/device/{device_id}/advisory'
        url = url.format(device_id=device_id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_interface_count(self) -> Dict[str, Any]:
        """Get Device Interface Count for Multiple Devices

        Returns the count of interfaces for all devices

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/interface/count'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_diagnostic_validation_workflows_count(self, start_time: Optional[Any] = None, end_time: Optional[Any] = None, run_status: Optional[Any] = None) -> Dict[str, Any]:
        """Retrieves the count of validation workflows

        Retrieves the count of workflows that have been successfully submitted and are currently available. 


        Args:
            start_time (Any): Workflows started after the given time (as milliseconds since UNIX epoch).
            end_time (Any): Workflows started before the given time (as milliseconds since UNIX epoch).
            run_status (Any): Execution status of the workflow. If the workflow is successfully submitted, runStatus is `PENDING`. If the workflow execution has started, runStatus is `IN_PROGRESS`. If the workflow executed is completed with all validations executed, runStatus is `COMPLETED`. If the workflow execution fails while running validations, runStatus is `FAILED`.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/diagnosticValidationWorkflows/count'
        params = {
            'startTime': start_time,
            'endTime': end_time,
            'runStatus': run_status,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_snmp_property(self) -> Dict[str, Any]:
        """Get SNMP properties

        Returns SNMP properties

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/snmp-property'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_snmp_property(self, content__type: Any) -> Dict[str, Any]:
        """Create/Update SNMP properties

        Adds SNMP properties

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/snmp-property'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_compliance_detail_count(self, compliance_type: Optional[Any] = None, compliance_status: Optional[Any] = None) -> Dict[str, Any]:
        """Get Compliance Detail Count

        Return  Compliance Count Detail

        Args:
            compliance_type (Any): Specify "Compliance type(s)" separated by commas. The Compliance type can be 'APPLICATION_VISIBILITY', 'EOX', 'FABRIC', 'IMAGE', 'NETWORK_PROFILE', 'NETWORK_SETTINGS', 'PSIRT', 'RUNNING_CONFIG', 'WORKFLOW'. 
            compliance_status (Any): Specify "Compliance status(es)" separated by commas. The Compliance status can be 'COMPLIANT', 'NON_COMPLIANT', 'IN_PROGRESS', 'NOT_AVAILABLE', 'NOT_APPLICABLE', 'ERROR'.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/compliance/detail/count'
        params = {
            'complianceType': compliance_type,
            'complianceStatus': compliance_status,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_data_api_v1_interfaces_query(self, content__type: Any) -> Dict[str, Any]:
        """Gets the list of interfaces across the Network Devices based on the provided complex filters and aggregation functions

        Gets the list of interfaces across the Network Devices based on the provided complex filters and aggregation functions

The elements are grouped and sorted by deviceUuid first, and are then sorted by the given sort field, or by the default value: name.

The supported sorting options are: name, adminStatus, description, duplexConfig, duplexOper, interfaceIfIndex,interfaceType, macAddress,mediaType, operStatus, portChannelId, portMode, portType,speed, vlanId. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-interfaces-1.0.2-resolved.yaml

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/data/api/v1/interfaces/query'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_client_health(self, timestamp: Optional[Any] = None) -> Dict[str, Any]:
        """Get Overall Client Health

        Returns Overall Client Health information by Client type (Wired and Wireless) for any given point of time

        Args:
            timestamp (Any): Epoch time(in milliseconds) when the Client health data is required

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/client-health'
        params = {
            'timestamp': timestamp,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_device_device_uuid_line_card(self, device_uuid: Any) -> Dict[str, Any]:
        """Get Linecard details

        Get line card detail for a given deviceuuid.  Response will contain serial no, part no, switch no and slot no.

        Args:
            device_uuid (Any): instanceuuid of device

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device/{device_uuid}/line-card'
        url = url.format(device_uuid=device_uuid)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_data_api_v1_interfaces_count(self, start_time: Optional[Any] = None, end_time: Optional[Any] = None, site_hierarchy: Optional[Any] = None, site_hierarchy_id: Optional[Any] = None, site_id: Optional[Any] = None, network_device_id: Optional[Any] = None, network_device_ip_address: Optional[Any] = None, network_device_mac_address: Optional[Any] = None, interface_id: Optional[Any] = None, interface_name: Optional[Any] = None) -> Dict[str, Any]:
        """Gets the total Network device interface counts in the specified time range. When there is no start and end time specified returns the latest interfaces total count.

        Gets the total Network device interface counts. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-interfaces-1.0.2-resolved.yaml

        Args:
            start_time (Any): Start time from which API queries the data set related to the resource. It must be specified in UNIX epochtime in milliseconds. Value is inclusive.

If `startTime` is not provided, API will default to current time.

            end_time (Any): End time to which API queries the data set related to the resource. It must be specified in UNIX epochtime in milliseconds. Value is inclusive.

            site_hierarchy (Any): The full hierarchical breakdown of the site tree starting from Global site name and ending with the specific site name. The Root site is named "Global" (Ex. `Global/AreaName/BuildingName/FloorName`)

This field supports wildcard asterisk (`*`) character search support. E.g. `*/San*, */San, /San*`

Examples:

`?siteHierarchy=Global/AreaName/BuildingName/FloorName` (single siteHierarchy requested)

`?siteHierarchy=Global/AreaName/BuildingName/FloorName&siteHierarchy=Global/AreaName2/BuildingName2/FloorName2` (multiple siteHierarchies requested)

            site_hierarchy_id (Any): The full hierarchy breakdown of the site tree in id form starting from Global site UUID and ending with the specific site UUID. (Ex. `globalUuid/areaUuid/buildingUuid/floorUuid`)

This field supports wildcard asterisk (`*`) character search support. E.g. `*uuid*, *uuid, uuid*`

Examples:

`?siteHierarchyId=globalUuid/areaUuid/buildingUuid/floorUuid `(single siteHierarchyId requested)

`?siteHierarchyId=globalUuid/areaUuid/buildingUuid/floorUuid&siteHierarchyId=globalUuid/areaUuid2/buildingUuid2/floorUuid2` (multiple siteHierarchyIds requested)

            site_id (Any): The UUID of the site. (Ex. `flooruuid`)

Examples:

`?siteId=id1` (single id requested)

`?siteId=id1&siteId=id2&siteId=id3` (multiple ids requested)

            network_device_id (Any): The list of Network Device Uuids. (Ex. `6bef213c-19ca-4170-8375-b694e251101c`)

Examples:

`networkDeviceId=6bef213c-19ca-4170-8375-b694e251101c` (single networkDeviceId requested)

`networkDeviceId=6bef213c-19ca-4170-8375-b694e251101c&networkDeviceId=32219612-819e-4b5e-a96b-cf22aca13dd9&networkDeviceId=2541e9a7-b80d-4955-8aa2-79b233318ba0` (multiple networkDeviceIds with & separator)

            network_device_ip_address (Any): The list of Network Device management IP Address. (Ex. `121.1.1.10`)

This field supports wildcard (`*`) character-based search. 
Ex: `*1.1*` or `1.1*` or `*1.1`

Examples:

`networkDeviceIpAddress=121.1.1.10`

`networkDeviceIpAddress=121.1.1.10&networkDeviceIpAddress=172.20.1.10&networkDeviceIpAddress=10.10.20.10` (multiple networkDevice IP Address with & separator)

            network_device_mac_address (Any): The list of Network Device MAC Address. (Ex. `64:f6:9d:07:9a:00`)

This field supports wildcard (`*`) character-based search. 
Ex: `*AB:AB:AB*` or `AB:AB:AB*` or `*AB:AB:AB`

Examples:

`networkDeviceMacAddress=64:f6:9d:07:9a:00`

`networkDeviceMacAddress=64:f6:9d:07:9a:00&networkDeviceMacAddress=70:56:9d:07:ac:77` (multiple networkDevice MAC addresses with & separator)

            interface_id (Any): The list of Interface Uuids. (Ex. `6bef213c-19ca-4170-8375-b694e251101c`)

Examples:

`interfaceId=6bef213c-19ca-4170-8375-b694e251101c` (single interface uuid )

`interfaceId=6bef213c-19ca-4170-8375-b694e251101c&32219612-819e-4b5e-a96b-cf22aca13dd9&2541e9a7-b80d-4955-8aa2-79b233318ba0` (multiple Interface uuid with & separator)

            interface_name (Any): The list of Interface name (Ex. `GigabitEthernet1/0/1`)
This field supports wildcard (`*`) character-based search. 
Ex: `*1/0/1*` or `1/0/1*` or `*1/0/1`

Examples:

`interfaceNames=GigabitEthernet1/0/1` (single interface name)

`interfaceNames=GigabitEthernet1/0/1&GigabitEthernet2/0/1&GigabitEthernet3/0/1` (multiple interface names with & separator)


        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/data/api/v1/interfaces/count'
        params = {
            'startTime': start_time,
            'endTime': end_time,
            'siteHierarchy': site_hierarchy,
            'siteHierarchyId': site_hierarchy_id,
            'siteId': site_id,
            'networkDeviceId': network_device_id,
            'networkDeviceIpAddress': network_device_ip_address,
            'networkDeviceMacAddress': network_device_mac_address,
            'interfaceId': interface_id,
            'interfaceName': interface_name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_wireless_profiles_count(self) -> Dict[str, Any]:
        """Get Wireless Profiles Count

        This API allows the user to get count of all wireless profiles

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/wirelessProfiles/count'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_tag_id(self, id: Any) -> Dict[str, Any]:
        """Delete Tag

        Deletes a tag specified by id

        Args:
            id (Any): Tag ID

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/tag/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_tag_id(self, id: Any) -> Dict[str, Any]:
        """Get Tag by Id

        Returns tag specified by Id

        Args:
            id (Any): Tag ID

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/tag/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_data_api_v1_event_event_series_audit_log_summary(self, parent_instance_id: Optional[Any] = None, is_parent_only: Optional[Any] = None, instance_id: Optional[Any] = None, name: Optional[Any] = None, event_id: Optional[Any] = None, category: Optional[Any] = None, severity: Optional[Any] = None, domain: Optional[Any] = None, sub_domain: Optional[Any] = None, source: Optional[Any] = None, user_id: Optional[Any] = None, context: Optional[Any] = None, event_hierarchy: Optional[Any] = None, site_id: Optional[Any] = None, device_id: Optional[Any] = None, is_system_events: Optional[Any] = None, description: Optional[Any] = None, start_time: Optional[Any] = None, end_time: Optional[Any] = None) -> Dict[str, Any]:
        """Get AuditLog Summary

        Get Audit Log Summary from the Event-Hub

        Args:
            parent_instance_id (Any): Parent Audit Log record's instanceID.
            is_parent_only (Any): Parameter to filter parent only audit-logs.
            instance_id (Any): InstanceID of the Audit Log.
            name (Any): Audit Log notification event name.
            event_id (Any): Audit Log notification's event ID. 
            category (Any): Audit Log notification's event category. Supported values: INFO, WARN, ERROR, ALERT, TASK_PROGRESS, TASK_FAILURE, TASK_COMPLETE, COMMAND, QUERY, CONVERSATION
            severity (Any): Audit Log notification's event severity. Supported values: 1, 2, 3, 4, 5.
            domain (Any): Audit Log notification's event domain.
            sub_domain (Any): Audit Log notification's event sub-domain.
            source (Any): Audit Log notification's event source.
            user_id (Any): Audit Log notification's event userId.
            context (Any): Audit Log notification's event correlationId.
            event_hierarchy (Any): Audit Log notification's event eventHierarchy. Example: "US.CA.San Jose" OR "US.CA" OR "CA.San Jose" - Delimiter for hierarchy separation is ".".
            site_id (Any): Audit Log notification's siteId.
            device_id (Any): Audit Log notification's deviceId.
            is_system_events (Any): Parameter to filter system generated audit-logs.
            description (Any): String full/partial search - (Provided input string is case insensitively matched for records).
            start_time (Any): Start Time in milliseconds since Epoch Eg. 1597950637211 (when provided endTime is mandatory)
            end_time (Any): End Time in milliseconds since Epoch Eg. 1597961437211 (when provided startTime is mandatory)

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/data/api/v1/event/event-series/audit-log/summary'
        params = {
            'parentInstanceId': parent_instance_id,
            'isParentOnly': is_parent_only,
            'instanceId': instance_id,
            'name': name,
            'eventId': event_id,
            'category': category,
            'severity': severity,
            'domain': domain,
            'subDomain': sub_domain,
            'source': source,
            'userId': user_id,
            'context': context,
            'eventHierarchy': event_hierarchy,
            'siteId': site_id,
            'deviceId': device_id,
            'isSystemEvents': is_system_events,
            'description': description,
            'startTime': start_time,
            'endTime': end_time,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_sda_anycast_gateways_id(self, id: Any) -> Dict[str, Any]:
        """Delete anycast gateway by id

        Deletes an anycast gateway based on id.

        Args:
            id (Any): ID of the anycast gateway.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/anycastGateways/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_template_programmer_project_name_project_name_template_importtemplates(self, content__type: Any, project_name: Any, do_version: Optional[Any] = None) -> Dict[str, Any]:
        """Imports the templates provided

        Imports the templates provided in the DTO by project Name

        Args:
            content__type (Any): Request body content type
            project_name (Any): Project name to create template under the project
            do_version (Any): If this flag is true then it creates a new version of the template with the imported contents in case if the templates already exists. "
If this flag is false and if template already exists, then operation fails with 'Template already exists' error

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/template-programmer/project/name/{project_name}/template/importtemplates'
        url = url.format(project_name=project_name)
        params = {
            'doVersion': do_version,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def post_dna_intent_api_v2_network_site_id(self, site_id: Any) -> Dict[str, Any]:
        """Create Network V2

        API to create network settings for DHCP,  Syslog, SNMP, NTP, Network AAA, Client and Endpoint AAA, and/or DNS center server settings.

        Args:
            site_id (Any): Site Id to which site details to associate with the network settings.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v2/network/{site_id}'
        url = url.format(site_id=site_id)
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def put_dna_intent_api_v2_network_site_id(self, site_id: Any) -> Dict[str, Any]:
        """Update Network V2

        API to update network settings for DHCP, Syslog, SNMP, NTP, Network AAA, Client and Endpoint AAA, and/or DNS center server settings.

        Args:
            site_id (Any): Site Id to update the network settings which is associated with the site

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v2/network/{site_id}'
        url = url.format(site_id=site_id)
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def post_dna_data_api_v1_flexible_report_report_report_id_execute(self, content__type: Any, report_id: Any) -> Dict[str, Any]:
        """Executing the Flexible report

        This API is used for executing the report

        Args:
            content__type (Any): Request body content type
            report_id (Any): Id of the Report

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/data/api/v1/flexible-report/report/{report_id}/execute'
        url = url.format(report_id=report_id)
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_qos_device_interface_info_id(self, id: Any) -> Dict[str, Any]:
        """Delete Qos Device Interface Info

        Delete all qos device interface infos associate with network device id

        Args:
            id (Any): Id of the qos device info, this object holds all qos device interface infos associate with network device id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/qos-device-interface-info/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_template_programmer_project(self, name: Optional[Any] = None, sort_order: Optional[Any] = None) -> Dict[str, Any]:
        """Gets a list of projects

        List the projects

        Args:
            name (Any): Name of project to be searched
            sort_order (Any): Sort Order Ascending (asc) or Descending (des)

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/template-programmer/project'
        params = {
            'name': name,
            'sortOrder': sort_order,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_template_programmer_project(self, content__type: Any) -> Dict[str, Any]:
        """Create Project

        This API is used to create a new project.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/template-programmer/project'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_template_programmer_project(self, content__type: Any) -> Dict[str, Any]:
        """Update Project

        This API is used to update an existing project.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/template-programmer/project'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_network_device_archive_cleartext(self, content__type: Any) -> Dict[str, Any]:
        """Export Device configurations

        Export Device configurations to an encrypted zip file

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/network-device-archive/cleartext'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def post_dna_intent_api_v2_lan_automation(self, content__type: Any) -> Dict[str, Any]:
        """LAN Automation Start V2

        Invoke V2 LAN Automation Start API, which supports optional auto-stop processing feature based on the provided timeout or a specific device list, or both. The stop processing will be executed automatically when either of the cases is satisfied, without specifically calling the stop API. The V2 API behaves similarly to V1 if no timeout or device list is provided, and the user needs to call the stop API for LAN Automation stop processing. With the V2 API, the user can also specify the level up to which the devices can be LAN automated.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v2/lan-automation'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_diagnostics_system_health_count(self, domain: Optional[Any] = None, subdomain: Optional[Any] = None) -> Dict[str, Any]:
        """System Health Count API

        This API gives the count of the latest system events

        Args:
            domain (Any): Fetch system events with this domain. Possible values of domain are listed here : /dna/platform/app/consumer-portal/developer-toolkit/events
            subdomain (Any): Fetch system events with this subdomain. Possible values of subdomain are listed here : /dna/platform/app/consumer-portal/developer-toolkit/events

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/diagnostics/system/health/count'
        params = {
            'domain': domain,
            'subdomain': subdomain,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_authentication_policy_servers(self) -> Dict[str, Any]:
        """Add Authentication and Policy Server Access Configuration

        API to add AAA/ISE server access configuration. Protocol can be configured as either RADIUS OR TACACS OR RADIUS_TACACS. If configuring Cisco ISE server, after configuration, use ‘Cisco ISE Server Integration Status’ Intent API to check the integration status. Based on integration status, if require use 'Accept Cisco ISE Server Certificate for Cisco ISE Server Integration' Intent API to accept the Cisco ISE certificate for Cisco ISE server integration, then use again ‘Cisco ISE Server Integration Status’ Intent API to check the integration status.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/authentication-policy-servers'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_authentication_policy_servers(self, is_ise_enabled: Optional[Any] = None, state: Optional[Any] = None, role: Optional[Any] = None) -> Dict[str, Any]:
        """Get Authentication and Policy Servers

        API to get Authentication and Policy Servers

        Args:
            is_ise_enabled (Any): Valid values are : true, false
            state (Any): Valid values are: ACTIVE, INACTIVE, RBAC_SUCCESS, RBAC_FAILURE, DELETED, FAILED, INPROGRESS
            role (Any): Authentication and Policy Server Role (Example: primary, secondary)

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/authentication-policy-servers'
        params = {
            'isIseEnabled': is_ise_enabled,
            'state': state,
            'role': role,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sites_site_id_wireless_settings_ssids_count(self, site_id: Any) -> Dict[str, Any]:
        """Get SSID Count by Site

        This API allows the user to get count of all SSIDs (Service Set Identifier) present at global site. 

        Args:
            site_id (Any): Site UUID

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sites/{site_id}/wirelessSettings/ssids/count'
        url = url.format(site_id=site_id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_licenses_device_summary(self, page_number: Any, order: Any, limit: Any, sort_by: Optional[Any] = None, dna_level: Optional[Any] = None, device_type: Optional[Any] = None, registration_status: Optional[Any] = None, virtual_account_name: Optional[Any] = None, smart_account_id: Optional[Any] = None, device_uuid: Optional[Any] = None) -> Dict[str, Any]:
        """Device License Summary

        Show license summary of device(s).

        Args:
            page_number (Any): Page number of response
            order (Any): Sorting order
            limit (Any): Limit
            sort_by (Any): Sort result by field
            dna_level (Any): Device Cisco DNA license level. The valid values are Advantage, Essentials
            device_type (Any): Type of device. The valid values are Routers, Switches and Hubs, Wireless Controller
            registration_status (Any): Smart license registration status of device. The valid values are Unknown, NA, Unregistered, Registered, Registration_expired, Reservation_in_progress, Registered_slr, Registered_plr, Registered_satellite
            virtual_account_name (Any): Name of virtual account
            smart_account_id (Any): Id of smart account
            device_uuid (Any): Id of device

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/licenses/device/summary'
        params = {
            'page_number': page_number,
            'order': order,
            'limit': limit,
            'sort_by': sort_by,
            'dna_level': dna_level,
            'device_type': device_type,
            'registration_status': registration_status,
            'virtual_account_name': virtual_account_name,
            'smart_account_id': smart_account_id,
            'device_uuid': device_uuid,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_maps_import_import_context_uuid(self, import_context_uuid: Any) -> Dict[str, Any]:
        """Import Map Archive - Cancel an Import

        Cancels a previously initatied import, allowing the system to cleanup cached resources about that import data, and ensures the import cannot accidentally be performed / approved at a later time.

        Args:
            import_context_uuid (Any): The unique import context UUID given by a previous call to Start Import API

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/maps/import/{import_context_uuid}'
        url = url.format(import_context_uuid=import_context_uuid)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_compliance_device_uuid_detail(self, device_uuid: Any, category: Optional[Any] = None, compliance_type: Optional[Any] = None, diff_list: Optional[Any] = None) -> Dict[str, Any]:
        """Compliance Details of Device

        Return compliance detailed report for a device.

        Args:
            device_uuid (Any): Device Id
            category (Any): category can have any value among 'INTENT', 'RUNNING_CONFIG' , 'IMAGE' , 'PSIRT' , 'DESIGN_OOD' , 'EOX' , 'NETWORK_SETTINGS'
            compliance_type (Any): Specify "Compliance type(s)" separated by commas. The Compliance type can be 'APPLICATION_VISIBILITY', 'EOX', 'FABRIC', 'IMAGE', 'NETWORK_PROFILE', 'NETWORK_SETTINGS', 'PSIRT', 'RUNNING_CONFIG', 'WORKFLOW'. 
            diff_list (Any): diff list [ pass true to fetch the diff list ]

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/compliance/{device_uuid}/detail'
        url = url.format(device_uuid=device_uuid)
        params = {
            'category': category,
            'complianceType': compliance_type,
            'diffList': diff_list,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_profiles_for_sites_profile_id_site_assignments_count(self, profile_id: Any) -> Dict[str, Any]:
        """Retrieves the count of sites that the given network profile for sites is assigned to

        Retrieves the count of sites that the given network profile for sites is assigned to.

        Args:
            profile_id (Any): The `id` of the network profile, retrievable from `GET /intent/api/v1/networkProfilesForSites`

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/networkProfilesForSites/{profile_id}/siteAssignments/count'
        url = url.format(profile_id=profile_id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_sda_provision_devices(self, network_device_id: Optional[Any] = None, site_id: Optional[Any] = None) -> Dict[str, Any]:
        """Delete provisioned devices

        Delete provisioned devices based on query parameters.

        Args:
            network_device_id (Any): ID of the network device.
            site_id (Any): ID of the site hierarchy.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/provisionDevices'
        params = {
            'networkDeviceId': network_device_id,
            'siteId': site_id,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_sda_provision_devices(self, content__type: Any) -> Dict[str, Any]:
        """Provision devices

        Provisions network devices to respective Sites based on user input.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sda/provisionDevices'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sda_provision_devices(self, id: Optional[Any] = None, network_device_id: Optional[Any] = None, site_id: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None) -> Dict[str, Any]:
        """Get provisioned devices

        Returns the list of provisioned devices based on query parameters.

        Args:
            id (Any): ID of the provisioned device.
            network_device_id (Any): ID of the network device.
            site_id (Any): ID of the site hierarchy.
            offset (Any): Starting record for pagination.
            limit (Any): Maximum number of devices to return.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/provisionDevices'
        params = {
            'id': id,
            'networkDeviceId': network_device_id,
            'siteId': site_id,
            'offset': offset,
            'limit': limit,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_sda_provision_devices(self, content__type: Any) -> Dict[str, Any]:
        """Re-provision devices

        Re-provisions network devices to the site based on the user input.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sda/provisionDevices'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_sda_port_channels_id(self, id: Any) -> Dict[str, Any]:
        """Delete port channel by id

        Deletes a port channel based on id.

        Args:
            id (Any): ID of the port channel.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/portChannels/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_flow_analysis(self, periodic_refresh: Optional[Any] = None, source_i_p: Optional[Any] = None, dest_i_p: Optional[Any] = None, source_port: Optional[Any] = None, dest_port: Optional[Any] = None, gt_create_time: Optional[Any] = None, lt_create_time: Optional[Any] = None, protocol: Optional[Any] = None, status: Optional[Any] = None, task_id: Optional[Any] = None, last_update_time: Optional[Any] = None, limit: Optional[Any] = None, offset: Optional[Any] = None, order: Optional[Any] = None, sort_by: Optional[Any] = None) -> Dict[str, Any]:
        """Retrieves all previous Pathtraces summary

        Returns a summary of all flow analyses stored. Results can be filtered by specified parameters.

        Args:
            periodic_refresh (Any): Is analysis periodically refreshed?
            source_i_p (Any): Source IP address
            dest_i_p (Any): Destination IP address
            source_port (Any): Source port
            dest_port (Any): Destination port
            gt_create_time (Any): Analyses requested after this time
            lt_create_time (Any): Analyses requested before this time
            protocol (Any): Protocol
            status (Any): Status
            task_id (Any): Task ID
            last_update_time (Any): Last update time
            limit (Any): Number of resources returned
            offset (Any): Start index of resources returned (1-based)
            order (Any): Order by this field
            sort_by (Any): Sort by this field

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/flow-analysis'
        params = {
            'periodicRefresh': periodic_refresh,
            'sourceIP': source_i_p,
            'destIP': dest_i_p,
            'sourcePort': source_port,
            'destPort': dest_port,
            'gtCreateTime': gt_create_time,
            'ltCreateTime': lt_create_time,
            'protocol': protocol,
            'status': status,
            'taskId': task_id,
            'lastUpdateTime': last_update_time,
            'limit': limit,
            'offset': offset,
            'order': order,
            'sortBy': sort_by,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_flow_analysis(self, content__type: Any) -> Dict[str, Any]:
        """Initiate a new Pathtrace

        Initiates a new flow analysis with periodic refresh and stat collection options. Returns a request id and a task id to get results and follow progress.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/flow-analysis'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_network_device_config_write_memory(self, content__type: Any) -> Dict[str, Any]:
        """Commit device configuration

        This operation would commit device running configuration to startup by issuing "write memory" to device

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/network-device-config/write-memory'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def put_dna_system_api_v1_role(self, content__type: Any) -> Dict[str, Any]:
        """Update role API

        Update a role in Cisco DNA Center System.

        Args:
            content__type (Any): The format of the payload

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/system/api/v1/role'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def post_dna_system_api_v1_role(self, content__type: Any) -> Dict[str, Any]:
        """Add role API

        Add a new role in Cisco DNA Center System.

        Args:
            content__type (Any): The format of the payload

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/system/api/v1/role'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_device_insight_site_id_device_link(self, site_id: Any, category: Any, offset: Optional[Any] = None, limit: Optional[Any] = None, sort_by: Optional[Any] = None, order: Optional[Any] = None) -> Dict[str, Any]:
        """Inventory Insight Device Link Mismatch API

        Find all devices with link mismatch (speed /  vlan)

        Args:
            site_id (Any): siteId
            category (Any): Links mismatch category.  Value can be speed-duplex or vlan.
            offset (Any): Row Number.  Default value is 1
            limit (Any): Default value is 500
            sort_by (Any): Sort By
            order (Any): Order.  Value can be asc or desc.  Default value is asc

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device/insight/{site_id}/device-link'
        url = url.format(site_id=site_id)
        params = {
            'category': category,
            'offset': offset,
            'limit': limit,
            'sortBy': sort_by,
            'order': order,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_onboarding_pnp_device_site_claim(self, content__type: Any) -> Dict[str, Any]:
        """Claim a Device to a Site

        Claim a device based on Catalyst Center Site-based design process. Some required parameters differ based on device platform:

Default/StackSwitch: imageInfo, configInfo.  

AccessPoints: rfProfile.  

Sensors: sensorProfile.  

CatalystWLC/MobilityExpress/EWC: staticIP, subnetMask, gateway. vlanId and ipInterfaceName are also allowed for Catalyst 9800 WLCs.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/onboarding/pnp-device/site-claim'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_data_api_v1_network_devices_id(self, id: Any, start_time: Optional[Any] = None, end_time: Optional[Any] = None, view: Optional[Any] = None, attribute: Optional[Any] = None) -> Dict[str, Any]:
        """Get the device data for the given device id (Uuid)

        Returns the device data for the given device Uuid in the specified start and end time range. When there is no start and end time specified returns the latest available data for the given Id. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-AssuranceNetworkDevices-1.0.2-resolved.yaml

        Args:
            id (Any): The device Uuid
            start_time (Any): Start time from which API queries the data set related to the resource. It must be specified in UNIX epochtime in milliseconds. Value is inclusive.

If `startTime` is not provided, API will default to current time.

            end_time (Any): End time to which API queries the data set related to the resource. It must be specified in UNIX epochtime in milliseconds. Value is inclusive.

            view (Any): The List of Network Device model views. Please refer to ```NetworkDeviceView``` for the supported list
            attribute (Any): The List of Network Device model attributes. This is helps to specify the interested fields in the request.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/data/api/v1/networkDevices/{id}'
        url = url.format(id=id)
        params = {
            'startTime': start_time,
            'endTime': end_time,
            'view': view,
            'attribute': attribute,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_lan_automation_log_id(self, id: Any) -> Dict[str, Any]:
        """LAN Automation Log by Id

        Invoke this API to get the LAN Automation session logs based on the given LAN Automation session id.

        Args:
            id (Any): LAN Automation session identifier.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/lan-automation/log/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_sites_id_device_credentials(self, content__type: Any, id: Any) -> Dict[str, Any]:
        """Update device credential settings for a site.

        Updates device credential settings for a site; `null` values indicate that the setting will be inherited from the parent site; empty objects (`{}`) indicate that the credential is unset, and that no credential of that type will be used for the site.

        Args:
            content__type (Any): Request body content type
            id (Any): Site Id, retrievable from the `id` attribute in `/dna/intent/api/v1/sites`

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sites/{id}/deviceCredentials'
        url = url.format(id=id)
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sites_id_device_credentials(self, id: Any, inherited: Optional[Any] = None) -> Dict[str, Any]:
        """Get device credential settings for a site

        Gets device credential settings for a site; `null` values indicate that the setting will be inherited from the parent site; empty objects (`{}`) indicate that the credential is unset, and that no credential of that type will be used for the site.

        Args:
            id (Any): Site Id, retrievable from the `id` attribute in `/dna/intent/api/v1/sites`
            inherited (Any): Include settings explicitly set for this site and settings inherited from sites higher in the site hierarchy; when `false`, `null` values indicate that the site inherits that setting from the parent site or a site higher in the site hierarchy.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sites/{id}/deviceCredentials'
        url = url.format(id=id)
        params = {
            '_inherited': inherited,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_discovery(self, content__type: Any) -> Dict[str, Any]:
        """Start discovery

        Initiates discovery with the given parameters

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/discovery'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_discovery(self, content__type: Any) -> Dict[str, Any]:
        """Updates an existing discovery by specified Id

        Stops or starts an existing discovery

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/discovery'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_discovery(self) -> Dict[str, Any]:
        """Delete all discovery

        Stops all the discoveries and removes them

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/discovery'
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_interface_network_device_device_id_count(self, device_id: Any) -> Dict[str, Any]:
        """Get Device Interface count

        Returns the interface count for the given device

        Args:
            device_id (Any): Device ID

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/interface/network-device/{device_id}/count'
        url = url.format(device_id=device_id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_dnac_release(self) -> Dict[str, Any]:
        """Cisco DNA Center Release Summary

        Provides information such as API version, mandatory core packages for installation or upgrade, optional packages, Cisco DNA Center name and version, supported direct updates, and tenant ID. 

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/dnac-release'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_image_importation_golden(self, accept: Optional[Any] = None, content__type: Optional[Any] = None) -> Dict[str, Any]:
        """Tag as Golden Image

        Golden Tag image. Set siteId as -1 for Global site.

        Args:
            accept (Any): MIME type / MIME subtype Consumed
            content__type (Any): MIME type / MIME subtype Produced

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if accept is not None:
            request_headers['Accept'] = str(accept)
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/image/importation/golden'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sda_layer2_virtual_networks_count(self, fabric_id: Optional[Any] = None, vlan_name: Optional[Any] = None, vlan_id: Optional[Any] = None, traffic_type: Optional[Any] = None, associated_layer3_virtual_network_name: Optional[Any] = None) -> Dict[str, Any]:
        """Get layer 2 virtual network count

        Returns the count of layer 2 virtual networks that match the provided query parameters.

        Args:
            fabric_id (Any): ID of the fabric the layer 2 virtual network is assigned to.
            vlan_name (Any): The vlan name of the layer 2 virtual network.
            vlan_id (Any): The vlan ID of the layer 2 virtual network.
            traffic_type (Any): The traffic type of the layer 2 virtual network.
            associated_layer3_virtual_network_name (Any): Name of the associated layer 3 virtual network.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/layer2VirtualNetworks/count'
        params = {
            'fabricId': fabric_id,
            'vlanName': vlan_name,
            'vlanId': vlan_id,
            'trafficType': traffic_type,
            'associatedLayer3VirtualNetworkName': associated_layer3_virtual_network_name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_sites_device_credentials_apply(self, content__type: Any) -> Dict[str, Any]:
        """Sync network devices credential

        When sync is triggered at a site with the credential that are associated to the same site, network devices in impacted sites (child sites which are inheriting the credential) get managed in inventory with the associated site credential. Credential gets configured on network devices before these get managed in inventory. Please make a note that cli credential wouldn't be configured on AAA authenticated devices but they just get managed with the associated site cli credential.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sites/deviceCredentials/apply'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_profiles_for_sites_count(self, type: Optional[Any] = None) -> Dict[str, Any]:
        """Retrieves the count of network profiles for sites

        Retrieves the count of network profiles for sites

        Args:
            type (Any): Filter the response to only count profiles of a given type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/networkProfilesForSites/count'
        params = {
            'type': type,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_data_api_v1_clients_trend_analytics(self, content__type: Any, x__c_a_l_l_e_r__i_d: Optional[Any] = None) -> Dict[str, Any]:
        """Retrieves the Trend analytics data related to clients.

        Retrieves the trend analytics of client data for the specified time range. The data will be grouped based on the given trend time interval. This API facilitates obtaining consolidated insights into the performance and status of the clients over the specified start and end time. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-clients1-1.0.0-resolved.yaml

        Args:
            content__type (Any): Request body content type
            x__c_a_l_l_e_r__i_d (Any): Caller ID is used to trace the origin of API calls and their associated queries executed on the database. It's an optional header parameter that can be added to an API request.


        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/data/api/v1/clients/trendAnalytics'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_device_count(self, hostname: Optional[Any] = None, management_ip_address: Optional[Any] = None, mac_address: Optional[Any] = None, location_name: Optional[Any] = None) -> Dict[str, Any]:
        """Get Device Count

        Returns the count of network devices based on the filter criteria by management IP address, mac address, hostname and location name

        Args:
            hostname (Any): hostname
            management_ip_address (Any): managementIpAddress
            mac_address (Any): macAddress
            location_name (Any): locationName

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device/count'
        params = {
            'hostname': hostname,
            'managementIpAddress': management_ip_address,
            'macAddress': mac_address,
            'locationName': location_name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v2_sp_profile_sp_profile_name(self, sp_profile_name: Any) -> Dict[str, Any]:
        """Delete SP Profile V2

        API to delete Service Provider Profile (QoS).

        Args:
            sp_profile_name (Any): SP profile name

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v2/sp-profile/{sp_profile_name}'
        url = url.format(sp_profile_name=sp_profile_name)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_maps_import_import_context_uuid_perform(self, content__type: Any, import_context_uuid: Any) -> Dict[str, Any]:
        """Import Map Archive - Perform Import

        For a previously initatied import, approves the import to be performed, accepting that data loss may occur.  A Map import will fully replace existing Maps data for the site(s) defined in the archive. The Map Archive Import Status API /maps/import/${contextUuid}/status should always be checked to validate the pre-import validation output prior to performing the import.

        Args:
            content__type (Any): Request body content type
            import_context_uuid (Any): The unique import context UUID given by a previous call of Start Import API

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/maps/import/{import_context_uuid}/perform'
        url = url.format(import_context_uuid=import_context_uuid)
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_device_reboot_apreboot(self, content__type: Optional[Any] = None) -> Dict[str, Any]:
        """Reboot Access Points

        Users can reboot multiple access points up-to 200 at a time using this API

        Args:
            content__type (Any): Content-Type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/device-reboot/apreboot'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_sda_fabric_devices_layer2_handoffs(self, content__type: Any) -> Dict[str, Any]:
        """Add fabric devices layer 2 handoffs

        Adds layer 2 handoffs in fabric devices based on user input.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sda/fabricDevices/layer2Handoffs'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sda_fabric_devices_layer2_handoffs(self, fabric_id: Any, network_device_id: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None) -> Dict[str, Any]:
        """Get fabric devices layer 2 handoffs

        Returns a list of layer 2 handoffs of fabric devices that match the provided query parameters.


        Args:
            fabric_id (Any): ID of the fabric this device belongs to.
            network_device_id (Any): Network device ID of the fabric device.
            offset (Any): Starting record for pagination.
            limit (Any): Maximum number of records to return.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/fabricDevices/layer2Handoffs'
        params = {
            'fabricId': fabric_id,
            'networkDeviceId': network_device_id,
            'offset': offset,
            'limit': limit,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_sda_fabric_devices_layer2_handoffs(self, fabric_id: Any, network_device_id: Any) -> Dict[str, Any]:
        """Delete fabric device layer 2 handoffs

        Deletes layer 2 handoffs of a fabric device based on user input.

        Args:
            fabric_id (Any): ID of the fabric this device belongs to.
            network_device_id (Any): Network device ID of the fabric device.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/fabricDevices/layer2Handoffs'
        params = {
            'fabricId': fabric_id,
            'networkDeviceId': network_device_id,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_event_subscription_syslog(self, content__type: Any) -> Dict[str, Any]:
        """Update Syslog Event Subscription

        Update Syslog Subscription Endpoint for list of registered events

        Args:
            content__type (Any): Content Type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/event/subscription/syslog'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_event_subscription_syslog(self, content__type: Any) -> Dict[str, Any]:
        """Create Syslog Event Subscription

        Create Syslog Subscription Endpoint for list of registered events

        Args:
            content__type (Any): Content Type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/event/subscription/syslog'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_event_subscription_syslog(self, event_ids: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None, sort_by: Optional[Any] = None, order: Optional[Any] = None, domain: Optional[Any] = None, sub_domain: Optional[Any] = None, category: Optional[Any] = None, type: Optional[Any] = None, name: Optional[Any] = None) -> Dict[str, Any]:
        """Get Syslog Event Subscriptions

        Gets the list of Syslog Subscriptions's based on provided offset and limit

        Args:
            event_ids (Any): List of subscriptions related to the respective eventIds (Comma separated event ids)
            offset (Any): The number of Subscriptions's to offset in the resultset whose default value 0
            limit (Any): The number of Subscriptions's to limit in the resultset whose default value 10
            sort_by (Any): SortBy field name
            order (Any): order(asc/desc)
            domain (Any): List of subscriptions related to the respective domain
            sub_domain (Any): List of subscriptions related to the respective sub-domain
            category (Any): List of subscriptions related to the respective category
            type (Any): List of subscriptions related to the respective type
            name (Any): List of subscriptions related to the respective name

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/event/subscription/syslog'
        params = {
            'eventIds': event_ids,
            'offset': offset,
            'limit': limit,
            'sortBy': sort_by,
            'order': order,
            'domain': domain,
            'subDomain': sub_domain,
            'category': category,
            'type': type,
            'name': name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_topology_vlan_vlan_names(self) -> Dict[str, Any]:
        """Get VLAN details

        Returns the list of VLAN names that are involved in a loop as identified by the Spanning Tree Protocol

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/topology/vlan/vlan-names'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_wireless_controllers_wireless_mobility_groups(self, network_device_id: Optional[Any] = None) -> Dict[str, Any]:
        """Get All MobilityGroups	

        Retrieve all configured mobility groups if no Network Device Id is provided as a query parameter. If a Network Device Id is given and a mobility group is configured for it, return the configured details; otherwise, return the default values from the device.

        Args:
            network_device_id (Any): Employ this query parameter to obtain the details of the Mobility Group corresponding to the provided networkDeviceId. Obtain the network device ID value by using the API GET call /dna/intent/api/v1/network-device/ip-address/${ipAddress}.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/wirelessControllers/wirelessMobilityGroups'
        params = {
            'networkDeviceId': network_device_id,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v2_global_credential_id(self, id: Any) -> Dict[str, Any]:
        """Delete Global Credential V2

        Delete a global credential. Only 'id' of the credential has to be passed.

        Args:
            id (Any): Global Credential id	

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v2/global-credential/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_tags_network_devices_members_associations_query(self, content__type: Any) -> Dict[str, Any]:
        """Query the tags associated with network devices.

        Fetches the tags associated with the given network device `ids`. Devices that don't have any tags associated will not be included in the response. A tag is a user-defined or system-defined construct to group resources. When a device is tagged, it is called a member of the tag. `ids` can be fetched via `/dna/intent/api/v1/network-device` API.


        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/tags/networkDevices/membersAssociations/query'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v2_site(self, group_name_hierarchy: Optional[Any] = None, id: Optional[Any] = None, type: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None) -> Dict[str, Any]:
        """Get Site V2

        API to get site(s) by site-name-hierarchy or siteId or type. List all sites if these parameters  are not given as an input.

        Args:
            group_name_hierarchy (Any): Site name hierarchy (E.g. Global/USA/CA)
            id (Any): Site Id
            type (Any): Site type (Acceptable values: area, building, floor)
            offset (Any): Offset/starting index for pagination
            limit (Any): Number of sites to be listed. Default and max supported value is 500

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v2/site'
        params = {
            'groupNameHierarchy': group_name_hierarchy,
            'id': id,
            'type': type,
            'offset': offset,
            'limit': limit,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_diagnostics_system_health(self, summary: Optional[Any] = None, domain: Optional[Any] = None, subdomain: Optional[Any] = None, limit: Optional[Any] = None, offset: Optional[Any] = None) -> Dict[str, Any]:
        """System Health API

        This API retrieves the latest system events 

        Args:
            summary (Any): Fetch the latest high severity event
            domain (Any): Fetch system events with this domain. Possible values of domain are listed here : /dna/platform/app/consumer-portal/developer-toolkit/events
            subdomain (Any): Fetch system events with this subdomain. Possible values of subdomain are listed here : /dna/platform/app/consumer-portal/developer-toolkit/events
            limit (Any): limit
            offset (Any): offset

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/diagnostics/system/health'
        params = {
            'summary': summary,
            'domain': domain,
            'subdomain': subdomain,
            'limit': limit,
            'offset': offset,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_trusted_certificates_import(self, content__type: Any) -> Dict[str, Any]:
        """Import Trusted Certificate

        Imports trusted certificate into a truststore. Accepts .pem or .der file as input.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/trustedCertificates/import'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_lan_automation_status_id(self, id: Any) -> Dict[str, Any]:
        """LAN Automation Status by Id

        Invoke this API to get the LAN Automation session status based on the given Lan Automation session id.

        Args:
            id (Any): LAN Automation session identifier.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/lan-automation/status/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_sda_fabric_devices_layer2_handoffs_id(self, id: Any) -> Dict[str, Any]:
        """Delete fabric device layer 2 handoff by id

        Deletes a layer 2 handoff of a fabric device based on id.

        Args:
            id (Any): ID of the layer 2 handoff of a fabric device.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/fabricDevices/layer2Handoffs/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def put_dna_intent_api_v2_applications(self, content__type: Any) -> Dict[str, Any]:
        """Edit Application/s

        Edit the attributes of an existing application

        Args:
            content__type (Any): content-type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v2/applications'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def post_dna_intent_api_v2_applications(self, content__type: Any) -> Dict[str, Any]:
        """Create Application/s

        Create new custom application/s

        Args:
            content__type (Any): content-type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v2/applications'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v2_applications(self, attributes: Any, offset: Any, limit: Any, name: Optional[Any] = None) -> Dict[str, Any]:
        """Get Application/s

        Get application/s by offset/limit or by name

        Args:
            attributes (Any): Attributes to retrieve, valid value application
            offset (Any): The starting point or index from where the paginated results should begin.
            limit (Any): The limit which is the maximum number of items to include in a single page of results, max value 500
            name (Any): The application name

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v2/applications'
        params = {
            'attributes': attributes,
            'offset': offset,
            'limit': limit,
            'name': name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_sda_fabric_devices(self, content__type: Any) -> Dict[str, Any]:
        """Add fabric devices

        Adds fabric devices based on user input.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sda/fabricDevices'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_sda_fabric_devices(self, fabric_id: Any, network_device_id: Optional[Any] = None, device_roles: Optional[Any] = None) -> Dict[str, Any]:
        """Delete fabric devices

        Deletes fabric devices based on user input.

        Args:
            fabric_id (Any): ID of the fabric this device belongs to.
            network_device_id (Any): Network device ID of the fabric device.
            device_roles (Any): Device roles of the fabric device. Allowed values are [CONTROL_PLANE_NODE, EDGE_NODE, BORDER_NODE, WIRELESS_CONTROLLER_NODE].

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/fabricDevices'
        params = {
            'fabricId': fabric_id,
            'networkDeviceId': network_device_id,
            'deviceRoles': device_roles,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_sda_fabric_devices(self, content__type: Any) -> Dict[str, Any]:
        """Update fabric devices

        Updates fabric devices based on user input.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sda/fabricDevices'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sda_fabric_devices(self, fabric_id: Any, network_device_id: Optional[Any] = None, device_roles: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None) -> Dict[str, Any]:
        """Get fabric devices

        Returns a list of fabric devices that match the provided query parameters.


        Args:
            fabric_id (Any): ID of the fabric this device belongs to.
            network_device_id (Any): Network device ID of the fabric device.
            device_roles (Any): Device roles of the fabric device. Allowed values are [CONTROL_PLANE_NODE, EDGE_NODE, BORDER_NODE, WIRELESS_CONTROLLER_NODE, EXTENDED_NODE].
            offset (Any): Starting record for pagination.
            limit (Any): Maximum number of records to return.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/fabricDevices'
        params = {
            'fabricId': fabric_id,
            'networkDeviceId': network_device_id,
            'deviceRoles': device_roles,
            'offset': offset,
            'limit': limit,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_wireless_settings_dot11be_profiles_id(self, content__type: Any, id: Any) -> Dict[str, Any]:
        """Update 802.11be Profile

        This API allows the user to update a 802.11be Profile

        Args:
            content__type (Any): Content Type
            id (Any): 802.11be Profile ID

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/wirelessSettings/dot11beProfiles/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_wireless_settings_dot11be_profiles_id(self, id: Any) -> Dict[str, Any]:
        """Delete a 802.11be Profile

        This API allows the user to delete a 802.11be Profile,if the 802.11be Profile is not mapped to any Wireless Network Profile

        Args:
            id (Any): 802.11be Profile ID

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/wirelessSettings/dot11beProfiles/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_wireless_settings_dot11be_profiles_id(self, id: Any) -> Dict[str, Any]:
        """Get 802.11be Profile by ID

        This API allows the user to get 802.11be Profile by ID

        Args:
            id (Any): 802.11be Profile ID

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/wirelessSettings/dot11beProfiles/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_network_profiles_for_sites_profile_id_site_assignments_bulk(self, content__type: Any, profile_id: Any) -> Dict[str, Any]:
        """Assign a network profile for sites to a list of sites

        Assign a network profile for sites to a list of sites. Also assigns the profile to child sites.

        Args:
            content__type (Any): Request body content type
            profile_id (Any): The `id` of the network profile, retrievable from `GET /intent/api/v1/networkProfilesForSites`

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/networkProfilesForSites/{profile_id}/siteAssignments/bulk'
        url = url.format(profile_id=profile_id)
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_network_profiles_for_sites_profile_id_site_assignments_bulk(self, profile_id: Any, site_id: Any) -> Dict[str, Any]:
        """Unassigns a network profile for sites from multiple sites

        Unassigns a given network profile for sites from multiple sites. The profile must be removed from the containing building first if this site is a floor.

        Args:
            profile_id (Any): The `id` of the network profile, retrievable from `GET /intent/api/v1/networkProfilesForSites`
            site_id (Any): The `id` of the site, retrievable from `GET /intent/api/v1/sites`

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/networkProfilesForSites/{profile_id}/siteAssignments/bulk'
        url = url.format(profile_id=profile_id)
        params = {
            'siteId': site_id,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_tasks_count(self, start_time: Optional[Any] = None, end_time: Optional[Any] = None, parent_id: Optional[Any] = None, root_id: Optional[Any] = None, status: Optional[Any] = None) -> Dict[str, Any]:
        """Get tasks count

        Returns the number of tasks that meet the filter criteria

        Args:
            start_time (Any): This is the epoch millisecond start time from which tasks need to be fetched
            end_time (Any): This is the epoch millisecond end time upto which task records need to be fetched
            parent_id (Any): Fetch tasks that have this parent Id
            root_id (Any): Fetch tasks that have this root Id
            status (Any): Fetch tasks that have this status. Available values : PENDING, FAILURE, SUCCESS

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/tasks/count'
        params = {
            'startTime': start_time,
            'endTime': end_time,
            'parentId': parent_id,
            'rootId': root_id,
            'status': status,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v2_floors_id(self, id: Any) -> Dict[str, Any]:
        """Deletes a floor

        Deletes a floor from the network hierarchy. This operations fails if there are any devices assigned to this floor.

        Args:
            id (Any): Floor ID

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v2/floors/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def put_dna_intent_api_v2_floors_id(self, content__type: Any, id: Any) -> Dict[str, Any]:
        """Updates a floor

        Updates a floor in the network hierarchy.

        Args:
            content__type (Any): Request body content type
            id (Any): Floor Id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v2/floors/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v2_floors_id(self, id: Any, units_of_measure: Optional[Any] = None) -> Dict[str, Any]:
        """Gets a floor

        Gets a floor in the network hierarchy.

        Args:
            id (Any): Floor Id
            units_of_measure (Any): Floor units of measure

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v2/floors/{id}'
        url = url.format(id=id)
        params = {
            '_unitsOfMeasure': units_of_measure,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_system_api_v1_user(self, content__type: Any) -> Dict[str, Any]:
        """Add user API

        Add a new user for Cisco DNA Center System.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/system/api/v1/user'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_system_api_v1_user(self, invoke_source: Any, auth_source: Optional[Any] = None) -> Dict[str, Any]:
        """Get users API

        Get all users for the Cisco DNA Center System.

        Args:
            invoke_source (Any): The source that invokes this API. The value of this query parameter must be set to "external".
            auth_source (Any): The source that authenticates the user. The value of this query parameter can be set to "internal" or "external". If not provided, then all users will be returned in the response.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/system/api/v1/user'
        params = {
            'invokeSource': invoke_source,
            'authSource': auth_source,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_system_api_v1_user(self, content__type: Any) -> Dict[str, Any]:
        """Update user API

        Update a user for Cisco DNA Center System.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/system/api/v1/user'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_sda_fabric_zones(self, content__type: Any) -> Dict[str, Any]:
        """Add fabric zone

        Adds a fabric zone based on user input.

        Args:
            content__type (Any): Request body content type.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sda/fabricZones'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sda_fabric_zones(self, id: Optional[Any] = None, site_id: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None) -> Dict[str, Any]:
        """Get fabric zones

        Returns a list of fabric zones that match the provided query parameters.

        Args:
            id (Any): ID of the fabric zone.
            site_id (Any): ID of the network hierarchy associated with the fabric zone.
            offset (Any): Starting record for pagination.
            limit (Any): Maximum number of records to return.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/fabricZones'
        params = {
            'id': id,
            'siteId': site_id,
            'offset': offset,
            'limit': limit,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_sda_fabric_zones(self, content__type: Any) -> Dict[str, Any]:
        """Update fabric zone

        Updates a fabric zone based on user input.

        Args:
            content__type (Any): Request body content type.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sda/fabricZones'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def post_dna_intent_api_v2_wireless_accesspoint_configuration(self, content__type: Optional[Any] = None) -> Dict[str, Any]:
        """Configure Access Points V2

        User can configure multiple access points with required options using this intent API

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v2/wireless/accesspoint-configuration'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_onboarding_pnp_settings_sacct_domain_vacct(self, domain: Any) -> Dict[str, Any]:
        """Get Virtual Account List

        Returns list of virtual accounts associated with the specified smart account

        Args:
            domain (Any): Smart Account Domain

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/onboarding/pnp-settings/sacct/{domain}/vacct'
        url = url.format(domain=domain)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_global_credential_global_credential_id(self, content__type: Any, global_credential_id: Any) -> Dict[str, Any]:
        """Update global credentials

        Update global credential for network devices in site(s)

        Args:
            content__type (Any): Request body content type
            global_credential_id (Any): Global credential Uuid

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/global-credential/{global_credential_id}'
        url = url.format(global_credential_id=global_credential_id)
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_global_credential_global_credential_id(self, global_credential_id: Any) -> Dict[str, Any]:
        """Delete global credentials by Id

        Deletes global credential for the given ID

        Args:
            global_credential_id (Any): ID of global-credential

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/global-credential/{global_credential_id}'
        url = url.format(global_credential_id=global_credential_id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_floors_floor_id_planned_access_points_planned_access_point_uuid(self, floor_id: Any, planned_access_point_uuid: Any) -> Dict[str, Any]:
        """Delete Planned Access Point for Floor

        Allow to delete a planned access point from an existing floor map including its planned radio and antenna details.  Use the Get variant of this API to fetch the existing planned access points for the floor.  The instanceUUID listed in each of the planned access point attributes acts as the path param input to this API to delete that specific instance.

        Args:
            floor_id (Any): The instance UUID of the floor hierarchy element
            planned_access_point_uuid (Any): The instance UUID of the planned access point to delete

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/floors/{floor_id}/planned-access-points/{planned_access_point_uuid}'
        url = url.format(floor_id=floor_id, planned_access_point_uuid=planned_access_point_uuid)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_template_programmer_project_name_exportprojects(self, content__type: Any) -> Dict[str, Any]:
        """Exports the projects for a given criteria.

        Exports the projects for given projectNames.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/template-programmer/project/name/exportprojects'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_qos_device_interface_info_count(self) -> Dict[str, Any]:
        """Get Qos Device Interface Info Count

        Get the number of all existing qos device interface infos group by network device id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/qos-device-interface-info-count'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_events_count(self, tags: Any, event_id: Optional[Any] = None) -> Dict[str, Any]:
        """Count of Events

        Get the count of registered events with provided eventIds or tags as mandatory

        Args:
            tags (Any): The registered Tags should be provided
            event_id (Any): The registered EventId should be provided

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/events/count'
        params = {
            'tags': tags,
            'eventId': event_id,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_interface_ospf(self) -> Dict[str, Any]:
        """Get OSPF interfaces

        Returns the interfaces that has OSPF enabled

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/interface/ospf'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_device_image_updates(self, id: Optional[Any] = None, parent_id: Optional[Any] = None, network_device_id: Optional[Any] = None, status: Optional[Any] = None, image_name: Optional[Any] = None, host_name: Optional[Any] = None, management_address: Optional[Any] = None, start_time: Optional[Any] = None, end_time: Optional[Any] = None, sort_by: Optional[Any] = None, order: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None) -> Dict[str, Any]:
        """Get network device image updates

        Returns the list of network device image updates based on the given filter criteria

        Args:
            id (Any): Update id which is unique for each network device under the parentId
            parent_id (Any): Updates that have this parent id
            network_device_id (Any): Network device id
            status (Any): Status of the image update. Available values : FAILURE, SUCCESS, IN_PROGRESS, PENDING
            image_name (Any): Software image name for the update
            host_name (Any): Host name of the network device for the image update. Supports case-insensitive partial search
            management_address (Any): Management address of the network device
            start_time (Any): Image update started after the given time (as milliseconds since UNIX epoch)
            end_time (Any): Image update started before the given time (as milliseconds since UNIX epoch)
            sort_by (Any): A property within the response to sort by.
            order (Any): Whether ascending or descending order should be used to sort the response.
            offset (Any): The first record to show for this page; the first record is numbered 1.
            limit (Any): The number of records to show for this page.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/networkDeviceImageUpdates'
        params = {
            'id': id,
            'parentId': parent_id,
            'networkDeviceId': network_device_id,
            'status': status,
            'imageName': image_name,
            'hostName': host_name,
            'managementAddress': management_address,
            'startTime': start_time,
            'endTime': end_time,
            'sortBy': sort_by,
            'order': order,
            'offset': offset,
            'limit': limit,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_wireless_controllers_wireless_mobility_groups_mobility_provision(self, content__type: Any) -> Dict[str, Any]:
        """Mobility Provision

        This API is used to provision/deploy wireless mobility into Cisco wireless controllers.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/wirelessControllers/wirelessMobilityGroups/mobilityProvision'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_sda_fabric_devices_id(self, id: Any) -> Dict[str, Any]:
        """Delete fabric device by id

        Deletes a fabric device based on id.

        Args:
            id (Any): ID of the fabric device.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/fabricDevices/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def post_dna_intent_api_v2_buildings(self, content__type: Any) -> Dict[str, Any]:
        """Creates a building

        Creates a building in the network hierarchy under area.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v2/buildings'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_sda_transit_networks(self, content__type: Any) -> Dict[str, Any]:
        """Update transit networks

        Updates transit networks based on user input.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sda/transitNetworks'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_sda_transit_networks(self, content__type: Any) -> Dict[str, Any]:
        """Add transit networks

        Adds transit networks based on user input.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sda/transitNetworks'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sda_transit_networks(self, id: Optional[Any] = None, name: Optional[Any] = None, type: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None) -> Dict[str, Any]:
        """Get transit networks

        Returns a list of transit networks that match the provided query parameters.

        Args:
            id (Any): ID of the transit network.
            name (Any): Name of the transit network.
            type (Any): Type of the transit network. Allowed values are [IP_BASED_TRANSIT, SDA_LISP_PUB_SUB_TRANSIT, SDA_LISP_BGP_TRANSIT].
            offset (Any): Starting record for pagination.
            limit (Any): Maximum number of records to return.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/transitNetworks'
        params = {
            'id': id,
            'name': name,
            'type': type,
            'offset': offset,
            'limit': limit,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_device_device_id_stack(self, device_id: Any) -> Dict[str, Any]:
        """Get Stack Details for Device

        Retrieves complete stack details for given device ID

        Args:
            device_id (Any): Device ID

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device/{device_id}/stack'
        url = url.format(device_id=device_id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v2_network_devices_device_id_interfaces_query(self, content__type: Any, device_id: Any) -> Dict[str, Any]:
        """Get Device Interface Stats Info

        This API returns the Interface Stats for the given Device Id. Please refer to the Feature tab for the Request Body usage and the API filtering support.

        Args:
            content__type (Any): Request body content type
            device_id (Any): Network Device Id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v2/networkDevices/{device_id}/interfaces/query'
        url = url.format(device_id=device_id)
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v2_application_policy_application_set_count(self, scalable_group_type: Any) -> Dict[str, Any]:
        """Get Application Set Count

        Get the number of all existing application sets

        Args:
            scalable_group_type (Any): Scalable group type to retrieve, valid value APPLICATION_GROUP

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v2/application-policy-application-set-count'
        params = {
            'scalableGroupType': scalable_group_type,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_onboarding_pnp_workflow_count(self, name: Optional[Any] = None) -> Dict[str, Any]:
        """Get Workflow Count

        Returns the workflow count

        Args:
            name (Any): Workflow Name

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/onboarding/pnp-workflow/count'
        params = {
            'name': name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_sda_fabric_zones_id(self, id: Any) -> Dict[str, Any]:
        """Delete fabric zone by id

        Deletes a fabric zone based on id.

        Args:
            id (Any): ID of the fabric zone.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/fabricZones/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_compliance_device_uuid(self, device_uuid: Any) -> Dict[str, Any]:
        """Device Compliance Status

        Return compliance status of a device.

        Args:
            device_uuid (Any): Device Id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/compliance/{device_uuid}'
        url = url.format(device_uuid=device_uuid)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_flow_analysis_flow_analysis_id(self, flow_analysis_id: Any) -> Dict[str, Any]:
        """Retrieves previous Pathtrace

        Returns result of a previously requested flow analysis by its Flow Analysis id

        Args:
            flow_analysis_id (Any): Flow analysis request id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/flow-analysis/{flow_analysis_id}'
        url = url.format(flow_analysis_id=flow_analysis_id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_flow_analysis_flow_analysis_id(self, flow_analysis_id: Any) -> Dict[str, Any]:
        """Deletes Pathtrace by Id

        Deletes a flow analysis request by its id

        Args:
            flow_analysis_id (Any): Flow analysis request id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/flow-analysis/{flow_analysis_id}'
        url = url.format(flow_analysis_id=flow_analysis_id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_health(self, timestamp: Optional[Any] = None) -> Dict[str, Any]:
        """Get Overall Network Health

        Returns Overall Network Health information by Device category (Access, Distribution, Core, Router, Wireless) for any given point of time

        Args:
            timestamp (Any): UTC timestamp of network health data in milliseconds

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-health'
        params = {
            'timestamp': timestamp,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_compliance_network_devices_id_issues_remediation_provision(self, content__type: Any, id: Any) -> Dict[str, Any]:
        """Compliance Remediation

        Remediates configuration compliance issues. Compliance issues related to 'Routing', 'HA Remediation', 'Software Image', 'Securities Advisories', 'SD-Access Unsupported Configuration', 'Workflow', etc. will not be addressed by this API.

Warning: Fixing compliance mismatches could result in a possible network flap.

        Args:
            content__type (Any): Request body content type
            id (Any): Network device identifier

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/compliance/networkDevices/{id}/issues/remediation/provision'
        url = url.format(id=id)
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_network_device_user_defined_field_id(self, id: Any) -> Dict[str, Any]:
        """Delete User-Defined-Field

        Deletes an existing Global User-Defined-Field using it's id.

        Args:
            id (Any): UDF id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device/user-defined-field/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_network_device_user_defined_field_id(self, id: Any) -> Dict[str, Any]:
        """Update User-Defined-Field

        Updates an existing global User Defined Field, using it's id.

        Args:
            id (Any): UDF id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device/user-defined-field/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_onboarding_pnp_settings(self) -> Dict[str, Any]:
        """Get PnP global settings

        Returns global PnP settings of the user

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/onboarding/pnp-settings'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_onboarding_pnp_settings(self, content__type: Any) -> Dict[str, Any]:
        """Update PnP global settings

        Updates the user's list of global PnP settings

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/onboarding/pnp-settings'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def put_dna_intent_api_v2_service_provider(self) -> Dict[str, Any]:
        """Update SP Profile V2

        API to update Service Provider Profile (QoS).

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v2/service-provider'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def post_dna_intent_api_v2_service_provider(self) -> Dict[str, Any]:
        """Create SP Profile V2

        API to create Service Provider Profile(QOS).

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v2/service-provider'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v2_service_provider(self) -> Dict[str, Any]:
        """Get Service Provider Details V2

        API to get Service Provider details (QoS).

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v2/service-provider'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_wireless_profiles(self, limit: Optional[Any] = None, offset: Optional[Any] = None) -> Dict[str, Any]:
        """Get Wireless Profiles

        This API allows the user to get all Wireless Network Profiles

        Args:
            limit (Any): Limit
            offset (Any): Offset

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/wirelessProfiles'
        params = {
            'limit': limit,
            'offset': offset,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_wireless_profiles(self, content__type: Any) -> Dict[str, Any]:
        """Create Wireless Profile

        This API allows the user to create a Wireless Network Profile

        Args:
            content__type (Any): Content Type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/wirelessProfiles'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_device_config_task(self, parent_task_id: Any) -> Dict[str, Any]:
        """Get config task details

        Returns a config task result details by specified id

        Args:
            parent_task_id (Any): task Id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device-config/task'
        params = {
            'parentTaskId': parent_task_id,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_tags_network_devices_members_associations_count(self) -> Dict[str, Any]:
        """Retrieve the count of network devices that are associated with at least one tag.

        Fetches the count of network devices that are associated with at least one tag. A tag is a user-defined or system-defined construct to group resources. When a device is tagged, it is called a member of the tag.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/tags/networkDevices/membersAssociations/count'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sda_multicast_virtual_networks_count(self, fabric_id: Optional[Any] = None) -> Dict[str, Any]:
        """Get multicast virtual network count

        Returns the count of multicast configurations associated to virtual networks that match the provided query parameters.

        Args:
            fabric_id (Any): ID of the fabric site the multicast configuration is associated with.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/multicast/virtualNetworks/count'
        params = {
            'fabricId': fabric_id,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_tag_count(self, name: Optional[Any] = None, name_space: Optional[Any] = None, attribute_name: Optional[Any] = None, size: Optional[Any] = None, system_tag: Optional[Any] = None) -> Dict[str, Any]:
        """Get Tag Count

        Returns tag count

        Args:
            name (Any): tagName
            name_space (Any): nameSpace
            attribute_name (Any): attributeName
            size (Any): size in kilobytes(KB)
            system_tag (Any): systemTag

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/tag/count'
        params = {
            'name': name,
            'nameSpace': name_space,
            'attributeName': attribute_name,
            'size': size,
            'systemTag': system_tag,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_device_id_brief(self, id: Any) -> Dict[str, Any]:
        """Get Device Summary

        Returns brief summary of device info such as hostname, management IP address for the given device Id

        Args:
            id (Any): Device ID

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device/{id}/brief'
        url = url.format(id=id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_sda_authentication_profiles(self, content__type: Any) -> Dict[str, Any]:
        """Update authentication profile

        Updates an authentication profile based on user input.

        Args:
            content__type (Any): Request body content type.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sda/authenticationProfiles'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sda_authentication_profiles(self, fabric_id: Optional[Any] = None, authentication_profile_name: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None) -> Dict[str, Any]:
        """Get authentication profiles

        Returns a list of authentication profiles that match the provided query parameters.

        Args:
            fabric_id (Any): ID of the fabric the authentication profile is assigned to.
            authentication_profile_name (Any): Return only the authentication profiles with this specified name. Note that 'No Authentication' is not a valid option for this parameter.
            offset (Any): Starting record for pagination.
            limit (Any): Maximum number of records to return.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/authenticationProfiles'
        params = {
            'fabricId': fabric_id,
            'authenticationProfileName': authentication_profile_name,
            'offset': offset,
            'limit': limit,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_data_api_v1_flexible_report_schedules(self, content__type: Any) -> Dict[str, Any]:
        """Get all flexible report schedules

        Get all flexible report schedules

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/data/api/v1/flexible-report/schedules'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_licenses_smart_account_smart_account_id_virtual_accounts(self, smart_account_id: Any) -> Dict[str, Any]:
        """Virtual Account Details

        Get virtual account details of a smart account.

        Args:
            smart_account_id (Any): Id of smart account

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/licenses/smartAccount/{smart_account_id}/virtualAccounts'
        url = url.format(smart_account_id=smart_account_id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_device_functional_capability_id(self, id: Any) -> Dict[str, Any]:
        """Get Functional Capability by Id

        Returns functional capability with given Id

        Args:
            id (Any): Functional Capability UUID

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device/functional-capability/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_sda_fabric_sites(self, content__type: Any) -> Dict[str, Any]:
        """Add fabric site

        Adds a fabric site based on user input.

        Args:
            content__type (Any): Request body content type.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sda/fabricSites'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sda_fabric_sites(self, id: Optional[Any] = None, site_id: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None) -> Dict[str, Any]:
        """Get fabric sites

        Returns a list of fabric sites that match the provided query parameters.

        Args:
            id (Any): ID of the fabric site.
            site_id (Any): ID of the network hierarchy associated with the fabric site.
            offset (Any): Starting record for pagination.
            limit (Any): Maximum number of records to return.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/fabricSites'
        params = {
            'id': id,
            'siteId': site_id,
            'offset': offset,
            'limit': limit,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_sda_fabric_sites(self, content__type: Any) -> Dict[str, Any]:
        """Update fabric site

        Updates a fabric site based on user input.

        Args:
            content__type (Any): Request body content type.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sda/fabricSites'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_onboarding_pnp_workflow(self, content__type: Optional[Any] = None) -> Dict[str, Any]:
        """Add a Workflow

        Adds a PnP Workflow along with the relevant tasks in the workflow into the PnP database

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/onboarding/pnp-workflow'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_onboarding_pnp_workflow(self, limit: Optional[Any] = None, offset: Optional[Any] = None, sort: Optional[Any] = None, sort_order: Optional[Any] = None, type: Optional[Any] = None, name: Optional[Any] = None) -> Dict[str, Any]:
        """Get Workflows

        Returns the list of workflows based on filter criteria. If a limit is not specified, it will default to return 50 workflows. Pagination and sorting are also supported by this endpoint

        Args:
            limit (Any): Limits number of results
            offset (Any): Index of first result
            sort (Any): Comma seperated lost of fields to sort on
            sort_order (Any): Sort Order Ascending (asc) or Descending (des)
            type (Any): Workflow Type
            name (Any): Workflow Name

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/onboarding/pnp-workflow'
        params = {
            'limit': limit,
            'offset': offset,
            'sort': sort,
            'sortOrder': sort_order,
            'type': type,
            'name': name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_device_network_device_id_config(self, network_device_id: Any) -> Dict[str, Any]:
        """Get Device Config by Id

        Returns the device config by specified device ID

        Args:
            network_device_id (Any): networkDeviceId

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device/{network_device_id}/config'
        url = url.format(network_device_id=network_device_id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_data_api_v1_clients_id(self, id: Any, x__c_a_l_l_e_r__i_d: Optional[Any] = None, start_time: Optional[Any] = None, end_time: Optional[Any] = None, view: Optional[Any] = None, attribute: Optional[Any] = None) -> Dict[str, Any]:
        """Retrieves specific client information matching the MAC address.

        Retrieves specific client information matching the MAC address. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-clients1-1.0.0-resolved.yaml

        Args:
            id (Any): id is the client mac address. It can be specified is any notational conventions 
01:23:45:67:89:AB or 01-23-45-67-89-AB or 0123.4567.89AB and is case insensitive

            x__c_a_l_l_e_r__i_d (Any): Caller ID is used to trace the origin of API calls and their associated queries executed on the database. It's an optional header parameter that can be added to an API request.

            start_time (Any): Start time from which API queries the data set related to the resource. It must be specified in UNIX epochtime in milliseconds. Value is inclusive.

If `startTime` is not provided, API will default to current time.

            end_time (Any): End time to which API queries the data set related to the resource. It must be specified in UNIX epochtime in milliseconds. Value is inclusive.

            view (Any): Client related Views
Refer to ClientView schema for list of views supported
Examples:

`view=Wireless` (single view requested)

`view=WirelessHealth&view=WirelessTraffic` (multiple view requested)

            attribute (Any): List of attributes related to resource that can be requested to only be part of the response along with the required attributes. Refer to ClientAttribute schema for list of attributes supported Examples:
`attribute=band` (single attribute requested)
`attribute=band&attribute=ssid&attribute=overallScore` (multiple attribute requested)

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/data/api/v1/clients/{id}'
        url = url.format(id=id)
        params = {
            'startTime': start_time,
            'endTime': end_time,
            'view': view,
            'attribute': attribute,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_device_id_meraki_organization(self, id: Any) -> Dict[str, Any]:
        """Get Organization list for Meraki

        Returns list of organizations for meraki dashboard

        Args:
            id (Any): Device Id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device/{id}/meraki-organization'
        url = url.format(id=id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_device_id_collection_schedule(self, id: Any) -> Dict[str, Any]:
        """Get Polling Interval by Id

        Returns polling interval by device id

        Args:
            id (Any): Device ID

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device/{id}/collection-schedule'
        url = url.format(id=id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_tags_interfaces_members_associations_query(self, content__type: Any) -> Dict[str, Any]:
        """Query the tags associated with interfaces.

        Fetches the tags associated with the given interface `ids`. Interfaces that don't have any tags associated will not be included in the response. A tag is a user-defined or system-defined construct to group resources. When an interface is tagged, it is called a member of the tag. `ids` can be fetched via `/dna/intent/api/v1/interface` API.


        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/tags/interfaces/membersAssociations/query'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_event_event_series(self, event_ids: Optional[Any] = None, start_time: Optional[Any] = None, end_time: Optional[Any] = None, category: Optional[Any] = None, type: Optional[Any] = None, severity: Optional[Any] = None, domain: Optional[Any] = None, sub_domain: Optional[Any] = None, source: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None, sort_by: Optional[Any] = None, order: Optional[Any] = None, tags: Optional[Any] = None, namespace: Optional[Any] = None, site_id: Optional[Any] = None) -> Dict[str, Any]:
        """Get Notifications

        Get the list of Published Notifications

        Args:
            event_ids (Any): The registered EventId should be provided
            start_time (Any): Start Time in milliseconds
            end_time (Any): End Time in milliseconds
            category (Any): Category
            type (Any): Type
            severity (Any): Severity
            domain (Any): Domain
            sub_domain (Any): Sub Domain
            source (Any): Source
            offset (Any): Start Offset
            limit (Any): # of records
            sort_by (Any): Sort By column
            order (Any): Ascending/Descending order [asc/desc]
            tags (Any): Tags
            namespace (Any): Namespace
            site_id (Any): Site Id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/event/event-series'
        params = {
            'eventIds': event_ids,
            'startTime': start_time,
            'endTime': end_time,
            'category': category,
            'type': type,
            'severity': severity,
            'domain': domain,
            'subDomain': sub_domain,
            'source': source,
            'offset': offset,
            'limit': limit,
            'sortBy': sort_by,
            'order': order,
            'tags': tags,
            'namespace': namespace,
            'siteId': site_id,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_data_api_v1_assurance_issues_id(self, id: Any, accept__language: Optional[Any] = None, x__c_a_l_l_e_r__i_d: Optional[Any] = None, view: Optional[Any] = None, attribute: Optional[Any] = None) -> Dict[str, Any]:
        """Get all the details and suggested actions of an issue for the given issue id

         Returns all the details and suggested actions of an issue for the given issue id. https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-IssuesList-1.0.0-resolved.yaml

        Args:
            id (Any): The issue Uuid
            accept__language (Any): This header parameter can be used to specify the language in which issue description and suggested actions need to be returned. Available options are - 'en' (English), 'ja' (Japanese), 'ko' (Korean), 'zh' (Chinese). If this parameter is not present the issue details are returned in English language.
            x__c_a_l_l_e_r__i_d (Any): Caller ID can be used to trace the caller for queries executed on database. The caller id is like a optional attribute which can be added to API invocation like ui, python, postman, test-automation etc
            view (Any): The name of the View. Each view represents a specific data set. Please refer to the `IssuesView` Model for supported views. View is predefined set of attributes supported by the API. Only the attributes related to the given view will be part of the API response along with default attributes. If multiple views are provided, then response will contain attributes from all those views. If no views are specified, all attributes will be returned.

| View Name | Included Attributes |
| --- | --- |
| `update` | updatedTime, updatedBy |
| `site` | siteName, siteHierarchy, siteId, siteHierarchyId |
Examples: `view=update` (single view requested) `view=update&view=site` (multiple views requested)       

            attribute (Any): List of attributes related to the issue. If these are provided, then only those attributes will be part of response along with the default attributes. Please refer to the `IssuesResponseAttribute` Model for supported attributes.
Examples: `attribute=deviceType` (single attribute requested) `attribute=deviceType&attribute=updatedBy` (multiple attributes requested)


        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if accept__language is not None:
            request_headers['Accept-Language'] = str(accept__language)
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/data/api/v1/assuranceIssues/{id}'
        url = url.format(id=id)
        params = {
            'view': view,
            'attribute': attribute,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_interface_interface_uuid_legit_operation(self, interface_uuid: Any) -> Dict[str, Any]:
        """Legit operations for interface

        Get list of all properties & operations valid for an interface.

        Args:
            interface_uuid (Any): Interface ID

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/interface/{interface_uuid}/legit-operation'
        url = url.format(interface_uuid=interface_uuid)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v2_floors(self, content__type: Any) -> Dict[str, Any]:
        """Creates a floor

        Create a floor in the network hierarchy under building.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v2/floors'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_interface_interface_uuid(self, content__type: Any, interface_uuid: Any, deployment_mode: Optional[Any] = None) -> Dict[str, Any]:
        """Update Interface details

        Add/Update Interface description, VLAN membership, Voice VLAN and change Interface admin status ('UP'/'DOWN') from Request body.

        Args:
            content__type (Any): Request body content type
            interface_uuid (Any): Interface ID
            deployment_mode (Any): Preview/Deploy ['Preview' means the configuration is not pushed to the device. 'Deploy' makes the configuration pushed to the device]

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/interface/{interface_uuid}'
        url = url.format(interface_uuid=interface_uuid)
        params = {
            'deploymentMode': deployment_mode,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def delete_dna_system_api_v1_user_user_id(self, user_id: Any) -> Dict[str, Any]:
        """Delete user API

        Delete a user from Cisco DNA Center System.

        Args:
            user_id (Any): The id of the user to be deleted

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/system/api/v1/user/{user_id}'
        url = url.format(user_id=user_id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_device_config_count(self) -> Dict[str, Any]:
        """Get Device Config Count

        Returns the count of device configs

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device/config/count'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_interface_isis(self) -> Dict[str, Any]:
        """Get ISIS interfaces

        Returns the interfaces that has ISIS enabled

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/interface/isis'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_profiles_for_sites_id(self, id: Any) -> Dict[str, Any]:
        """Retrieve a network profile for sites by id

        Retrieves a network profile for sites by id.

        Args:
            id (Any): The `id` of the network profile, retrievable from `GET /intent/api/v1/networkProfilesForSites`

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/networkProfilesForSites/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_network_profiles_for_sites_id(self, id: Any) -> Dict[str, Any]:
        """Deletes a network profile for sites

        Deletes a network profile for sites.

        Args:
            id (Any): The `id` of the network profile, retrievable from `GET /intent/api/v1/networkProfilesForSites`

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/networkProfilesForSites/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_data_api_v1_event_event_series_audit_logs(self, parent_instance_id: Optional[Any] = None, instance_id: Optional[Any] = None, name: Optional[Any] = None, event_id: Optional[Any] = None, category: Optional[Any] = None, severity: Optional[Any] = None, domain: Optional[Any] = None, sub_domain: Optional[Any] = None, source: Optional[Any] = None, user_id: Optional[Any] = None, context: Optional[Any] = None, event_hierarchy: Optional[Any] = None, site_id: Optional[Any] = None, device_id: Optional[Any] = None, is_system_events: Optional[Any] = None, description: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None, start_time: Optional[Any] = None, end_time: Optional[Any] = None, sort_by: Optional[Any] = None, order: Optional[Any] = None) -> Dict[str, Any]:
        """Get AuditLog Records

        Get Audit Log Event instances from the Event-Hub 

        Args:
            parent_instance_id (Any): Parent Audit Log record's instanceID.
            instance_id (Any): InstanceID of the Audit Log.
            name (Any): Audit Log notification event name.
            event_id (Any): Audit Log notification's event ID. 
            category (Any): Audit Log notification's event category. Supported values: INFO, WARN, ERROR, ALERT, TASK_PROGRESS, TASK_FAILURE, TASK_COMPLETE, COMMAND, QUERY, CONVERSATION
            severity (Any): Audit Log notification's event severity. Supported values: 1, 2, 3, 4, 5.
            domain (Any): Audit Log notification's event domain.
            sub_domain (Any): Audit Log notification's event sub-domain.
            source (Any): Audit Log notification's event source.
            user_id (Any): Audit Log notification's event userId.
            context (Any): Audit Log notification's event correlationId.
            event_hierarchy (Any): Audit Log notification's event eventHierarchy. Example: "US.CA.San Jose" OR "US.CA" OR "CA.San Jose" - Delimiter for hierarchy separation is ".".
            site_id (Any): Audit Log notification's siteId.
            device_id (Any): Audit Log notification's deviceId.
            is_system_events (Any): Parameter to filter system generated audit-logs.
            description (Any): String full/partial search - (Provided input string is case insensitively matched for records).
            offset (Any): Position of a particular Audit Log record in the data. 
            limit (Any): Number of Audit Log records to be returned per page.
            start_time (Any): Start Time in milliseconds since Epoch Eg. 1597950637211 (when provided endTime is mandatory)
            end_time (Any): End Time in milliseconds since Epoch Eg. 1597961437211 (when provided startTime is mandatory)
            sort_by (Any): Sort the Audit Logs by certain fields. Supported values are event notification header attributes.
            order (Any): Order of the sorted Audit Log records. Default value is desc by timestamp. Supported values: asc, desc.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/data/api/v1/event/event-series/audit-logs'
        params = {
            'parentInstanceId': parent_instance_id,
            'instanceId': instance_id,
            'name': name,
            'eventId': event_id,
            'category': category,
            'severity': severity,
            'domain': domain,
            'subDomain': sub_domain,
            'source': source,
            'userId': user_id,
            'context': context,
            'eventHierarchy': event_hierarchy,
            'siteId': site_id,
            'deviceId': device_id,
            'isSystemEvents': is_system_events,
            'description': description,
            'offset': offset,
            'limit': limit,
            'startTime': start_time,
            'endTime': end_time,
            'sortBy': sort_by,
            'order': order,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_global_credential_http_read(self, content__type: Any) -> Dict[str, Any]:
        """Update HTTP read credential

        Updates global HTTP Read credential

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/global-credential/http-read'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_global_credential_http_read(self, content__type: Any) -> Dict[str, Any]:
        """Create HTTP read credentials

        Adds HTTP read credentials

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/global-credential/http-read'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_diagnostics_system_performance_history(self, kpi: Optional[Any] = None, start_time: Optional[Any] = None, end_time: Optional[Any] = None) -> Dict[str, Any]:
        """System Performance Historical API

        Retrieves the average values of cluster key performance indicators (KPIs), like CPU utilization, memory utilization or network rates grouped by time intervals within a specified time range. The data will be available from the past 24 hours.

        Args:
            kpi (Any): Fetch historical data for this kpi. Valid values: cpu,memory,network
            start_time (Any): This is the epoch start time in milliseconds from which performance indicator need to be fetched
            end_time (Any): This is the epoch end time in milliseconds upto which performance indicator need to be fetched

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/diagnostics/system/performance/history'
        params = {
            'kpi': kpi,
            'startTime': start_time,
            'endTime': end_time,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_device_device_uuid_supervisor_card(self, device_uuid: Any) -> Dict[str, Any]:
        """Get Supervisor card detail

        Get supervisor card detail for a given deviceuuid. Response will contain serial no, part no, switch no and slot no.

        Args:
            device_uuid (Any): instanceuuid of device

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device/{device_uuid}/supervisor-card'
        url = url.format(device_uuid=device_uuid)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_sites_id_image_distribution_settings(self, content__type: Any, id: Any) -> Dict[str, Any]:
        """Set image distribution settings for a site

        Set image distribution settings for a site; `null` values indicate that the setting will be inherited from the parent site; empty objects (`{}`) indicate that the settings is unset.

        Args:
            content__type (Any): Request body content type
            id (Any): Site Id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sites/{id}/imageDistributionSettings'
        url = url.format(id=id)
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sites_id_image_distribution_settings(self, id: Any, inherited: Optional[Any] = None) -> Dict[str, Any]:
        """Retrieve image distribution settings for a site

        Retrieve image distribution settings for a site; `null` values indicate that the setting will be inherited from the parent site; empty objects (`{}`) indicate that the setting is unset at a site.

        Args:
            id (Any): Site Id
            inherited (Any): Include settings explicitly set for this site and settings inherited from sites higher in the site hierarchy; when `false`, `null` values indicate that the site inherits that setting from the parent site or a site higher in the site hierarchy.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sites/{id}/imageDistributionSettings'
        url = url.format(id=id)
        params = {
            '_inherited': inherited,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_wireless_controllers_network_device_id_ssid_details(self, network_device_id: Any, ssid_name: Optional[Any] = None, admin_status: Optional[Any] = None, managed: Optional[Any] = None, limit: Optional[Any] = None, offset: Optional[Any] = None) -> Dict[str, Any]:
        """Get SSID Details for specific Wireless Controller

        Retrieves all details of SSIDs associated with the specific Wireless Controller.

        Args:
            network_device_id (Any): Obtain the network device ID value by using the API call GET: /dna/intent/api/v1/network-device/ip-address/${ipAddress}.
            ssid_name (Any): Employ this query parameter to obtain the details of the SSID corresponding to the provided SSID name.
            admin_status (Any): Utilize this query parameter to obtain the administrative status. A 'true' value signifies that the admin status of the SSID is enabled, while a 'false' value indicates that the admin status of the SSID is disabled.
            managed (Any): If value is 'true' means SSIDs are configured through design.If the value is 'false' means out of band configuration from the Wireless Controller.
            limit (Any): The number of records to show for this page.
            offset (Any): The first record to show for this page; the first record is numbered 1.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/wirelessControllers/{network_device_id}/ssidDetails'
        url = url.format(network_device_id=network_device_id)
        params = {
            'ssidName': ssid_name,
            'adminStatus': admin_status,
            'managed': managed,
            'limit': limit,
            'offset': offset,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_template_programmer_template_template_id(self, template_id: Any, latest_version: Optional[Any] = None) -> Dict[str, Any]:
        """Gets details of a given template

        Details of the template by its id

        Args:
            template_id (Any): TemplateId(UUID) to get details of the template
            latest_version (Any): latestVersion flag to get the latest versioned template

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/template-programmer/template/{template_id}'
        url = url.format(template_id=template_id)
        params = {
            'latestVersion': latest_version,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_template_programmer_template_template_id(self, template_id: Any) -> Dict[str, Any]:
        """Deletes the template

        Deletes the template by its id

        Args:
            template_id (Any): templateId(UUID) of template to be deleted

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/template-programmer/template/{template_id}'
        url = url.format(template_id=template_id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_licenses_smart_account_virtual_account_deregister(self, content__type: Optional[Any] = None) -> Dict[str, Any]:
        """Device Deregistration

        Deregister device(s) from CSSM(Cisco Smart Software Manager).

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/licenses/smartAccount/virtualAccount/deregister'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_custom_issue_definitions_id(self, content__type: Any, id: Any, x__c_a_l_l_e_r__i_d: Optional[Any] = None) -> Dict[str, Any]:
        """Updates an existing custom issue definition based on the provided Id.

        Updates an existing custom issue definition based on the provided Id. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-AssuranceUserDefinedIssueAPIs-1.0.0-resolved.yaml

        Args:
            content__type (Any): Request body content type
            id (Any): The custom issue definition Identifier
            x__c_a_l_l_e_r__i_d (Any): Caller ID is used to trace the origin of API calls and their associated queries executed on the database. It's an optional header parameter that can be added to an API request.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/intent/api/v1/customIssueDefinitions/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_custom_issue_definitions_id(self, id: Any, x__c_a_l_l_e_r__i_d: Optional[Any] = None) -> Dict[str, Any]:
        """Deletes an existing custom issue definition.

        Deletes an existing custom issue definition based on the Id. Only the Global profile issue has the access to delete the issue definition, so no profile id is required. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-AssuranceUserDefinedIssueAPIs-1.0.0-resolved.yaml

        Args:
            id (Any): The custom issue definition unique identifier
            x__c_a_l_l_e_r__i_d (Any): Caller ID can be used to trace the caller for queries executed on database. The caller id is like a optional attribute which can be added to API invocation like ui, python, postman, test-automation etc

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/intent/api/v1/customIssueDefinitions/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_system_api_v1_event_artifact(self, event_ids: Optional[Any] = None, tags: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None, sort_by: Optional[Any] = None, order: Optional[Any] = None, search: Optional[Any] = None) -> Dict[str, Any]:
        """Get EventArtifacts

        Gets the list of artifacts based on provided offset and limit

        Args:
            event_ids (Any): List of eventIds
            tags (Any): Tags defined
            offset (Any): Record start offset
            limit (Any): # of records to return in result set
            sort_by (Any): Sort by field
            order (Any): sorting order (asc/desc)
            search (Any): findd matches in name, description, eventId, type, category

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/system/api/v1/event/artifact'
        params = {
            'eventIds': event_ids,
            'tags': tags,
            'offset': offset,
            'limit': limit,
            'sortBy': sort_by,
            'order': order,
            'search': search,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_template_programmer_project_project_id(self, project_id: Any) -> Dict[str, Any]:
        """Deletes the project

        Deletes the project by its id

        Args:
            project_id (Any): projectId(UUID) of project to be deleted

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/template-programmer/project/{project_id}'
        url = url.format(project_id=project_id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_template_programmer_project_project_id(self, project_id: Any) -> Dict[str, Any]:
        """Gets the details of a given project.

        Get the details of the given project by its id.

        Args:
            project_id (Any): projectId(UUID) of project to get project details

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/template-programmer/project/{project_id}'
        url = url.format(project_id=project_id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_network_profiles_for_sites_profile_id_site_assignments_id(self, profile_id: Any, id: Any) -> Dict[str, Any]:
        """Unassigns a network profile for sites from a site

        Unassigns a given network profile for sites from a site. The profile must be removed from parent sites first, otherwise this operation will not ulimately  unassign the profile.

        Args:
            profile_id (Any): The `id` of the network profile, retrievable from `GET /intent/api/v1/networkProfilesForSites`
            id (Any): The `id` of the site, retrievable from `GET /intent/api/v1/networkProfilesForSites/{id}/siteAssignments`

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/networkProfilesForSites/{profile_id}/siteAssignments/{id}'
        url = url.format(profile_id=profile_id, id=id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_diagnostic_validation_workflows_id(self, id: Any) -> Dict[str, Any]:
        """Deletes a validation workflow

        Deletes the workflow for the given id


        Args:
            id (Any): Workflow id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/diagnosticValidationWorkflows/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_diagnostic_validation_workflows_id(self, id: Any) -> Dict[str, Any]:
        """Retrieves validation workflow details

        Retrieves workflow details for a workflow id


        Args:
            id (Any): Workflow id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/diagnosticValidationWorkflows/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_device_module_count(self, device_id: Any, name_list: Optional[Any] = None, vendor_equipment_type_list: Optional[Any] = None, part_number_list: Optional[Any] = None, operational_state_code_list: Optional[Any] = None) -> Dict[str, Any]:
        """Get Module count

        Returns Module Count

        Args:
            device_id (Any): deviceId
            name_list (Any): nameList
            vendor_equipment_type_list (Any): vendorEquipmentTypeList
            part_number_list (Any): partNumberList
            operational_state_code_list (Any): operationalStateCodeList

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device/module/count'
        params = {
            'deviceId': device_id,
            'nameList': name_list,
            'vendorEquipmentTypeList': vendor_equipment_type_list,
            'partNumberList': part_number_list,
            'operationalStateCodeList': operational_state_code_list,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_sda_provision_devices_id(self, id: Any) -> Dict[str, Any]:
        """Delete provisioned device by Id

        Deletes provisioned device based on Id.

        Args:
            id (Any): ID of the provisioned device.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/provisionDevices/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_image_distribution(self, content__type: Any) -> Dict[str, Any]:
        """Trigger software image distribution

        Distributes a software image on a given device. Software image must be imported successfully into DNA Center before it can be distributed

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/image/distribution'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sda_transit_networks_count(self, type: Optional[Any] = None) -> Dict[str, Any]:
        """Get transit networks count

        Returns the count of transit networks that match the provided query parameters.

        Args:
            type (Any): Type of the transit network. Allowed values are [IP_BASED_TRANSIT, SDA_LISP_PUB_SUB_TRANSIT, SDA_LISP_BGP_TRANSIT].

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/transitNetworks/count'
        params = {
            'type': type,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v2_lan_automation_id(self, content__type: Any, id: Any) -> Dict[str, Any]:
        """LAN Automation Stop and Update Devices V2

        Invoke this API to stop LAN Automation and update device parameters such as Loopback0 IP address and/or hostname discovered in the current session. 

        Args:
            content__type (Any): Request body content type
            id (Any): LAN Automation id can be obtained from /dna/intent/api/v1/lan-automation/status.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v2/lan-automation/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sda_fabrics_vlan_to_ssids(self, limit: Optional[Any] = None, offset: Optional[Any] = None) -> Dict[str, Any]:
        """Returns all the Fabric Sites that have VLAN to SSID mapping.

        It will return all vlan to SSID mapping across all the fabric site

        Args:
            limit (Any): Return only this many IP Pool to SSID Mapping
            offset (Any): Number of records to skip for pagination

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/fabrics/vlanToSsids'
        params = {
            'limit': limit,
            'offset': offset,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_licenses_device_count(self, device_type: Optional[Any] = None, registration_status: Optional[Any] = None, dna_level: Optional[Any] = None, virtual_account_name: Optional[Any] = None, smart_account_id: Optional[Any] = None) -> Dict[str, Any]:
        """Device Count Details

        Get total number of managed device(s).

        Args:
            device_type (Any): Type of device
            registration_status (Any): Smart license registration status of device
            dna_level (Any): Device Cisco DNA License Level
            virtual_account_name (Any): Virtual account name
            smart_account_id (Any): Smart account id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/licenses/device/count'
        params = {
            'device_type': device_type,
            'registration_status': registration_status,
            'dna_level': dna_level,
            'virtual_account_name': virtual_account_name,
            'smart_account_id': smart_account_id,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_data_reports_report_id_executions(self, report_id: Any) -> Dict[str, Any]:
        """Get all execution details for a given report

        Get details of all executions for a given report

        Args:
            report_id (Any): reportId of report

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/data/reports/{report_id}/executions'
        url = url.format(report_id=report_id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_event_subscription_rest(self, content__type: Any) -> Dict[str, Any]:
        """Create Rest/Webhook Event Subscription

        Create Rest/Webhook Subscription Endpoint for list of registered events

        Args:
            content__type (Any): Content Type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/event/subscription/rest'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_event_subscription_rest(self, content__type: Any) -> Dict[str, Any]:
        """Update Rest/Webhook Event Subscription

        Update Rest/Webhook Subscription Endpoint for list of registered events

        Args:
            content__type (Any): Content Type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/event/subscription/rest'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_event_subscription_rest(self, event_ids: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None, sort_by: Optional[Any] = None, order: Optional[Any] = None, domain: Optional[Any] = None, sub_domain: Optional[Any] = None, category: Optional[Any] = None, type: Optional[Any] = None, name: Optional[Any] = None) -> Dict[str, Any]:
        """Get Rest/Webhook Event Subscriptions

        Gets the list of Rest/Webhook Subscriptions's based on provided query params

        Args:
            event_ids (Any): List of subscriptions related to the respective eventIds (Comma separated event ids)
            offset (Any): The number of Subscriptions's to offset in the resultset whose default value 0
            limit (Any): The number of Subscriptions's to limit in the resultset whose default value 10
            sort_by (Any): SortBy field name
            order (Any): order(asc/desc)
            domain (Any): List of subscriptions related to the respective domain
            sub_domain (Any): List of subscriptions related to the respective sub-domain
            category (Any): List of subscriptions related to the respective category
            type (Any): List of subscriptions related to the respective type
            name (Any): List of subscriptions related to the respective name

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/event/subscription/rest'
        params = {
            'eventIds': event_ids,
            'offset': offset,
            'limit': limit,
            'sortBy': sort_by,
            'order': order,
            'domain': domain,
            'subDomain': sub_domain,
            'category': category,
            'type': type,
            'name': name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_system_api_v1_roles(self, invoke_source: Any) -> Dict[str, Any]:
        """Get roles API

        Get all roles for the Cisco DNA Center System.

        Args:
            invoke_source (Any): The source that invokes this API. The value of this header must be set to "external".

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if invoke_source is not None:
            request_headers['invokeSource'] = str(invoke_source)
        url = self.base_url + '/dna/system/api/v1/roles'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v2_applications_id(self, id: Any) -> Dict[str, Any]:
        """Delete Application

        Delete existing custom application by id

        Args:
            id (Any): Id of custom application to delete

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v2/applications/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_image_importation_golden_site_site_id_family_device_family_identifier_role_device_role_image_image_id(self, accept: Any, site_id: Any, device_family_identifier: Any, device_role: Any, image_id: Any) -> Dict[str, Any]:
        """Get Golden Tag Status of an Image.

        Get golden tag status of an image. Set siteId as -1 for Global site.

        Args:
            accept (Any): MIME type / MIME subtype Consumed
            site_id (Any): Site Id in uuid format. Set siteId as -1 for Global site.
            device_family_identifier (Any): Device family identifier e.g. : 277696480-283933147, e.g. : 277696480
            device_role (Any): Device Role. Permissible Values : ALL, UNKNOWN, ACCESS, BORDER ROUTER, DISTRIBUTION and CORE.
            image_id (Any): Image Id in uuid format.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if accept is not None:
            request_headers['Accept'] = str(accept)
        url = self.base_url + '/dna/intent/api/v1/image/importation/golden/site/{site_id}/family/{device_family_identifier}/role/{device_role}/image/{image_id}'
        url = url.format(site_id=site_id, device_family_identifier=device_family_identifier, device_role=device_role, image_id=image_id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_image_importation_golden_site_site_id_family_device_family_identifier_role_device_role_image_image_id(self, site_id: Any, device_family_identifier: Any, device_role: Any, image_id: Any, accept: Optional[Any] = None) -> Dict[str, Any]:
        """Remove Golden Tag for image.

        Remove golden tag. Set siteId as -1 for Global site.

        Args:
            site_id (Any): Site Id in uuid format. Set siteId as -1 for Global site.
            device_family_identifier (Any): Device family identifier e.g. : 277696480-283933147, e.g. : 277696480
            device_role (Any): Device Role. Permissible Values : ALL, UNKNOWN, ACCESS, BORDER ROUTER, DISTRIBUTION and CORE.
            image_id (Any): Image Id in uuid format.
            accept (Any): MIME type / MIME subtype Consumed

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if accept is not None:
            request_headers['Accept'] = str(accept)
        url = self.base_url + '/dna/intent/api/v1/image/importation/golden/site/{site_id}/family/{device_family_identifier}/role/{device_role}/image/{image_id}'
        url = url.format(site_id=site_id, device_family_identifier=device_family_identifier, device_role=device_role, image_id=image_id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sda_port_channels_count(self, fabric_id: Optional[Any] = None, network_device_id: Optional[Any] = None, port_channel_name: Optional[Any] = None, connected_device_type: Optional[Any] = None) -> Dict[str, Any]:
        """Get port channel count

        Returns the count of port channels that match the provided query parameters.

        Args:
            fabric_id (Any): ID of the fabric the device is assigned to.
            network_device_id (Any): ID of the network device.
            port_channel_name (Any): Name of the port channel.
            connected_device_type (Any): Connected device type of the port channel. The allowed values are [TRUNK, EXTENDED_NODE].

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/portChannels/count'
        params = {
            'fabricId': fabric_id,
            'networkDeviceId': network_device_id,
            'portChannelName': port_channel_name,
            'connectedDeviceType': connected_device_type,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_maps_supported_access_points(self) -> Dict[str, Any]:
        """Maps Supported Access Points

        Gets the list of supported access point types as well as valid antenna pattern names that can be used for each.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/maps/supported-access-points'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_data_api_v1_event_event_series_audit_log_parent_records(self, instance_id: Optional[Any] = None, name: Optional[Any] = None, event_id: Optional[Any] = None, category: Optional[Any] = None, severity: Optional[Any] = None, domain: Optional[Any] = None, sub_domain: Optional[Any] = None, source: Optional[Any] = None, user_id: Optional[Any] = None, context: Optional[Any] = None, event_hierarchy: Optional[Any] = None, site_id: Optional[Any] = None, device_id: Optional[Any] = None, is_system_events: Optional[Any] = None, description: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None, start_time: Optional[Any] = None, end_time: Optional[Any] = None, sort_by: Optional[Any] = None, order: Optional[Any] = None) -> Dict[str, Any]:
        """Get AuditLog Parent Records

        Get Parent Audit Log Event instances from the Event-Hub 

        Args:
            instance_id (Any): InstanceID of the Audit Log.
            name (Any): Audit Log notification event name.
            event_id (Any): Audit Log notification's event ID. 
            category (Any): Audit Log notification's event category. Supported values: INFO, WARN, ERROR, ALERT, TASK_PROGRESS, TASK_FAILURE, TASK_COMPLETE, COMMAND, QUERY, CONVERSATION
            severity (Any): Audit Log notification's event severity. Supported values: 1, 2, 3, 4, 5.
            domain (Any): Audit Log notification's event domain.
            sub_domain (Any): Audit Log notification's event sub-domain.
            source (Any): Audit Log notification's event source.
            user_id (Any): Audit Log notification's event userId.
            context (Any): Audit Log notification's event correlationId.
            event_hierarchy (Any): Audit Log notification's event eventHierarchy. Example: "US.CA.San Jose" OR "US.CA" OR "CA.San Jose" - Delimiter for hierarchy separation is ".".
            site_id (Any): Audit Log notification's siteId.
            device_id (Any): Audit Log notification's deviceId.
            is_system_events (Any): Parameter to filter system generated audit-logs.
            description (Any): String full/partial search - (Provided input string is case insensitively matched for records).
            offset (Any): Position of a particular Audit Log record in the data. 
            limit (Any): Number of Audit Log records to be returned per page.
            start_time (Any): Start Time in milliseconds since Epoch Eg. 1597950637211 (when provided endTime is mandatory)
            end_time (Any): End Time in milliseconds since Epoch Eg. 1597961437211 (when provided startTime is mandatory)
            sort_by (Any): Sort the Audit Logs by certain fields. Supported values are event notification header attributes.
            order (Any): Order of the sorted Audit Log records. Default value is desc by timestamp. Supported values: asc, desc.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/data/api/v1/event/event-series/audit-log/parent-records'
        params = {
            'instanceId': instance_id,
            'name': name,
            'eventId': event_id,
            'category': category,
            'severity': severity,
            'domain': domain,
            'subDomain': sub_domain,
            'source': source,
            'userId': user_id,
            'context': context,
            'eventHierarchy': event_hierarchy,
            'siteId': site_id,
            'deviceId': device_id,
            'isSystemEvents': is_system_events,
            'description': description,
            'offset': offset,
            'limit': limit,
            'startTime': start_time,
            'endTime': end_time,
            'sortBy': sort_by,
            'order': order,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_sites_id_dns_settings(self, content__type: Any, id: Any) -> Dict[str, Any]:
        """Set DNS settings for a site

        Set DNS settings for a site; `null` values indicate that the setting will be inherited from the parent site; empty objects (`{}`) indicate that the settings is unset.

        Args:
            content__type (Any): Request body content type
            id (Any): Site Id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sites/{id}/dnsSettings'
        url = url.format(id=id)
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sites_id_dns_settings(self, id: Any, inherited: Optional[Any] = None) -> Dict[str, Any]:
        """Retrieve DNS settings for a site

        Retrieve DNS settings for a site; `null` values indicate that the setting will be inherited from the parent site; empty objects (`{}`) indicate that the setting is unset at a site.

        Args:
            id (Any): Site Id
            inherited (Any): Include settings explicitly set for this site and settings inherited from sites higher in the site hierarchy; when `false`, `null` values indicate that the site inherits that setting from the parent site or a site higher in the site hierarchy.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sites/{id}/dnsSettings'
        url = url.format(id=id)
        params = {
            '_inherited': inherited,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_global_credential_cli(self, content__type: Any) -> Dict[str, Any]:
        """Create CLI credentials

        Adds global CLI credential

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/global-credential/cli'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_global_credential_cli(self, content__type: Any) -> Dict[str, Any]:
        """Update CLI credentials

        Updates global CLI credentials

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/global-credential/cli'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_health_score_definitions_id(self, id: Any, x__c_a_l_l_e_r__i_d: Optional[Any] = None) -> Dict[str, Any]:
        """Get health score definition for the given id.

        Get health score defintion for the given id. Definition includes all properties from HealthScoreDefinition schema by default. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-issueAndHealthDefinitions-1.0.0-resolved.yaml


        Args:
            id (Any): Health score definition id.
            x__c_a_l_l_e_r__i_d (Any): Caller ID is used to trace the origin of API calls and their associated queries executed on the database. It's an optional header parameter that can be added to an API request.


        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/intent/api/v1/healthScoreDefinitions/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_health_score_definitions_id(self, content__type: Any, id: Any, x__c_a_l_l_e_r__i_d: Optional[Any] = None) -> Dict[str, Any]:
        """Update health score definition for the given id.

        Update health threshold, include status of overall health status.

And also to synchronize with global profile issue thresholds of the definition for given id. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-issueAndHealthDefinitions-1.0.0-resolved.yaml


        Args:
            content__type (Any): Request body content type
            id (Any): Health score definition id.
            x__c_a_l_l_e_r__i_d (Any): Caller ID is used to trace the origin of API calls and their associated queries executed on the database. It's an optional header parameter that can be added to an API request.


        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/intent/api/v1/healthScoreDefinitions/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v2_template_programmer_project(self, id: Optional[Any] = None, name: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None, sort_order: Optional[Any] = None) -> Dict[str, Any]:
        """Get project(s) details

        Get project(s) details

        Args:
            id (Any): Id of project to be searched
            name (Any): Name of project to be searched
            offset (Any): Index of first result
            limit (Any): Limits number of results
            sort_order (Any): Sort Order Ascending (asc) or Descending (dsc)

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v2/template-programmer/project'
        params = {
            'id': id,
            'name': name,
            'offset': offset,
            'limit': limit,
            'sortOrder': sort_order,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_lan_automation(self, content__type: Any) -> Dict[str, Any]:
        """LAN Automation Start

        Invoke this API to start LAN Automation for the given site.

        Args:
            content__type (Any): 

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/lan-automation'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_file_file_id(self, file_id: Any) -> Dict[str, Any]:
        """Download a file by fileId

        Downloads a file specified by fileId

        Args:
            file_id (Any): File Identification number

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/file/{file_id}'
        url = url.format(file_id=file_id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_health_score_definitions(self, x__c_a_l_l_e_r__i_d: Optional[Any] = None, device_type: Optional[Any] = None, id: Optional[Any] = None, include_for_overall_health: Optional[Any] = None, attribute: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None) -> Dict[str, Any]:
        """Get all health score definitions for given filters.

        Get all health score defintions.

Supported filters are id, name and overall health include status. A health score definition can be different across device type. So, deviceType in the query param is important and default is all device types.

By default all supported attributes are listed in response. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-issueAndHealthDefinitions-1.0.0-resolved.yaml


        Args:
            x__c_a_l_l_e_r__i_d (Any): Caller ID is used to trace the origin of API calls and their associated queries executed on the database. It's an optional header parameter that can be added to an API request.

            device_type (Any): These are the device families supported for health score definitions. If no input is made on device family, all device families are considered.
            id (Any): The definition identifier.

Examples:

id=015d9cba-4f53-4087-8317-7e49e5ffef46 (single entity id request)

id=015d9cba-4f53-4087-8317-7e49e5ffef46&id=015d9cba-4f53-4087-8317-7e49e5ffef47 (multiple ids in the query param)

            include_for_overall_health (Any): The inclusion status of the issue definition, either true or false. true indicates that particular health metric is included in overall health computation, otherwise false. By default it's set to true. 
            attribute (Any): These are the attributes supported in health score definitions response. By default, all properties are sent in response.

            offset (Any): Specifies the starting point within all records returned by the API. It's one based offset. The starting value is 1.
            limit (Any): Maximum number of records to return

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/intent/api/v1/healthScoreDefinitions'
        params = {
            'deviceType': device_type,
            'id': id,
            'includeForOverallHealth': include_for_overall_health,
            'attribute': attribute,
            'offset': offset,
            'limit': limit,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_event_email_config(self, content__type: Any) -> Dict[str, Any]:
        """Update Email Destination

        Update Email Destination

        Args:
            content__type (Any): Content Type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/event/email-config'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_event_email_config(self, content__type: Any) -> Dict[str, Any]:
        """Create Email Destination

        Create Email Destination

        Args:
            content__type (Any): Content Type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/event/email-config'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_event_email_config(self) -> Dict[str, Any]:
        """Get Email Destination

        Get Email Destination

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/event/email-config'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_data_api_v1_interfaces(self, start_time: Optional[Any] = None, end_time: Optional[Any] = None, limit: Optional[Any] = None, offset: Optional[Any] = None, sort_by: Optional[Any] = None, order: Optional[Any] = None, site_hierarchy: Optional[Any] = None, site_hierarchy_id: Optional[Any] = None, site_id: Optional[Any] = None, view: Optional[Any] = None, attribute: Optional[Any] = None, network_device_id: Optional[Any] = None, network_device_ip_address: Optional[Any] = None, network_device_mac_address: Optional[Any] = None, interface_id: Optional[Any] = None, interface_name: Optional[Any] = None) -> Dict[str, Any]:
        """Gets interfaces along with statistics data from all network devices.

        Retrieves the list of the interfaces from all network devices based on the provided query parameters. The latest interfaces data in the specified start and end time range will be returned. When there is no start and end time specified returns the latest available data.

The elements are grouped and sorted by deviceUuid first, and are then sorted by the given sort field, or by the default value: name.

 The supported sorting options are: name, adminStatus, description, duplexConfig, duplexOper,interfaceIfIndex,interfaceType, macAddress,mediaType, operStatus,portChannelId, portMode, portType,speed, vlanId. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-interfaces-1.0.2-resolved.yaml

        Args:
            start_time (Any): Start time from which API queries the data set related to the resource. It must be specified in UNIX epochtime in milliseconds. Value is inclusive.

If `startTime` is not provided, API will default to current time.

            end_time (Any): End time to which API queries the data set related to the resource. It must be specified in UNIX epochtime in milliseconds. Value is inclusive.

            limit (Any): Maximum number of records to return
            offset (Any): Specifies the starting point within all records returned by the API. It's one based offset. The starting value is 1.
            sort_by (Any): A field within the response to sort by.
            order (Any): The sort order of the field ascending or descending.
            site_hierarchy (Any): The full hierarchical breakdown of the site tree starting from Global site name and ending with the specific site name. The Root site is named "Global" (Ex. `Global/AreaName/BuildingName/FloorName`)

This field supports wildcard asterisk (`*`) character search support. E.g. `*/San*, */San, /San*`

Examples:

`?siteHierarchy=Global/AreaName/BuildingName/FloorName` (single siteHierarchy requested)

`?siteHierarchy=Global/AreaName/BuildingName/FloorName&siteHierarchy=Global/AreaName2/BuildingName2/FloorName2` (multiple siteHierarchies requested)

            site_hierarchy_id (Any): The full hierarchy breakdown of the site tree in id form starting from Global site UUID and ending with the specific site UUID. (Ex. `globalUuid/areaUuid/buildingUuid/floorUuid`)

This field supports wildcard asterisk (`*`) character search support. E.g. `*uuid*, *uuid, uuid*`

Examples:

`?siteHierarchyId=globalUuid/areaUuid/buildingUuid/floorUuid `(single siteHierarchyId requested)

`?siteHierarchyId=globalUuid/areaUuid/buildingUuid/floorUuid&siteHierarchyId=globalUuid/areaUuid2/buildingUuid2/floorUuid2` (multiple siteHierarchyIds requested)

            site_id (Any): The UUID of the site. (Ex. `flooruuid`)

Examples:

`?siteId=id1` (single id requested)

`?siteId=id1&siteId=id2&siteId=id3` (multiple ids requested)

            view (Any): The specific summary view being requested. This is an optional parameter which can be passed to get one or more of the specific view associated fields. The default view is ``configuration``.

### Response data proviced by each view:  

1. **configuration**
[id,adminStatus,description,duplexConfig,duplexOper,interfaceIfIndex,interfaceType,ipv4Address,ipv6AddressList,isL3Interface,isWan,macAddress,mediaType,name,operStatus, portChannelId,portMode, portType,speed,timestamp,vlanId,networkDeviceId,networkDeviceIpAddress,networkDeviceMacAddress,siteName,siteHierarchy,siteHierarchyId]  

2. **statistics**
[id,name,rxDiscards,rxError,rxRate,rxUtilization,txDiscards,txError,txRate,txUtilization,networkDeviceId,networkDeviceIpAddress,networkDeviceMacAddress,siteName,siteHierarchy,siteHierarchyId]  

3. **stackPort**
[id,name,peerStackMember,peerStackPort,stackPortType,networkDeviceId,networkDeviceIpAddress,networkDeviceMacAddress,siteName,siteHierarchy,siteHierarchyId]  

The default view is configuration, If need to access an additional view, simply include the view name in the query parameter.

Examples:

view=configuration (single view requested)

view=configuration&view=statistic&stackPort (multiple views requested)

            attribute (Any): The following list of attributes can be provided in the attribute field

[id,adminStatus, description,duplexConfig,duplexOper,interfaceIfIndex,interfaceType,ipv4Address,ipv6AddressList,isL3Interface,isWan,macAddress,mediaType,name,operStatus,peerStackMember,peerStackPort, portChannelId,portMode, portType,rxDiscards,rxError,rxRate,rxUtilization,speed,stackPortType,timestamp,txDiscards,txError,txRate,txUtilization,vlanId,networkDeviceId,networkDeviceIpAddress,networkDeviceMacAddress,siteName,siteHierarchy,siteHierarchyId]

If length of attribute list is too long, please use 'views' param instead.

Examples:

attributes=name (single attribute requested)

attributes=name,description,duplexOper (multiple attributes with comma separator)

            network_device_id (Any): The list of Network Device Uuids. (Ex. `6bef213c-19ca-4170-8375-b694e251101c`)

Examples:

`networkDeviceId=6bef213c-19ca-4170-8375-b694e251101c` (single networkDeviceId requested)

`networkDeviceId=6bef213c-19ca-4170-8375-b694e251101c&networkDeviceId=32219612-819e-4b5e-a96b-cf22aca13dd9&networkDeviceId=2541e9a7-b80d-4955-8aa2-79b233318ba0` (multiple networkDeviceIds with & separator)

            network_device_ip_address (Any): The list of Network Device management IP Address. (Ex. `121.1.1.10`)

This field supports wildcard (`*`) character-based search. 
Ex: `*1.1*` or `1.1*` or `*1.1`

Examples:

`networkDeviceIpAddress=121.1.1.10`

`networkDeviceIpAddress=121.1.1.10&networkDeviceIpAddress=172.20.1.10&networkDeviceIpAddress=10.10.20.10` (multiple networkDevice IP Address with & separator)

            network_device_mac_address (Any): The list of Network Device MAC Address. (Ex. `64:f6:9d:07:9a:00`)

This field supports wildcard (`*`) character-based search. 
Ex: `*AB:AB:AB*` or `AB:AB:AB*` or `*AB:AB:AB`

Examples:

`networkDeviceMacAddress=64:f6:9d:07:9a:00`

`networkDeviceMacAddress=64:f6:9d:07:9a:00&networkDeviceMacAddress=70:56:9d:07:ac:77` (multiple networkDevice MAC addresses with & separator)

            interface_id (Any): The list of Interface Uuids. (Ex. `6bef213c-19ca-4170-8375-b694e251101c`)

Examples:

`interfaceId=6bef213c-19ca-4170-8375-b694e251101c` (single interface uuid )

`interfaceId=6bef213c-19ca-4170-8375-b694e251101c&32219612-819e-4b5e-a96b-cf22aca13dd9&2541e9a7-b80d-4955-8aa2-79b233318ba0` (multiple Interface uuid with & separator)

            interface_name (Any): The list of Interface name (Ex. `GigabitEthernet1/0/1`)
This field supports wildcard (`*`) character-based search. 
Ex: `*1/0/1*` or `1/0/1*` or `*1/0/1`

Examples:

`interfaceNames=GigabitEthernet1/0/1` (single interface name)

`interfaceNames=GigabitEthernet1/0/1&GigabitEthernet2/0/1&GigabitEthernet3/0/1` (multiple interface names with & separator)


        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/data/api/v1/interfaces'
        params = {
            'startTime': start_time,
            'endTime': end_time,
            'limit': limit,
            'offset': offset,
            'sortBy': sort_by,
            'order': order,
            'siteHierarchy': site_hierarchy,
            'siteHierarchyId': site_hierarchy_id,
            'siteId': site_id,
            'view': view,
            'attribute': attribute,
            'networkDeviceId': network_device_id,
            'networkDeviceIpAddress': network_device_ip_address,
            'networkDeviceMacAddress': network_device_mac_address,
            'interfaceId': interface_id,
            'interfaceName': interface_name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_license_setting(self) -> Dict[str, Any]:
        """Update license setting

        Update license setting - Configure default smart account id  and/or virtual account id for auto registration of devices for smart license flow. Virtual account should be part of default smart account. Default smart account id cannot be set to 'null'. Auto registration of devices for smart license flow is applicable only for direct or on-prem SSM connection mode.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/licenseSetting'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_license_setting(self) -> Dict[str, Any]:
        """Retrieve license setting

        Retrieves license setting - Default smart account id and virtual account id for auto registration of devices for smart license flow. If default smart account is not configured, 'defaultSmartAccountId' is 'null'. Similarly, if auto registration of devices for smart license flow is not enabled, 'autoRegistrationVirtualAccountId' is 'null'. For smart proxy connection mode, 'autoRegistrationVirtualAccountId' is always 'null'.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/licenseSetting'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_onboarding_pnp_device_reset(self, content__type: Any) -> Dict[str, Any]:
        """Reset Device

        Recovers a device from a Workflow Execution Error state

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/onboarding/pnp-device/reset'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def post_dna_data_api_v1_assurance_issues_query(self, content__type: Any, accept__language: Optional[Any] = None, x__c_a_l_l_e_r__i_d: Optional[Any] = None) -> Dict[str, Any]:
        """Get the details of issues for given set of filters

        Returns all details of each issue along with suggested actions for given set of filters specified in request body. If there is no start and/or end time, then end time will be defaulted to current time and start time will be defaulted to 24-hours ago from end time. https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-IssuesList-1.0.0-resolved.yaml

        Args:
            content__type (Any): Request body content type
            accept__language (Any): This header parameter can be used to specify the language in which issue description and suggested actions need to be returned. Available options are - 'en' (English), 'ja' (Japanese), 'ko' (Korean), 'zh' (Chinese). If this parameter is not present the issue details are returned in English language.
            x__c_a_l_l_e_r__i_d (Any): Caller ID can be used to trace the caller for queries executed on database. The caller id is like a optional attribute which can be added to API invocation like ui, python, postman, test-automation etc

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        if accept__language is not None:
            request_headers['Accept-Language'] = str(accept__language)
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/data/api/v1/assuranceIssues/query'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_wireless_controllers_device_id_provision(self, content__type: Any, device_id: Any) -> Dict[str, Any]:
        """Wireless Controller Provision

        This API is used to provision wireless controller

        Args:
            content__type (Any): Content Type
            device_id (Any): Network Device ID. This value can be obtained by using the API call GET: /dna/intent/api/v1/network-device/ip-address/${ipAddress}

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/wirelessControllers/{device_id}/provision'
        url = url.format(device_id=device_id)
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_custom_issue_definitions_count(self, x__c_a_l_l_e_r__i_d: Optional[Any] = None, id: Optional[Any] = None, profile_id: Optional[Any] = None, name: Optional[Any] = None, priority: Optional[Any] = None, is_enabled: Optional[Any] = None, severity: Optional[Any] = None, facility: Optional[Any] = None, mnemonic: Optional[Any] = None) -> Dict[str, Any]:
        """Get the total custom issue definitions count based on the provided filters.

        Get the total number of Custom issue definitions count based on the provided filters. The supported filters are id, name, profileId and definition enable status, severity, facility and mnemonic. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-AssuranceUserDefinedIssueAPIs-1.0.0-resolved.yaml


        Args:
            x__c_a_l_l_e_r__i_d (Any): Caller ID can be used to trace the caller for queries executed on database. The caller id is like a optional attribute which can be added to API invocation like ui, python, postman, test-automation etc   
            id (Any): The custom issue definition identifier and unique identifier across the profile.
Examples: id=6bef213c-19ca-4170-8375-b694e251101c (single entity uuid requested) id=6bef213c-19ca-4170-8375-b694e251101c&id=19ca-4170-8375-b694e251101c-6bef213c (multiple Id request in the query param)

            profile_id (Any): The profile identifier to fetch the profile associated custom issue definitions. The default is global. For the custom profile, it is profile UUID. Example : 3fa85f64-5717-4562-b3fc-2c963f66afa6

            name (Any): The list of UDI issue names. (Ex."TestUdiIssues")

            priority (Any): The Issue priority value, possible values are P1, P2, P3, P4. P1: A critical issue that needs immediate attention and can have a wide impact on network operations. P2: A major issue that can potentially impact multiple devices or clients. P3: A minor issue that has a localized or minimal impact. P4: A warning issue that may not be an immediate problem but addressing it can optimize the network performance
            is_enabled (Any): The enable status of the custom issue definition, either true or false.
            severity (Any): The syslog severity level. 0: Emergency 1: Alert, 2: Critical. 3: Error, 4: Warning, 5: Notice, 6: Info. Examples:severity=1&severity=2 (multi value support with & separator)

            facility (Any): The syslog facility name
            mnemonic (Any): The syslog mnemonic name

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/intent/api/v1/customIssueDefinitions/count'
        params = {
            'id': id,
            'profileId': profile_id,
            'name': name,
            'priority': priority,
            'isEnabled': is_enabled,
            'severity': severity,
            'facility': facility,
            'mnemonic': mnemonic,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_wireless_settings_dot11be_profiles_count(self) -> Dict[str, Any]:
        """Get 802.11be Profiles Count

        This API allows the user to get count of all 802.11be Profile(s)

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/wirelessSettings/dot11beProfiles/count'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_sda_multicast(self, content__type: Any) -> Dict[str, Any]:
        """Update multicast

        Updates a multicast configuration at a fabric level based on user input.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sda/multicast'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sda_multicast(self, fabric_id: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None) -> Dict[str, Any]:
        """Get multicast

        Returns a list of multicast configurations at a fabric site level that match the provided query parameters.

        Args:
            fabric_id (Any): ID of the fabric site where multicast is configured.
            offset (Any): Starting record for pagination.
            limit (Any): Maximum number of records to return.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/multicast'
        params = {
            'fabricId': fabric_id,
            'offset': offset,
            'limit': limit,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_network_devices_assign_to_site_apply(self, content__type: Any) -> Dict[str, Any]:
        """Assign network devices to a site

        Assign unprovisioned network devices to a site. Along with that it can also be used to assign unprovisioned network devices to a different site. If device controllability is enabled, it will be triggered once device assigned to site successfully. Device Controllability can be enabled/disabled using `/dna/intent/api/v1/networkDevices/deviceControllability/settings`.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/networkDevices/assignToSite/apply'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sda_fabric_devices_count(self, fabric_id: Any, network_device_id: Optional[Any] = None, device_roles: Optional[Any] = None) -> Dict[str, Any]:
        """Get fabric devices count

        Returns the count of fabric devices that match the provided query parameters.

        Args:
            fabric_id (Any): ID of the fabric this device belongs to.
            network_device_id (Any): Network device ID of the fabric device.
            device_roles (Any): Device roles of the fabric device. Allowed values are [CONTROL_PLANE_NODE, EDGE_NODE, BORDER_NODE, WIRELESS_CONTROLLER_NODE, EXTENDED_NODE].

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/fabricDevices/count'
        params = {
            'fabricId': fabric_id,
            'networkDeviceId': network_device_id,
            'deviceRoles': device_roles,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_data_api_v1_flexible_report_report_content_report_id_execution_id(self, content__type: Any, report_id: Any, execution_id: Any) -> Dict[str, Any]:
        """Download Flexible Report

        This is used to download the flexible report. The API returns report content. Save the response to a file by converting the response data as a blob and setting the file format available from content-disposition response header.

        Args:
            content__type (Any): Request body content type
            report_id (Any): Id of the report
            execution_id (Any): Id of execution

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/data/api/v1/flexible-report/report/content/{report_id}/{execution_id}'
        url = url.format(report_id=report_id, execution_id=execution_id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_template_programmer_template_exporttemplates(self, content__type: Any) -> Dict[str, Any]:
        """Exports the templates for a given criteria.

        Exports the templates for given templateIds.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/template-programmer/template/exporttemplates'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_system_api_v1_users_external_servers(self, invoke_source: Any) -> Dict[str, Any]:
        """Get external authentication servers API

        Get external users authentication servers.

        Args:
            invoke_source (Any): The source that invokes this API. The value of this query parameter must be set to "external".

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/system/api/v1/users/external-servers'
        params = {
            'invokeSource': invoke_source,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sda_layer3_virtual_networks_count(self, fabric_id: Optional[Any] = None, anchored_site_id: Optional[Any] = None) -> Dict[str, Any]:
        """Get layer 3 virtual networks count

        Returns the count of layer 3 virtual networks that match the provided query parameters.

        Args:
            fabric_id (Any): ID of the fabric the layer 3 virtual network is assigned to.
            anchored_site_id (Any): Fabric ID of the fabric site the layer 3 virtual network is anchored at.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/layer3VirtualNetworks/count'
        params = {
            'fabricId': fabric_id,
            'anchoredSiteId': anchored_site_id,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_data_api_v1_interfaces_query_count(self, content__type: Any) -> Dict[str, Any]:
        """The Total interfaces count across the Network devices.

        Gets the total number of interfaces across the Network devices based on the provided complex filters and aggregation functions. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-interfaces-1.0.2-resolved.yaml

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/data/api/v1/interfaces/query/count'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_lan_automation_status(self, offset: Optional[Any] = None, limit: Optional[Any] = None) -> Dict[str, Any]:
        """LAN Automation Status

        Invoke this API to get the LAN Automation session status. 

        Args:
            offset (Any): Starting index of the LAN Automation session. Minimum value is 1.
            limit (Any): Number of LAN Automation sessions to be retrieved. Limit value can range between 1 to 10.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/lan-automation/status'
        params = {
            'offset': offset,
            'limit': limit,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_licenses_smart_account_virtual_account_virtual_account_name_register(self, virtual_account_name: Any) -> Dict[str, Any]:
        """Device Registration

        Register device(s) in CSSM(Cisco Smart Software Manager).

        Args:
            virtual_account_name (Any): Name of virtual account

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/licenses/smartAccount/virtualAccount/{virtual_account_name}/register'
        url = url.format(virtual_account_name=virtual_account_name)
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_discovery_id_network_device_count(self, id: Any, task_id: Optional[Any] = None) -> Dict[str, Any]:
        """Get Devices discovered by Id

        Returns the count of network devices discovered in the given discovery. Discovery ID can be obtained using the "Get Discoveries by range" API.

        Args:
            id (Any): Discovery ID
            task_id (Any): taskId

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/discovery/{id}/network-device/count'
        url = url.format(id=id)
        params = {
            'taskId': task_id,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_task_task_id(self, task_id: Any) -> Dict[str, Any]:
        """Get task by Id

        Returns a task by specified id

        Args:
            task_id (Any): UUID of the Task

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/task/{task_id}'
        url = url.format(task_id=task_id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_system_api_v1_role_permissions(self) -> Dict[str, Any]:
        """Get permissions API

        Get permissions for a role from Cisco DNA Center System.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/system/api/v1/role/permissions'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_discovery_id_network_device_start_index_records_to_return(self, id: Any, start_index: Any, records_to_return: Any, task_id: Optional[Any] = None) -> Dict[str, Any]:
        """Get Discovered devices by range

        Returns the network devices discovered for the given discovery and for the given range. The maximum number of records that can be retrieved is 500. Discovery ID can be obtained using the "Get Discoveries by range" API.

        Args:
            id (Any): Discovery ID
            start_index (Any): Starting index for the records
            records_to_return (Any): Number of records to fetch from the start index
            task_id (Any): taskId

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/discovery/{id}/network-device/{start_index}/{records_to_return}'
        url = url.format(id=id, start_index=start_index, records_to_return=records_to_return)
        params = {
            'taskId': task_id,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_data_api_v1_clients_count(self, x__c_a_l_l_e_r__i_d: Optional[Any] = None, start_time: Optional[Any] = None, end_time: Optional[Any] = None, type: Optional[Any] = None, os_type: Optional[Any] = None, os_version: Optional[Any] = None, site_hierarchy: Optional[Any] = None, site_hierarchy_id: Optional[Any] = None, site_id: Optional[Any] = None, ipv4_address: Optional[Any] = None, ipv6_address: Optional[Any] = None, mac_address: Optional[Any] = None, wlc_name: Optional[Any] = None, connected_network_device_name: Optional[Any] = None, ssid: Optional[Any] = None, band: Optional[Any] = None) -> Dict[str, Any]:
        """Retrieves the total count of clients by applying basic filtering

        Retrieves the number of clients by applying basic filtering. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-clients1-1.0.0-resolved.yaml

        Args:
            x__c_a_l_l_e_r__i_d (Any): Caller ID is used to trace the origin of API calls and their associated queries executed on the database. It's an optional header parameter that can be added to an API request.

            start_time (Any): Start time from which API queries the data set related to the resource. It must be specified in UNIX epochtime in milliseconds. Value is inclusive.

If `startTime` is not provided, API will default to current time.

            end_time (Any): End time to which API queries the data set related to the resource. It must be specified in UNIX epochtime in milliseconds. Value is inclusive.

            type (Any): The client device type whether client is connected to network through Wired or Wireless medium.

            os_type (Any): Client device operating system type.
This field supports wildcard (`*`) character-based search. If the value contains the (`*`) character, please use the /query API for regex search. 
Ex: `*iOS*` or `iOS*` or `*iOS`
Examples:

`osType=iOS` (single osType requested)

`osType=iOS&osType=Android` (multiple osType requested)

            os_version (Any): Client device operating system version
This field supports wildcard (`*`) character-based search. If the value contains the (`*`) character, please use the /query API for regex search. 
Ex: `*14.3*` or `14.3*` or `*14.3`
Examples:

`osVersion=14.3` (single osVersion requested)

`osVersion=14.3&osVersion=10.1` (multiple osVersion requested)

            site_hierarchy (Any): The full hierarchical breakdown of the site tree starting from Global site name and ending with the specific site name. The Root site is named "Global" (Ex. "Global/AreaName/BuildingName/FloorName") This field supports wildcard (`*`) character-based search. If the value contains the (`*`) character, please use the /query API for regex search.  Ex: `*BuildingName*` or `BuildingName*` or `*BuildingName`
Examples:
`siteHierarchy=Global/AreaName/BuildingName/FloorName` (single siteHierarchy requested)
`siteHierarchy=Global/AreaName/BuildingName1/FloorName1&siteHierarchy=Global/AreaName/BuildingName1/FloorName2` (multiple siteHierarchy requested)
            site_hierarchy_id (Any): The full hierarchy breakdown of the site tree in id form starting from Global site UUID and ending with the specific site UUID. (Ex. "globalUuid/areaUuid/buildingUuid/floorUuid") This field supports wildcard (`*`) character-based search.  Ex: `*buildingUuid*` or `buildingUuid*` or `*buildingUuid`
Examples:
`siteHierarchyId=globalUuid/areaUuid/buildingUuid/floorUuid` (single siteHierarchyId requested)
`siteHierarchyId=globalUuid/areaUuid/buildingUuid1/floorUuid1&siteHierarchyId=globalUuid/areaUuid/buildingUuid1/floorUuid2` (multiple siteHierarchyId requested)
            site_id (Any): The site UUID without the top level hierarchy. (Ex."floorUuid") Examples:
`siteId=floorUuid` (single siteId requested)
`siteId=floorUuid1&siteId=floorUuid2` (multiple siteId requested)
            ipv4_address (Any): IPv4 Address of the network entity either network device or client
This field supports wildcard (`*`) character-based search. 
Ex: `*1.1*` or `1.1*` or `*1.1`

Examples:

`ipv4Address=1.1.1.1` (single ipv4Address requested)

`ipv4Address=1.1.1.1&ipv4Address=2.2.2.2` (multiple ipv4Address requested)

            ipv6_address (Any): IPv6 Address of the network entity either network device or client
This field supports wildcard (`*`) character-based search.
Ex: `*2001:db8*` or `2001:db8*` or `*2001:db8`

Examples:

`ipv6Address=2001:db8:0:0:0:0:2:1` (single ipv6Address requested)

`ipv6Address=2001:db8:0:0:0:0:2:1&ipv6Address=2001:db8:85a3:8d3:1319:8a2e:370:7348` (multiple ipv6Address requested)

            mac_address (Any): The macAddress of the network device or client
This field supports wildcard (`*`) character-based search. 
Ex: `*AB:AB:AB*` or `AB:AB:AB*` or `*AB:AB:AB`
Examples:

`macAddress=AB:AB:AB:CD:CD:CD` (single macAddress requested)

`macAddress=AB:AB:AB:CD:CD:DC&macAddress=AB:AB:AB:CD:CD:FE` (multiple macAddress requested)

            wlc_name (Any): Wireless Controller name that reports the wireless client.
This field supports wildcard (`*`) character-based search. If the value contains the (`*`) character, please use the /query API for regex search.
Ex: `*wlc-25*` or `wlc-25*` or `*wlc-25`

Examples:

`wlcName=wlc-25` (single wlcName requested)

`wlcName=wlc-25&wlc-34` (multiple wlcName requested)

            connected_network_device_name (Any): Name of the neighbor network device that client is connected to.
This field supports wildcard (`*`) character-based search. If the value contains the (`*`) character, please use the /query API for regex search.
Ex: `*ap-25*` or `ap-25*` or `*ap-25`

Examples:

`connectedNetworkDeviceName=ap-25` (single connectedNetworkDeviceName requested)

`connectedNetworkDeviceName=ap-25&ap-34` (multiple connectedNetworkDeviceName requested)    

            ssid (Any): SSID is the name of wireless network to which client connects to. It is also referred to as WLAN ID - Wireless Local Area Network Identifier.
This field supports wildcard (`*`) character-based search. If the value contains the (`*`) character, please use the /query API for regex search. 
Ex: `*Alpha*` or `Alpha*` or `*Alpha`

Examples:

`ssid=Alpha` (single ssid requested)

`ssid=Alpha&ssid=Guest` (multiple ssid requested)

            band (Any): WiFi frequency band that client or Access Point operates. Band value is represented in Giga Hertz - GHz
Examples:

`band=5GHZ` (single band requested)

`band=2.4GHZ&band=6GHZ` (multiple band requested)


        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/data/api/v1/clients/count'
        params = {
            'startTime': start_time,
            'endTime': end_time,
            'type': type,
            'osType': os_type,
            'osVersion': os_version,
            'siteHierarchy': site_hierarchy,
            'siteHierarchyId': site_hierarchy_id,
            'siteId': site_id,
            'ipv4Address': ipv4_address,
            'ipv6Address': ipv6_address,
            'macAddress': mac_address,
            'wlcName': wlc_name,
            'connectedNetworkDeviceName': connected_network_device_name,
            'ssid': ssid,
            'band': band,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_device_device_uuid_poe(self, device_uuid: Any) -> Dict[str, Any]:
        """POE details 

        Returns POE details for device.

        Args:
            device_uuid (Any): UUID of the device

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device/{device_uuid}/poe'
        url = url.format(device_uuid=device_uuid)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_product_names(self, product_name: Optional[Any] = None, product_id: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None) -> Dict[str, Any]:
        """Retrieves the list of network device product names

        Get the list of network device product names, their ordinal, and the support PIDs based on filter criteria.


        Args:
            product_name (Any): Filter with network device product name. Supports partial case-insensitive search. A minimum of 3 characters are required for search
            product_id (Any): Filter with product ID (PID)
            offset (Any): The first record to show for this page; the first record is numbered 1. The minimum value is 1.
            limit (Any): The number of records to show for this page. The minimum and maximum values are 1 and 500, respectively.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/productNames'
        params = {
            'productName': product_name,
            'productId': product_id,
            'offset': offset,
            'limit': limit,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_onboarding_pnp_device_vacct_sync(self, content__type: Any) -> Dict[str, Any]:
        """Sync Virtual Account Devices

        Synchronizes the device info from the given smart account & virtual account with the PnP database. The response payload returns a list of synced devices (Deprecated).

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/onboarding/pnp-device/vacct-sync'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_network_device_device_id_user_defined_field(self, device_id: Any, name: Any) -> Dict[str, Any]:
        """Remove User-Defined-Field from device

        Remove a User-Defined-Field from device. Name of UDF has to be passed as the query parameter. Please note that Global UDF will not be deleted by this operation.

        Args:
            device_id (Any): UUID of device from which UDF has to be removed
            name (Any): Name of UDF to be removed

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device/{device_id}/user-defined-field'
        url = url.format(device_id=device_id)
        params = {
            'name': name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_network_device_device_id_user_defined_field(self, device_id: Any) -> Dict[str, Any]:
        """Add User-Defined-Field to device

        Assigns an existing Global User-Defined-Field to a device. If the UDF is already assigned to the specific device, then it updates the device UDF value accordingly. Please note that the assigning UDF 'name' must be an existing global UDF. Otherwise error shall be shown.

        Args:
            device_id (Any): UUID of device to which UDF has to be added

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device/{device_id}/user-defined-field'
        url = url.format(device_id=device_id)
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_template_programmer_project_project_id_template(self, content__type: Any, project_id: Any) -> Dict[str, Any]:
        """Create Template

        API to create a template by project id.

        Args:
            content__type (Any): Request body content type
            project_id (Any): UUID of the project in which the template needs to be created

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/template-programmer/project/{project_id}/template'
        url = url.format(project_id=project_id)
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_wireless_controllers_network_device_id_anchor_managed_ap_locations(self, network_device_id: Any, limit: Optional[Any] = None, offset: Optional[Any] = None) -> Dict[str, Any]:
        """Get Anchor Managed AP Locations for specific Wireless Controller

        Retrieves all the details of Anchor Managed AP locations associated with the specific Wireless Controller.

        Args:
            network_device_id (Any): Obtain the network device ID value by using the API call GET: /dna/intent/api/v1/network-device/ip-address/${ipAddress}.
            limit (Any): The number of records to show for this page.
            offset (Any): The first record to show for this page; the first record is numbered 1.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/wirelessControllers/{network_device_id}/anchorManagedApLocations'
        url = url.format(network_device_id=network_device_id)
        params = {
            'limit': limit,
            'offset': offset,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_device_device_uuid_interface_interface_uuid_neighbor(self, device_uuid: Any, interface_uuid: Any) -> Dict[str, Any]:
        """Get connected device detail

        Get connected device detail for given deviceUuid and interfaceUuid

        Args:
            device_uuid (Any): instanceuuid of Device
            interface_uuid (Any): instanceuuid of interface

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device/{device_uuid}/interface/{interface_uuid}/neighbor'
        url = url.format(device_uuid=device_uuid, interface_uuid=interface_uuid)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_site_member_id_member(self, id: Any, member_type: Any, offset: Optional[Any] = None, limit: Optional[Any] = None, level: Optional[Any] = None) -> Dict[str, Any]:
        """Get devices that are assigned to a site

        API to get devices that are assigned to a site.

        Args:
            id (Any): Site Id
            member_type (Any): Member type (This API only supports the 'networkdevice' type)
            offset (Any): Offset/starting index for pagination
            limit (Any): Number of devices to be listed. Default and max supported value is 500
            level (Any): Depth of site hierarchy to be considered to list the devices. If the provided value is -1, devices for all child sites will be listed.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/site-member/{id}/member'
        url = url.format(id=id)
        params = {
            'memberType': member_type,
            'offset': offset,
            'limit': limit,
            'level': level,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_data_api_v1_assurance_issues_summary_analytics(self, content__type: Any, accept__language: Optional[Any] = None, x__c_a_l_l_e_r__i_d: Optional[Any] = None) -> Dict[str, Any]:
        """Get summary analytics data of issues

        Gets the summary analytics data related to issues based on given filters and group by field. This data can be used to find issue counts grouped by different keys. https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-IssuesList-1.0.0-resolved.yaml

        Args:
            content__type (Any): Request body content type
            accept__language (Any): This header parameter can be used to specify the language in which issue display name need to be returned. Available options are - 'en' (English), 'ja' (Japanese), 'ko' (Korean), 'zh' (Chinese). If this parameter is not present the issue display name is returned in English language.
            x__c_a_l_l_e_r__i_d (Any): Caller ID can be used to trace the caller for queries executed on database. The caller id is like a optional attribute which can be added to API invocation like ui, python, postman, test-automation etc

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        if accept__language is not None:
            request_headers['Accept-Language'] = str(accept__language)
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/data/api/v1/assuranceIssues/summaryAnalytics'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_sda_transit_networks_id(self, id: Any) -> Dict[str, Any]:
        """Delete transit network by id

        Deletes a transit network based on id.

        Args:
            id (Any): ID of the transit network.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/transitNetworks/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_sda_fabric_sites_id(self, id: Any) -> Dict[str, Any]:
        """Delete fabric site by id

        Deletes a fabric site based on id.

        Args:
            id (Any): ID of the fabric site.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/fabricSites/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_lan_automation_log(self, offset: Optional[Any] = None, limit: Optional[Any] = None) -> Dict[str, Any]:
        """LAN Automation Log 

        Invoke this API to get the LAN Automation session logs.

        Args:
            offset (Any): Starting index of the LAN Automation session. Minimum value is 1.
            limit (Any): Number of LAN Automation sessions to be retrieved. Limit value can range between 1 to 10.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/lan-automation/log'
        params = {
            'offset': offset,
            'limit': limit,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sites_site_id_profile_assignments(self, site_id: Any, offset: Optional[Any] = None, limit: Optional[Any] = None) -> Dict[str, Any]:
        """Retrieves the list of network profiles that the given site has been assigned

        Retrieves the list of profiles that the given site has been assigned.  These profiles may either be directly assigned to this site, or were assigned to a parent site and have been inherited.

These assigments can be modified via the `/dna/intent/api/v1/networkProfilesForSites/{profileId}/siteAssignments` resources.


        Args:
            site_id (Any): The `id` of the site, retrievable from `/dna/intent/api/v1/sites`
            offset (Any): The first record to show for this page; the first record is numbered 1.
            limit (Any): The number of records to show for this page.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sites/{site_id}/profileAssignments'
        url = url.format(site_id=site_id)
        params = {
            'offset': offset,
            'limit': limit,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_wireless_controllers_device_id_assign_managed_ap_locations(self, content__type: Any, device_id: Any) -> Dict[str, Any]:
        """Assign Managed AP Locations For WLC

        This API allows user to assign Managed AP Locations for WLC by device ID. The payload should always be a complete list. The Managed AP Locations included in the payload will be fully processed for both addition and deletion.

        Args:
            content__type (Any): Request body content type
            device_id (Any): Network Device ID. This value can be obtained by using the API call GET: /dna/intent/api/v1/network-device/ip-address/${ipAddress}

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/wirelessControllers/{device_id}/assignManagedApLocations'
        url = url.format(device_id=device_id)
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_discovery_job(self, ip_address: Any, offset: Optional[Any] = None, limit: Optional[Any] = None, name: Optional[Any] = None) -> Dict[str, Any]:
        """Get Discovery jobs by IP

        Returns the list of discovery jobs for the given IP

        Args:
            ip_address (Any): ipAddress
            offset (Any): offset
            limit (Any): limit
            name (Any): name

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/discovery/job'
        params = {
            'ipAddress': ip_address,
            'offset': offset,
            'limit': limit,
            'name': name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v2_application_policy_application_set_id(self, id: Any) -> Dict[str, Any]:
        """Delete Application Set

        Delete existing custom application set by id

        Args:
            id (Any): Id of custom application set to delete

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v2/application-policy-application-set/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v2_template_programmer_template(self, id: Optional[Any] = None, name: Optional[Any] = None, project_id: Optional[Any] = None, project_name: Optional[Any] = None, software_type: Optional[Any] = None, software_version: Optional[Any] = None, product_family: Optional[Any] = None, product_series: Optional[Any] = None, product_type: Optional[Any] = None, filter_conflicting_templates: Optional[Any] = None, tags: Optional[Any] = None, un_committed: Optional[Any] = None, sort_order: Optional[Any] = None, all_template_attributes: Optional[Any] = None, include_version_details: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None) -> Dict[str, Any]:
        """Get template(s) details

        Get template(s) details

        Args:
            id (Any): Id of template to be searched
            name (Any): Name of template to be searched
            project_id (Any): Filter template(s) based on project id
            project_name (Any): Filter template(s) based on project name
            software_type (Any): Filter template(s) based software type
            software_version (Any): Filter template(s) based softwareVersion
            product_family (Any): Filter template(s) based on device family
            product_series (Any): Filter template(s) based on device series
            product_type (Any): Filter template(s) based on device type
            filter_conflicting_templates (Any): Filter template(s) based on confliting templates
            tags (Any): Filter template(s) based on tags
            un_committed (Any): Return uncommitted template
            sort_order (Any): Sort Order Ascending (asc) or Descending (dsc)
            all_template_attributes (Any): Return all template attributes
            include_version_details (Any): Include template version details
            offset (Any): Index of first result
            limit (Any): Limits number of results

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v2/template-programmer/template'
        params = {
            'id': id,
            'name': name,
            'projectId': project_id,
            'projectName': project_name,
            'softwareType': software_type,
            'softwareVersion': software_version,
            'productFamily': product_family,
            'productSeries': product_series,
            'productType': product_type,
            'filterConflictingTemplates': filter_conflicting_templates,
            'tags': tags,
            'unCommitted': un_committed,
            'sortOrder': sort_order,
            'allTemplateAttributes': all_template_attributes,
            'includeVersionDetails': include_version_details,
            'offset': offset,
            'limit': limit,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_sda_layer2_virtual_networks_id(self, id: Any) -> Dict[str, Any]:
        """Delete layer 2 virtual network by id

        Deletes a layer 2 virtual network based on id.

        Args:
            id (Any): ID of the layer 2 virtual network.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/layer2VirtualNetworks/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_lan_automation_log_id_serial_number(self, id: Any, serial_number: Any, log_level: Optional[Any] = None) -> Dict[str, Any]:
        """LAN Automation Logs for Individual Devices

        Invoke this API to get the LAN Automation session logs for individual devices based on the given LAN Automation session id and device serial number. 

        Args:
            id (Any): LAN Automation session identifier.
            serial_number (Any): Device serial number.
            log_level (Any): Supported levels are ERROR, INFO, WARNING, TRACE, CONFIG and ALL. Specifying ALL will display device specific logs with the exception of CONFIG logs. In order to view CONFIG logs along with the remaining logs, please leave the query parameter blank.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/lan-automation/log/{id}/{serial_number}'
        url = url.format(id=id, serial_number=serial_number)
        params = {
            'logLevel': log_level,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_assurance_issues_id_update(self, content__type: Any, id: Any, accept__language: Optional[Any] = None, x__c_a_l_l_e_r__i_d: Optional[Any] = None) -> Dict[str, Any]:
        """Update the given issue by updating selected fields

        Updates selected fields in the given issue. Currently the only field that can be updated is 'notes' field. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-IssuesLifecycle-1.0.0-resolved.yaml

        Args:
            content__type (Any): Request body content type
            id (Any): The issue Uuid
            accept__language (Any): This header parameter can be used to specify the language in which issue description and suggested actions need to be returned. Available options are - 'en' (English), 'ja' (Japanese), 'ko' (Korean), 'zh' (Chinese). If this parameter is not present the issue details are returned in English language.
            x__c_a_l_l_e_r__i_d (Any): Caller ID can be used to trace the caller for queries executed on database. The caller id is like a optional attribute which can be added to API invocation like ui, python, postman, test-automation etc

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        if accept__language is not None:
            request_headers['Accept-Language'] = str(accept__language)
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/intent/api/v1/assuranceIssues/{id}/update'
        url = url.format(id=id)
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_discovery_id_job(self, id: Any, offset: Optional[Any] = None, limit: Optional[Any] = None, ip_address: Optional[Any] = None) -> Dict[str, Any]:
        """Get list of discoveries by discovery Id

        Returns the list of discovery jobs for the given Discovery ID. The results can be optionally filtered based on IP. Discovery ID can be obtained using the "Get Discoveries by range" API.

        Args:
            id (Any): Discovery ID
            offset (Any): Starting index for the records
            limit (Any): Number of records to fetch from the starting index
            ip_address (Any): Filter records based on IP address

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/discovery/{id}/job'
        url = url.format(id=id)
        params = {
            'offset': offset,
            'limit': limit,
            'ipAddress': ip_address,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_topology_physical_topology(self, node_type: Optional[Any] = None) -> Dict[str, Any]:
        """Get Physical Topology

        Returns the raw physical topology by specified criteria of nodeType

        Args:
            node_type (Any): nodeType

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/topology/physical-topology'
        params = {
            'nodeType': node_type,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_topology_site_topology(self) -> Dict[str, Any]:
        """Get Site Topology

        Returns site topology

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/topology/site-topology'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_integration_settings_status(self) -> Dict[str, Any]:
        """Get ITSM Integration status

        Fetches ITSM Integration status

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/integration-settings/status'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_wireless_controllers_network_device_id_secondary_managed_ap_locations(self, network_device_id: Any, limit: Optional[Any] = None, offset: Optional[Any] = None) -> Dict[str, Any]:
        """Get Secondary Managed AP Locations for specific Wireless Controller

        Retrieves all the details of Secondary Managed AP locations associated with the specific Wireless Controller.

        Args:
            network_device_id (Any): Obtain the network device ID value by using the API call GET: /dna/intent/api/v1/network-device/ip-address/${ipAddress}.
            limit (Any): The number of records to show for this page.
            offset (Any): The first record to show for this page; the first record is numbered 1.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/wirelessControllers/{network_device_id}/secondaryManagedApLocations'
        url = url.format(network_device_id=network_device_id)
        params = {
            'limit': limit,
            'offset': offset,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_sites_id_ntp_settings(self, content__type: Any, id: Any) -> Dict[str, Any]:
        """Set NTP settings for a site

        Set NTP settings for a site; `null` values indicate that the setting will be inherited from the parent site; empty objects (`{}`) indicate that the settings is unset.

        Args:
            content__type (Any): Request body content type
            id (Any): Site Id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sites/{id}/ntpSettings'
        url = url.format(id=id)
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sites_id_ntp_settings(self, id: Any, inherited: Optional[Any] = None) -> Dict[str, Any]:
        """Retrieve NTP settings for a site

        Retrieve NTP settings for a site; `null` values indicate that the setting will be inherited from the parent site; empty objects (`{}`) indicate that the setting is unset at a site.

        Args:
            id (Any): Site Id
            inherited (Any): Include settings explicitly set for this site and settings inherited from sites higher in the site hierarchy; when `false`, `null` values indicate that the site inherits that setting from the parent site or a site higher in the site hierarchy.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sites/{id}/ntpSettings'
        url = url.format(id=id)
        params = {
            '_inherited': inherited,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_tags_interfaces_members_associations(self, offset: Optional[Any] = None, limit: Optional[Any] = None) -> Dict[str, Any]:
        """Retrieve tags associated with the interfaces.

        Fetches the tags associated with the interfaces. Interfaces that don't have any tags associated will not be included in the response. A tag is a user-defined or system-defined construct to group resources. When an interface is tagged, it is called a member of the tag.

        Args:
            offset (Any): The first record to show for this page; the first record is numbered 1. minimum: 1
            limit (Any): The number of records to show for this page. minimum: 1, maximum: 500

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/tags/interfaces/membersAssociations'
        params = {
            'offset': offset,
            'limit': limit,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_device_image_updates_count(self, id: Optional[Any] = None, parent_id: Optional[Any] = None, network_device_id: Optional[Any] = None, status: Optional[Any] = None, image_name: Optional[Any] = None, host_name: Optional[Any] = None, management_address: Optional[Any] = None, start_time: Optional[Any] = None, end_time: Optional[Any] = None) -> Dict[str, Any]:
        """Count of network device image updates

        Returns the count of network device image updates based on the given filter criteria

        Args:
            id (Any): Update id which is unique for each network device under the parentId
            parent_id (Any): Updates that have this parent id
            network_device_id (Any): Network device id
            status (Any): Status of the image update. Available values: FAILURE, SUCCESS, IN_PROGRESS, PENDING
            image_name (Any): Software image name for the update
            host_name (Any): Host name of the network device for the image update. Supports case-insensitive partial search.
            management_address (Any): Management address of the network device
            start_time (Any): Image update started after the given time (as milliseconds since UNIX epoch).
            end_time (Any): Image update started before the given time (as milliseconds since UNIX epoch).

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/networkDeviceImageUpdates/count'
        params = {
            'id': id,
            'parentId': parent_id,
            'networkDeviceId': network_device_id,
            'status': status,
            'imageName': image_name,
            'hostName': host_name,
            'managementAddress': management_address,
            'startTime': start_time,
            'endTime': end_time,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_device_replacement_count(self, replacement_status: Optional[Any] = None) -> Dict[str, Any]:
        """Return replacement devices count

        Get replacement devices count

        Args:
            replacement_status (Any): Device Replacement status list[READY-FOR-REPLACEMENT, REPLACEMENT-IN-PROGRESS, REPLACEMENT-SCHEDULED, REPLACED, ERROR]

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/device-replacement/count'
        params = {
            'replacementStatus': replacement_status,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_buildings_building_id_planned_access_points(self, building_id: Any, limit: Optional[Any] = None, offset: Optional[Any] = None, radios: Optional[Any] = None) -> Dict[str, Any]:
        """Get Planned Access Points for Building

        Provides a list of Planned Access Points for the Building it is requested for

        Args:
            building_id (Any): The instance UUID of the building hierarchy element
            limit (Any): The page size limit for the response, e.g. limit=100 will return a maximum of 100 records
            offset (Any): The page offset for the response. E.g. if limit=100, offset=0 will return first 100 records, offset=1 will return next 100 records, etc.
            radios (Any): Whether to include the planned radio details of the planned access points

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/buildings/{building_id}/planned-access-points'
        url = url.format(building_id=building_id)
        params = {
            'limit': limit,
            'offset': offset,
            'radios': radios,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_system_issue_definitions_count(self, x__c_a_l_l_e_r__i_d: Optional[Any] = None, device_type: Optional[Any] = None, profile_id: Optional[Any] = None, id: Optional[Any] = None, name: Optional[Any] = None, priority: Optional[Any] = None, issue_enabled: Optional[Any] = None) -> Dict[str, Any]:
        """Get the count of system defined issue definitions based on provided filters.

        Get the count of system defined issue definitions based on provided filters. Supported filters are id, name, profileId and definition enable status. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-issueAndHealthDefinitions-1.0.0-resolved.yaml


        Args:
            x__c_a_l_l_e_r__i_d (Any): Caller ID is used to trace the origin of API calls and their associated queries executed on the database. It's an optional header parameter that can be added to an API request.

            device_type (Any): These are the device families/types supported for system issue definitions. If no input is made on device type, all device types are considered.
            profile_id (Any): The profile identier to fetch the profile associated issue defintions. The default is `global`. Please refer Network design profiles documentation for more details.
            id (Any): The definition identifier.

Examples:

id=015d9cba-4f53-4087-8317-7e49e5ffef46 (single entity id request)

id=015d9cba-4f53-4087-8317-7e49e5ffef46&id=015d9cba-4f53-4087-8317-7e49e5ffef47 (multiple ids in the query param)

            name (Any): The list of system defined issue names. (Ex."BGP_Down")

Examples:

name=BGP_Down (single entity uuid requested)

name=BGP_Down&name=BGP_Flap (multiple issue names separated by & operator)

            priority (Any): Issue priority, possible values are P1, P2, P3, P4.

`P1`: A critical issue that needs immediate attention and can have a wide impact on network operations.

`P2`: A major issue that can potentially impact multiple devices or clients.

`P3`: A minor issue that has a localized or minimal impact.

`P4`: A warning issue that may not be an immediate problem but addressing it can optimize the network performance.

            issue_enabled (Any): The enablement status of the issue definition, either true or false.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/intent/api/v1/systemIssueDefinitions/count'
        params = {
            'deviceType': device_type,
            'profileId': profile_id,
            'id': id,
            'name': name,
            'priority': priority,
            'issueEnabled': issue_enabled,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_product_names_count(self, product_name: Optional[Any] = None, product_id: Optional[Any] = None) -> Dict[str, Any]:
        """Count of network product names

        Count of product names based on filter criteria

        Args:
            product_name (Any): Filter with network device product name. Supports partial case-insensitive search. A minimum of 3 characters are required for search
            product_id (Any): Filter with product ID (PID)

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/productNames/count'
        params = {
            'productName': product_name,
            'productId': product_id,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_wireless_accesspoint_configuration_summary(self, key: Any) -> Dict[str, Any]:
        """Get Access Point Configuration

        Users can query the access point configuration information per device using the ethernet MAC address

        Args:
            key (Any): The ethernet MAC address of Access point

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/wireless/accesspoint-configuration/summary'
        params = {
            'key': key,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_network_device_brief(self, content__type: Any) -> Dict[str, Any]:
        """Update Device role

        Updates the role of the device as access, core, distribution, border router

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/network-device/brief'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_image_importation_source_url(self, content__type: Any, schedule_at: Optional[Any] = None, schedule_desc: Optional[Any] = None, schedule_origin: Optional[Any] = None) -> Dict[str, Any]:
        """Import software image via URL

        Fetches a software image from remote file system (using URL for HTTP/FTP) and uploads to DNA Center. Supported image files extensions are bin, img, tar, smu, pie, aes, iso, ova, tar_gz and qcow2

        Args:
            content__type (Any): Request body content type
            schedule_at (Any): Epoch Time (The number of milli-seconds since January 1 1970 UTC) at which the distribution should be scheduled (Optional) 
            schedule_desc (Any): Custom Description (Optional)
            schedule_origin (Any): Originator of this call (Optional)

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/image/importation/source/url'
        params = {
            'scheduleAt': schedule_at,
            'scheduleDesc': schedule_desc,
            'scheduleOrigin': schedule_origin,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_device_config(self) -> Dict[str, Any]:
        """Get Device Config for all devices

        Returns the config for all devices. This API has been deprecated and will not be available in a Cisco Catalyst Center release after Nov 1st 2024 23:59:59 GMT.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device/config'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_topology_l2_vlan_i_d(self, vlan_i_d: Any) -> Dict[str, Any]:
        """Get topology details

        Returns Layer 2 network topology by specified VLAN ID

        Args:
            vlan_i_d (Any): Vlan Name for e.g Vlan1, Vlan23 etc

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/topology/l2/{vlan_i_d}'
        url = url.format(vlan_i_d=vlan_i_d)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_data_api_v1_assurance_issues(self, accept__language: Optional[Any] = None, x__c_a_l_l_e_r__i_d: Optional[Any] = None, start_time: Optional[Any] = None, end_time: Optional[Any] = None, limit: Optional[Any] = None, offset: Optional[Any] = None, sort_by: Optional[Any] = None, order: Optional[Any] = None, is_global: Optional[Any] = None, priority: Optional[Any] = None, severity: Optional[Any] = None, status: Optional[Any] = None, entity_type: Optional[Any] = None, category: Optional[Any] = None, device_type: Optional[Any] = None, name: Optional[Any] = None, issue_id: Optional[Any] = None, entity_id: Optional[Any] = None, updated_by: Optional[Any] = None, site_hierarchy: Optional[Any] = None, site_hierarchy_id: Optional[Any] = None, site_name: Optional[Any] = None, site_id: Optional[Any] = None, fabric_site_id: Optional[Any] = None, fabric_vn_name: Optional[Any] = None, fabric_transit_site_id: Optional[Any] = None, network_device_id: Optional[Any] = None, network_device_ip_address: Optional[Any] = None, mac_address: Optional[Any] = None, view: Optional[Any] = None, attribute: Optional[Any] = None, ai_driven: Optional[Any] = None, fabric_driven: Optional[Any] = None, fabric_site_driven: Optional[Any] = None, fabric_vn_driven: Optional[Any] = None, fabric_transit_driven: Optional[Any] = None) -> Dict[str, Any]:
        """Get the details of issues for given set of filters

        Returns all details of each issue along with suggested actions for given set of filters specified in query parameters. If there is no start and/or end time, then end time will be defaulted to current time and start time will be defaulted to 24-hours ago from end time. All string type query parameters support wildcard search (using *). For example: siteHierarchy=Global/San Jose/* returns issues under all sites whole siteHierarchy starts with "Global/San Jose/". https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-IssuesList-1.0.0-resolved.yaml

        Args:
            accept__language (Any): This header parameter can be used to specify the language in which issue description and suggested actions need to be returned. Available options are - 'en' (English), 'ja' (Japanese), 'ko' (Korean), 'zh' (Chinese). If this parameter is not present the issue details are returned in English language.
            x__c_a_l_l_e_r__i_d (Any): Caller ID can be used to trace the caller for queries executed on database. The caller id is like a optional attribute which can be added to API invocation like ui, python, postman, test-automation etc
            start_time (Any): Start time from which API queries the data set related to the resource. It must be specified in UNIX epochtime in milliseconds. Value is inclusive.

If `startTime` is not provided, API will default to current time.

            end_time (Any): End time to which API queries the data set related to the resource. It must be specified in UNIX epochtime in milliseconds. Value is inclusive.

            limit (Any): Maximum number of issues to return
            offset (Any): Specifies the starting point within all records returned by the API. It's one based offset. The starting value is 1.
            sort_by (Any): 
            order (Any): The sort order of the field ascending or descending.
            is_global (Any): Global issues are those issues which impacts across many devices, sites. They are also displayed on Issue Dashboard in Catalyst Center UI. Non-Global issues are displayed only on Client 360 or Device 360 pages. If this flag is 'true', only global issues are returned. If it if 'false', all issues are returned.

            priority (Any): Priority of the issue. Supports single priority and multiple priorities Examples: priority=P1 (single priority requested) priority=P1&priority=P2&priority=P3 (multiple priorities requested)

            severity (Any): Severity of the issue. Supports single severity and multiple severities.
Examples:
severity=high (single severity requested)
severity=high&severity=medium (multiple severities requested)

            status (Any): Status of the issue. Supports single status and multiple statuses. Examples: status=active (single status requested) status=active&status=resolved (multiple statuses requested)

            entity_type (Any): Entity type of the issue. Supports single entity type and multiple entity types. Examples: entityType=networkDevice (single entity type requested) entityType=network device&entityType=client (multiple entity types requested)

            category (Any): Categories of the issue. Supports single category and multiple categories. Examples: category=availability (single status requested) category=availability&category=onboarding (multiple categories requested)

            device_type (Any): Device Type of the device to which this issue belongs to. Supports single device type and multiple device types.
Examples: deviceType=wireless controller (single device type requested) deviceType=wireless controller&deviceType=core (multiple device types requested)

            name (Any): The name of the issue
Examples:
name=ap_down (single issue name requested)
name=ap_down&name=wlc_monitor (multiple issue names requested)
Issue names can be retrieved using the API - /data/api/v1/assuranceIssueConfigurations

            issue_id (Any): UUID of the issue Examples: issueId=e52aecfe-b142-4287-a587-11a16ba6dd26 (single issue id requested) issueId=e52aecfe-b142-4287-a587-11a16ba6dd26&issueId=864d0421-02c0-43a6-9c52-81cad45f66d8 (multiple issue ids requested)

            entity_id (Any): Id of the entity for which this issue belongs to. For example, it
    could be mac address of AP or UUID of Sensor
  example: 68:ca:e4:79:3f:20 4de02167-901b-43cf-8822-cffd3caa286f
Examples: entityId=68:ca:e4:79:3f:20 (single entity id requested) entityId=68:ca:e4:79:3f:20&entityId=864d0421-02c0-43a6-9c52-81cad45f66d8 (multiple entity ids requested)

            updated_by (Any): The user who last updated this issue. Examples: updatedBy=admin (single updatedBy requested) updatedBy=admin&updatedBy=john (multiple updatedBy requested)

            site_hierarchy (Any): The full hierarchical breakdown of the site tree starting from Global site name and ending with the specific site name. The Root site is named "Global" (Ex. `Global/AreaName/BuildingName/FloorName`)

This field supports wildcard asterisk (*) character search support. E.g. */San*, */San, /San*

Examples:

`?siteHierarchy=Global/AreaName/BuildingName/FloorName` (single siteHierarchy requested)

`?siteHierarchy=Global/AreaName/BuildingName/FloorName&siteHierarchy=Global/AreaName2/BuildingName2/FloorName2` (multiple siteHierarchies requested)

            site_hierarchy_id (Any): The full hierarchy breakdown of the site tree in id form starting from Global site UUID and ending with the specific site UUID. (Ex. `globalUuid/areaUuid/buildingUuid/floorUuid`)

This field supports wildcard asterisk (*) character search support. E.g. `*uuid*, *uuid, uuid*

Examples:

`?siteHierarchyId=globalUuid/areaUuid/buildingUuid/floorUuid `(single siteHierarchyId requested)

`?siteHierarchyId=globalUuid/areaUuid/buildingUuid/floorUuid&siteHierarchyId=globalUuid/areaUuid2/buildingUuid2/floorUuid2` (multiple siteHierarchyIds requested)

            site_name (Any): The name of the site. (Ex. `FloorName`)

This field supports wildcard asterisk (*) character search support. E.g. *San*, *San, San*

Examples:

`?siteName=building1` (single siteName requested)

`?siteName=building1&siteName=building2&siteName=building3` (multiple siteNames requested)

            site_id (Any): The UUID of the site. (Ex. `flooruuid`)

This field supports wildcard asterisk (*) character search support. E.g.*flooruuid*, *flooruuid, flooruuid*

Examples:

`?siteId=id1` (single id requested)

`?siteId=id1&siteId=id2&siteId=id3` (multiple ids requested)

            fabric_site_id (Any): The UUID of the fabric site. (Ex. "flooruuid")
Examples: fabricSiteId=e52aecfe-b142-4287-a587-11a16ba6dd26 (single id requested) fabricSiteId=e52aecfe-b142-4287-a587-11a16ba6dd26,864d0421-02c0-43a6-9c52-81cad45f66d8 (multiple ids requested)

            fabric_vn_name (Any): The name of the fabric virtual network
Examples: fabricVnName=name1 (single fabric virtual network name requested) fabricVnName=name1&fabricVnName=name2&fabricVnName=name3 (multiple fabric virtual network names requested)

            fabric_transit_site_id (Any): The UUID of the fabric transit site. (Ex. "flooruuid")
Examples: fabricTransitSiteId=e52aecfe-b142-4287-a587-11a16ba6dd26 (single id requested) fabricTransitSiteId=e52aecfe-b142-4287-a587-11a16ba6dd26&fabricTransitSiteId=864d0421-02c0-43a6-9c52-81cad45f66d8 (multiple ids requested)

            network_device_id (Any): The list of Network Device Uuids. (Ex. `6bef213c-19ca-4170-8375-b694e251101c`)

Examples:

`networkDeviceId=6bef213c-19ca-4170-8375-b694e251101c` (single networkDeviceId requested)

`networkDeviceId=6bef213c-19ca-4170-8375-b694e251101c&networkDeviceId=32219612-819e-4b5e-a96b-cf22aca13dd9&networkDeviceId=2541e9a7-b80d-4955-8aa2-79b233318ba0` (multiple networkDeviceIds with & separator)

            network_device_ip_address (Any): The list of Network Device management IP Address. (Ex. `121.1.1.10`)

This field supports wildcard (`*`) character-based search. 
Ex: `*1.1*` or `1.1*` or `*1.1`

Examples:

`networkDeviceIpAddress=121.1.1.10`

`networkDeviceIpAddress=121.1.1.10&networkDeviceIpAddress=172.20.1.10&networkDeviceIpAddress=10.10.20.10` (multiple networkDevice IP Address with & separator)

            mac_address (Any): The macAddress of the network device or client
This field supports wildcard (`*`) character-based search. 
Ex: `*AB:AB:AB*` or `AB:AB:AB*` or `*AB:AB:AB`
Examples:

`macAddress=AB:AB:AB:CD:CD:CD` (single macAddress requested)

`macAddress=AB:AB:AB:CD:CD:DC&macAddress=AB:AB:AB:CD:CD:FE` (multiple macAddress requested)

            view (Any): The name of the View. Each view represents a specific data set. Please refer to the `IssuesView` Model for supported views. View is predefined set of attributes supported by the API. Only the attributes related to the given view will be part of the API response along with default attributes. If multiple views are provided, then response will contain attributes from all those views. If no views are specified, all attributes will be returned.

| View Name | Included Attributes |
| --- | --- |
| `update` | updatedTime, updatedBy |
| `site` | siteName, siteHierarchy, siteId, siteHierarchyId |
Examples: `view=update` (single view requested) `view=update&view=site` (multiple views requested)       

            attribute (Any): List of attributes related to the issue. If these are provided, then only those attributes will be part of response along with the default attributes. Please refer to the `IssuesResponseAttribute` Model for supported attributes.
Examples: `attribute=deviceType` (single attribute requested) `attribute=deviceType&attribute=updatedBy` (multiple attributes requested)

            ai_driven (Any): Flag whether the issue is AI driven issue
            fabric_driven (Any): Flag whether the issue is related to a Fabric site, a virtual network or a transit.
            fabric_site_driven (Any): Flag whether the issue is Fabric site driven issue
            fabric_vn_driven (Any): Flag whether the issue is Fabric Virtual Network driven issue
            fabric_transit_driven (Any): Flag whether the issue is Fabric Transit driven issue

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if accept__language is not None:
            request_headers['Accept-Language'] = str(accept__language)
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/data/api/v1/assuranceIssues'
        params = {
            'startTime': start_time,
            'endTime': end_time,
            'limit': limit,
            'offset': offset,
            'sortBy': sort_by,
            'order': order,
            'isGlobal': is_global,
            'priority': priority,
            'severity': severity,
            'status': status,
            'entityType': entity_type,
            'category': category,
            'deviceType': device_type,
            'name': name,
            'issueId': issue_id,
            'entityId': entity_id,
            'updatedBy': updated_by,
            'siteHierarchy': site_hierarchy,
            'siteHierarchyId': site_hierarchy_id,
            'siteName': site_name,
            'siteId': site_id,
            'fabricSiteId': fabric_site_id,
            'fabricVnName': fabric_vn_name,
            'fabricTransitSiteId': fabric_transit_site_id,
            'networkDeviceId': network_device_id,
            'networkDeviceIpAddress': network_device_ip_address,
            'macAddress': mac_address,
            'view': view,
            'attribute': attribute,
            'aiDriven': ai_driven,
            'fabricDriven': fabric_driven,
            'fabricSiteDriven': fabric_site_driven,
            'fabricVnDriven': fabric_vn_driven,
            'fabricTransitDriven': fabric_transit_driven,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_licenses_smart_accounts(self) -> Dict[str, Any]:
        """Smart Account Details

        Retrieve details of all smart accounts.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/licenses/smartAccounts'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sda_fabric_devices_layer3_handoffs_ip_transits_count(self, fabric_id: Any, network_device_id: Optional[Any] = None) -> Dict[str, Any]:
        """Get fabric devices layer 3 handoffs with ip transit count

        Returns the count of layer 3 handoffs with ip transit of fabric devices that match the provided query parameters.

        Args:
            fabric_id (Any): ID of the fabric this device belongs to.
            network_device_id (Any): Network device ID of the fabric device.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/fabricDevices/layer3Handoffs/ipTransits/count'
        params = {
            'fabricId': fabric_id,
            'networkDeviceId': network_device_id,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sda_fabric_devices_layer3_handoffs_sda_transits_count(self, fabric_id: Any, network_device_id: Optional[Any] = None) -> Dict[str, Any]:
        """Get fabric devices layer 3 handoffs with sda transit count

        Returns the count of layer 3 handoffs with sda transit of fabric devices that match the provided query parameters.

        Args:
            fabric_id (Any): ID of the fabric this device belongs to.
            network_device_id (Any): Network device ID of the fabric device.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/fabricDevices/layer3Handoffs/sdaTransits/count'
        params = {
            'fabricId': fabric_id,
            'networkDeviceId': network_device_id,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_profiles_for_sites(self, offset: Optional[Any] = None, limit: Optional[Any] = None, sort_by: Optional[Any] = None, order: Optional[Any] = None, type: Optional[Any] = None) -> Dict[str, Any]:
        """Retrieves the list of network profiles for sites

        Retrieves the list of network profiles for sites.

        Args:
            offset (Any): The first record to show for this page; the first record is numbered 1.
            limit (Any): The number of records to show for this page.
            sort_by (Any): A property within the response to sort by.
            order (Any): Whether ascending or descending order should be used to sort the response.
            type (Any): Filter responses to only include profiles of a given type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/networkProfilesForSites'
        params = {
            'offset': offset,
            'limit': limit,
            'sortBy': sort_by,
            'order': order,
            'type': type,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_device_functional_capability(self, device_id: Any, function_name: Optional[Any] = None) -> Dict[str, Any]:
        """Get Functional Capability for devices

        Returns the functional-capability for given devices

        Args:
            device_id (Any): Accepts comma separated deviceid's and return list of functional-capabilities for the given id's. If invalid or not-found id's are provided, null entry will be returned in the list.
            function_name (Any): functionName

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device/functional-capability'
        params = {
            'deviceId': device_id,
            'functionName': function_name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_areas(self, content__type: Any) -> Dict[str, Any]:
        """Creates an area

        Creates an area in the network hierarchy.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/areas'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sda_port_assignments(self, fabric_id: Optional[Any] = None, network_device_id: Optional[Any] = None, interface_name: Optional[Any] = None, data_vlan_name: Optional[Any] = None, voice_vlan_name: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None) -> Dict[str, Any]:
        """Get port assignments

        Returns a list of port assignments that match the provided query parameters.

        Args:
            fabric_id (Any): ID of the fabric the device is assigned to.
            network_device_id (Any): Network device ID of the port assignment.
            interface_name (Any): Interface name of the port assignment.
            data_vlan_name (Any): Data VLAN name of the port assignment.
            voice_vlan_name (Any): Voice VLAN name of the port assignment.
            offset (Any): Starting record for pagination.
            limit (Any): Maximum number of records to return.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/portAssignments'
        params = {
            'fabricId': fabric_id,
            'networkDeviceId': network_device_id,
            'interfaceName': interface_name,
            'dataVlanName': data_vlan_name,
            'voiceVlanName': voice_vlan_name,
            'offset': offset,
            'limit': limit,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_sda_port_assignments(self, fabric_id: Any, network_device_id: Any, interface_name: Optional[Any] = None, data_vlan_name: Optional[Any] = None, voice_vlan_name: Optional[Any] = None) -> Dict[str, Any]:
        """Delete port assignments

        Deletes port assignments based on user input.

        Args:
            fabric_id (Any): ID of the fabric the device is assigned to.
            network_device_id (Any): Network device ID of the port assignment.
            interface_name (Any): Interface name of the port assignment.
            data_vlan_name (Any): Data VLAN name of the port assignment.
            voice_vlan_name (Any): Voice VLAN name of the port assignment.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/portAssignments'
        params = {
            'fabricId': fabric_id,
            'networkDeviceId': network_device_id,
            'interfaceName': interface_name,
            'dataVlanName': data_vlan_name,
            'voiceVlanName': voice_vlan_name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_sda_port_assignments(self, content__type: Any) -> Dict[str, Any]:
        """Update port assignments

        Updates port assignments based on user input.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sda/portAssignments'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_sda_port_assignments(self, content__type: Any) -> Dict[str, Any]:
        """Add port assignments

        Adds port assignments based on user input.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sda/portAssignments'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def post_dna_system_api_v1_auth_token(self, content__type: Any, authorization: Any) -> Dict[str, Any]:
        """Authentication API

        API to obtain an access token, which remains valid for 1 hour. The token obtained using this API is required to be set as value to the X-Auth-Token HTTP Header for all API calls to Cisco DNA Center.

        Args:
            content__type (Any): Request body content type
            authorization (Any): API supports both Basic auth and AES key encryption as Authorization token in header. AES key encryption is optional and can be enabled under DNAC System configuration. For Basic Auth: Authorization header is Base64 encoded string of "username:password", For example Authorization header will contain “Basic YWRtaW46TWFnbGV2MTIz”, where YWRtaW46TWFnbGV2MTIz is the Base64 encoded string. For AES key encryption, Authorization header is Base64 encoded string of AES key. For example Authorization header will contain "CSCO-AES-256 credentials=2k/wGz48lp3ma9sM+2xiyQ==", where "2k/wGz48lp3ma9sM+2xiyQ==" is base64 encoded string of 256 bits AES key encrypted "username:password".

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        if authorization is not None:
            request_headers['Authorization'] = str(authorization)
        url = self.base_url + '/dna/system/api/v1/auth/token'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def post_dna_data_api_v1_assurance_events_query(self, content__type: Any, x__c_a_l_l_e_r__i_d: Optional[Any] = None) -> Dict[str, Any]:
        """Query assurance events with filters

        Returns the list of events discovered by Catalyst Center, determined by the complex filters. Please refer to the 'API Support Documentation' section to understand which fields are supported. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-AssuranceEvents-1.0.0-resolved.yaml

        Args:
            content__type (Any): Request body content type
            x__c_a_l_l_e_r__i_d (Any): Caller ID is used to trace the origin of API calls and their associated queries executed on the database. It's an optional header parameter that can be added to an API request.


        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/data/api/v1/assuranceEvents/query'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_dnacaap_management_execution_status_execution_id(self, execution_id: Any) -> Dict[str, Any]:
        """Get Business API Execution Details

        Retrieves the execution details of a Business API

        Args:
            execution_id (Any): Execution Id of API

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/dnacaap/management/execution-status/{execution_id}'
        url = url.format(execution_id=execution_id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_lan_automation_sessions(self) -> Dict[str, Any]:
        """LAN Automation Active Sessions

        Invoke this API to get the LAN Automation active session information

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/lan-automation/sessions'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_app_policy_intent(self, content__type: Any) -> Dict[str, Any]:
        """Application Policy Intent

        Create/Update/Delete application policy

        Args:
            content__type (Any): content-type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/app-policy-intent'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_devices_not_assigned_to_site(self, offset: Optional[Any] = None, limit: Optional[Any] = None) -> Dict[str, Any]:
        """Get site not assigned network devices

        Get network devices that are not assigned to any site.

        Args:
            offset (Any): The first record to show for this page; the first record is numbered 1.
            limit (Any): The number of records to show for this page.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/networkDevices/notAssignedToSite'
        params = {
            'offset': offset,
            'limit': limit,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_device_reboot_apreboot_status(self, parent_task_id: Optional[Any] = None) -> Dict[str, Any]:
        """Get Access Point Reboot task result

        Users can query the access point reboot status using this intent API

        Args:
            parent_task_id (Any): task id of ap reboot request

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/device-reboot/apreboot/status'
        params = {
            'parentTaskId': parent_task_id,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_device_detail(self, identifier: Any, search_by: Any, timestamp: Optional[Any] = None) -> Dict[str, Any]:
        """Get Device Detail

        Returns detailed Network Device information retrieved by Mac Address, Device Name or UUID for any given point of time. 

        Args:
            identifier (Any): One of "macAddress", "nwDeviceName", "uuid" (case insensitive)
            search_by (Any): MAC Address, device name, or UUID of the network device
            timestamp (Any): UTC timestamp of device data in milliseconds

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/device-detail'
        params = {
            'identifier': identifier,
            'searchBy': search_by,
            'timestamp': timestamp,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_integrate_ise_id(self, id: Any) -> Dict[str, Any]:
        """Accept Cisco ISE Server Certificate for Cisco ISE Server Integration

        API to accept Cisco ISE server certificate for Cisco ISE server integration. Use ‘Cisco ISE Server Integration Status’ Intent API to check the integration status. This API can be used to retry the failed integration.

        Args:
            id (Any): Cisco ISE Server Identifier. Use 'Get Authentication and Policy Servers' intent API to find the identifier.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/integrate-ise/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_lan_automation_count(self) -> Dict[str, Any]:
        """LAN Automation Session Count

        Invoke this API to get the total count of LAN Automation sessions.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/lan-automation/count'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_device_ip_address_ip_address(self, ip_address: Any) -> Dict[str, Any]:
        """Get Network Device by IP

        Returns the network device by specified IP address

        Args:
            ip_address (Any): Device IP address

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device/ip-address/{ip_address}'
        url = url.format(ip_address=ip_address)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_network_device_file(self, content__type: Any) -> Dict[str, Any]:
        """Export Device list

        Exports the selected network device to a file

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/network-device/file'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_network_device_deviceid_management_address(self, deviceid: Any) -> Dict[str, Any]:
        """Update Device Management Address

        This is a simple PUT API to edit the management IP Address of the device.

        Args:
            deviceid (Any): The UUID of the device whose management IP address is to be updated.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device/{deviceid}/management-address'
        url = url.format(deviceid=deviceid)
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_tag_id_member_member_id(self, id: Any, member_id: Any) -> Dict[str, Any]:
        """Remove Tag member

        Removes Tag member from the tag specified by id

        Args:
            id (Any): Tag ID
            member_id (Any): TagMember id to be removed from tag

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/tag/{id}/member/{member_id}'
        url = url.format(id=id, member_id=member_id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_onboarding_pnp_device_site_config_preview(self, content__type: Any) -> Dict[str, Any]:
        """Preview Config

        Triggers a preview for site-based Day 0 Configuration

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/onboarding/pnp-device/site-config-preview'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def post_dna_data_api_v1_assurance_issues_query_count(self, content__type: Any, x__c_a_l_l_e_r__i_d: Optional[Any] = None) -> Dict[str, Any]:
        """Get the total number of issues for given set of filters

        Returns the total number issues for given set of filters. If there is no start and/or end time, then end time will be defaulted to current time and start time will be defaulted to 24-hours ago from end time. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-IssuesList-1.0.0-resolved.yaml

        Args:
            content__type (Any): Request body content type
            x__c_a_l_l_e_r__i_d (Any): Caller ID can be used to trace the caller for queries executed on database. The caller id is like a optional attribute which can be added to API invocation like ui, python, postman, test-automation etc

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/data/api/v1/assuranceIssues/query/count'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_network_device_poller_cli_read_request(self, content__type: Any) -> Dict[str, Any]:
        """Run read-only commands on devices to get their real-time configuration

        Submit request for read-only CLIs

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/network-device-poller/cli/read-request'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_wireless_access_points_factory_reset_request_provision(self, content__type: Any) -> Dict[str, Any]:
        """Factory Reset Access Point(s)

        This API is used to factory reset Access Points. It is supported for maximum 100 Access Points per request. Factory reset clears all configurations from the Access Points. After factory reset the Access Point may become unreachable from the currently associated Wireless Controller and may or may not join back the same controller. 

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/wirelessAccessPoints/factoryResetRequest/provision'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def post_dna_data_api_v1_clients_query_count(self, content__type: Any, x__c_a_l_l_e_r__i_d: Optional[Any] = None) -> Dict[str, Any]:
        """Retrieves the number of clients by applying complex filters.

        Retrieves the number of clients by applying complex filters. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-clients1-1.0.0-resolved.yaml

        Args:
            content__type (Any): Request body content type
            x__c_a_l_l_e_r__i_d (Any): Caller ID is used to trace the origin of API calls and their associated queries executed on the database. It's an optional header parameter that can be added to an API request.


        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/data/api/v1/clients/query/count'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_devices_not_assigned_to_site_count(self) -> Dict[str, Any]:
        """Get site not assigned network devices count

        Get network devices count that are not assigned to any site.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/networkDevices/notAssignedToSite/count'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def delete_dna_system_api_v1_role_role_id(self, role_id: Any) -> Dict[str, Any]:
        """Delete role API

        Delete a role in Cisco DNA Center System

        Args:
            role_id (Any): The Id of the role to be deleted

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/system/api/v1/role/{role_id}'
        url = url.format(role_id=role_id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_device_serial_number_serial_number(self, serial_number: Any) -> Dict[str, Any]:
        """Get Device by Serial number

        Returns the network device with given serial number

        Args:
            serial_number (Any): Device serial number

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device/serial-number/{serial_number}'
        url = url.format(serial_number=serial_number)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v2_applications_count(self, scalable_group_type: Any) -> Dict[str, Any]:
        """Get Application Count

        Get the number of all existing applications

        Args:
            scalable_group_type (Any): scalable group type to retrieve, valid value APPLICATION

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v2/applications-count'
        params = {
            'scalableGroupType': scalable_group_type,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_data_reports_report_id_executions_execution_id(self, report_id: Any, execution_id: Any) -> Dict[str, Any]:
        """Download report content

        Returns report content. Save the response to a file by converting the response data as a blob and setting the file format available from content-disposition response header.

        Args:
            report_id (Any): reportId of report
            execution_id (Any): executionId of report execution

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/data/reports/{report_id}/executions/{execution_id}'
        url = url.format(report_id=report_id, execution_id=execution_id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_maps_import_start(self, content__type: Any) -> Dict[str, Any]:
        """Import Map Archive - Start Import

        Initiates a map archive import of a tar.gz file.  The archive must consist of one xmlDir/MapsImportExport.xml map descriptor file, and 1 or more images for the map areas nested under /images folder.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/maps/import/start'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_onboarding_pnp_device_count(self, serial_number: Optional[Any] = None, state: Optional[Any] = None, onb_state: Optional[Any] = None, name: Optional[Any] = None, pid: Optional[Any] = None, source: Optional[Any] = None, workflow_id: Optional[Any] = None, workflow_name: Optional[Any] = None, smart_account_id: Optional[Any] = None, virtual_account_id: Optional[Any] = None, last_contact: Optional[Any] = None) -> Dict[str, Any]:
        """Get Device Count

        Returns the device count based on filter criteria. This is useful for pagination

        Args:
            serial_number (Any): Device Serial Number
            state (Any): Device State
            onb_state (Any): Device Onboarding State
            name (Any): Device Name
            pid (Any): Device ProductId
            source (Any): Device Source
            workflow_id (Any): Device Workflow Id
            workflow_name (Any): Device Workflow Name
            smart_account_id (Any): Device Smart Account
            virtual_account_id (Any): Device Virtual Account
            last_contact (Any): Device Has Contacted lastContact > 0

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/onboarding/pnp-device/count'
        params = {
            'serialNumber': serial_number,
            'state': state,
            'onbState': onb_state,
            'name': name,
            'pid': pid,
            'source': source,
            'workflowId': workflow_id,
            'workflowName': workflow_name,
            'smartAccountId': smart_account_id,
            'virtualAccountId': virtual_account_id,
            'lastContact': last_contact,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_system_api_v1_event_artifact_count(self) -> Dict[str, Any]:
        """EventArtifact Count

        Get the count of registered event artifacts.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/system/api/v1/event/artifact/count'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_onboarding_pnp_device_claim(self, content__type: Any) -> Dict[str, Any]:
        """Claim Device

        Claims one of more devices with specified workflow

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/onboarding/pnp-device/claim'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_assurance_issues_resolve(self, content__type: Any, x__c_a_l_l_e_r__i_d: Optional[Any] = None) -> Dict[str, Any]:
        """Resolve the given lists of issues

        Resolves the given list of issues. The response contains the list of issues which were successfully resolved as well as the issues which are failed to resolve. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-IssuesLifecycle-1.0.0-resolved.yaml

        Args:
            content__type (Any): Request body content type
            x__c_a_l_l_e_r__i_d (Any): Caller ID can be used to trace the caller for queries executed on database. The caller id is like a optional attribute which can be added to API invocation like ui, python, postman, test-automation etc

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/intent/api/v1/assuranceIssues/resolve'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_compliance_count(self, compliance_status: Optional[Any] = None) -> Dict[str, Any]:
        """Get Compliance Status Count

        Return Compliance Status Count

        Args:
            compliance_status (Any): Specify "Compliance status(es)" separated by commas. The Compliance status can be 'COMPLIANT', 'NON_COMPLIANT', 'IN_PROGRESS', 'NOT_AVAILABLE', 'NOT_APPLICABLE', 'ERROR'.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/compliance/count'
        params = {
            'complianceStatus': compliance_status,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_tasks(self, offset: Optional[Any] = None, limit: Optional[Any] = None, sort_by: Optional[Any] = None, order: Optional[Any] = None, start_time: Optional[Any] = None, end_time: Optional[Any] = None, parent_id: Optional[Any] = None, root_id: Optional[Any] = None, status: Optional[Any] = None) -> Dict[str, Any]:
        """Get tasks

        Returns task(s) based on filter criteria

        Args:
            offset (Any): The first record to show for this page; the first record is numbered 1.
            limit (Any): The number of records to show for this page.
            sort_by (Any): A property within the response to sort by.
            order (Any): Whether ascending or descending order should be used to sort the response.
            start_time (Any): This is the epoch millisecond start time from which tasks need to be fetched
            end_time (Any): This is the epoch millisecond end time upto which task records need to be fetched
            parent_id (Any): Fetch tasks that have this parent Id
            root_id (Any): Fetch tasks that have this root Id
            status (Any): Fetch tasks that have this status. Available values : PENDING, FAILURE, SUCCESS

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/tasks'
        params = {
            'offset': offset,
            'limit': limit,
            'sortBy': sort_by,
            'order': order,
            'startTime': start_time,
            'endTime': end_time,
            'parentId': parent_id,
            'rootId': root_id,
            'status': status,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_data_api_v1_assurance_events_id_child_events(self, id: Any, x__c_a_l_l_e_r__i_d: Optional[Any] = None) -> Dict[str, Any]:
        """Get list of child events for the given wireless client event

        Wireless client event could have child events and this API can be used to fetch the same using parent event `id` as the input. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-AssuranceEvents-1.0.0-resolved.yaml

        Args:
            id (Any): Unique identifier for the event
            x__c_a_l_l_e_r__i_d (Any): Caller ID is used to trace the origin of API calls and their associated queries executed on the database. It's an optional header parameter that can be added to an API request.


        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/data/api/v1/assuranceEvents/{id}/childEvents'
        url = url.format(id=id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_provisioning_settings(self) -> Dict[str, Any]:
        """Get provisioning settings

        Returns provisioning settings

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/provisioningSettings'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_provisioning_settings(self, content__type: Any) -> Dict[str, Any]:
        """Set provisioning settings

        Sets provisioning settings

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/provisioningSettings'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_data_api_v1_site_health_summaries_count(self, x__c_a_l_l_e_r__i_d: Optional[Any] = None, end_time: Optional[Any] = None, site_hierarchy: Optional[Any] = None, site_hierarchy_id: Optional[Any] = None, site_type: Optional[Any] = None, id: Optional[Any] = None) -> Dict[str, Any]:
        """Read site count.

        Get a count of sites. Use the available query parameters to get the count of a subset of sites.
This API provides the latest data from a given `endTime`
If data is not ready for the provided endTime, the request will fail, and the error message will indicate the recommended endTime to use to retrieve a complete data set.
This behavior may occur if the provided endTime=currentTime, since we are not a real time system.
When `endTime` is not provided, the API returns the latest data. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-siteHealthSummaries-1.0.3-resolved.yaml


        Args:
            x__c_a_l_l_e_r__i_d (Any): Caller ID is used to trace the origin of API calls and their associated queries executed on the database. It's an optional header parameter that can be added to an API request.

            end_time (Any): End time to which API queries the data set related to the resource. It must be specified in UNIX epochtime in milliseconds. Value is inclusive.

            site_hierarchy (Any): The full hierarchical breakdown of the site tree starting from Global site name and ending with the specific site name. The Root site is named "Global" (Ex. `Global/AreaName/BuildingName/FloorName`)

This field supports wildcard asterisk (`*`) character search support. E.g. `*/San*, */San, /San*`

Examples:

`?siteHierarchy=Global/AreaName/BuildingName/FloorName` (single siteHierarchy requested)

`?siteHierarchy=Global/AreaName/BuildingName/FloorName&siteHierarchy=Global/AreaName2/BuildingName2/FloorName2` (multiple siteHierarchies requested)

            site_hierarchy_id (Any): The full hierarchy breakdown of the site tree in id form starting from Global site UUID and ending with the specific site UUID. (Ex. `globalUuid/areaUuid/buildingUuid/floorUuid`)

This field supports wildcard asterisk (`*`) character search support. E.g. `*uuid*, *uuid, uuid*`

Examples:

`?siteHierarchyId=globalUuid/areaUuid/buildingUuid/floorUuid `(single siteHierarchyId requested)

`?siteHierarchyId=globalUuid/areaUuid/buildingUuid/floorUuid&siteHierarchyId=globalUuid/areaUuid2/buildingUuid2/floorUuid2` (multiple siteHierarchyIds requested)

            site_type (Any): The type of the site. A site can be an area, building, or floor.

Default when not provided will be `[floor,building,area]`

Examples:

`?siteType=area` (single siteType requested)

`?siteType=area&siteType=building&siteType=floor` (multiple siteTypes requested)

            id (Any): The list of entity Uuids. (Ex."6bef213c-19ca-4170-8375-b694e251101c")
Examples: id=6bef213c-19ca-4170-8375-b694e251101c (single entity uuid requested)
id=6bef213c-19ca-4170-8375-b694e251101c&id=32219612-819e-4b5e-a96b-cf22aca13dd9&id=2541e9a7-b80d-4955-8aa2-79b233318ba0 (multiple entity uuid with '&' separator)


        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/data/api/v1/siteHealthSummaries/count'
        params = {
            'endTime': end_time,
            'siteHierarchy': site_hierarchy,
            'siteHierarchyId': site_hierarchy_id,
            'siteType': site_type,
            'id': id,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_eox_status_device_device_id(self, device_id: Any) -> Dict[str, Any]:
        """Get EoX Details Per Device

        Retrieves EoX details for a device 

        Args:
            device_id (Any): Device instance UUID

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/eox-status/device/{device_id}'
        url = url.format(device_id=device_id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_nodes_config(self) -> Dict[str, Any]:
        """Cisco DNA Center Nodes Configuration Summary

        Provides details about the current Cisco DNA Center node configuration, such as API version, node name, NTP server, intracluster link, LACP mode, network static routes, DNS server, subnet mask, host IP, default gateway, and interface information. 

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/nodes-config'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_maps_import_import_context_uuid_status(self, import_context_uuid: Any) -> Dict[str, Any]:
        """Import Map Archive - Import Status

        Gets the status of a map archive import operation. For a map archive import that has just been initiated, will provide the result of validation of the archive and a pre-import preview of what will be performed if the import is performed.  Once an import is requested to be performed, this API will give the status of the import and upon completion a post-import summary of what was performed by the operation.

        Args:
            import_context_uuid (Any): The unique import context UUID given by a previous and recent call to maps/import/start API

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/maps/import/{import_context_uuid}/status'
        url = url.format(import_context_uuid=import_context_uuid)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_system_api_v1_users_external_authentication(self, content__type: Any) -> Dict[str, Any]:
        """Manage External Authentication Setting API

        Enable or disable external authentication on Cisco DNA Center System.

Please find the Administrator Guide for your particular release from the list linked below and follow the steps required to enable external authentication before trying to do so from this API.

https://www.cisco.com/c/en/us/support/cloud-systems-management/dna-center/products-maintenance-guides-list.html

        Args:
            content__type (Any): The format of the payload

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/system/api/v1/users/external-authentication'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_system_api_v1_users_external_authentication(self) -> Dict[str, Any]:
        """Get External Authentication Setting API

        Get the External Authentication setting.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/system/api/v1/users/external-authentication'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_interface_id(self, id: Any) -> Dict[str, Any]:
        """Get Interface by Id

        Returns the interface for the given interface ID

        Args:
            id (Any): Interface ID

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/interface/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_licenses_device_device_uuid_details(self, device_uuid: Any) -> Dict[str, Any]:
        """Device License Details

        Get detailed license information of a device.

        Args:
            device_uuid (Any): Id of device

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/licenses/device/{device_uuid}/details'
        url = url.format(device_uuid=device_uuid)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_data_api_v1_interfaces_id(self, id: Any, start_time: Optional[Any] = None, end_time: Optional[Any] = None, view: Optional[Any] = None, attribute: Optional[Any] = None) -> Dict[str, Any]:
        """Get the interface data for the given interface id (instance Uuid) along with the statistics data

        Returns the interface data for the given interface instance Uuid along with the statistics data. The latest interface data in the specified start and end time range will be returned. When there is no start and end time specified returns the latest available data for the given interface Id. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-interfaces-1.0.2-resolved.yaml

        Args:
            id (Any): The interface Uuid
            start_time (Any): Start time from which API queries the data set related to the resource. It must be specified in UNIX epochtime in milliseconds. Value is inclusive.

If `startTime` is not provided, API will default to current time.

            end_time (Any): End time to which API queries the data set related to the resource. It must be specified in UNIX epochtime in milliseconds. Value is inclusive.

            view (Any): Interface data model views
            attribute (Any): The following list of attributes can be provided in the attribute field

[id,adminStatus, description,duplexConfig,duplexOper,interfaceIfIndex,interfaceType,ipv4Address,ipv6AddressList,isL3Interface,isWan,macAddress,mediaType,name,operStatus,peerStackMember,peerStackPort, portChannelId,portMode, portType,rxDiscards,rxError,rxRate,rxUtilization,speed,stackPortType,timestamp,txDiscards,txError,txRate,txUtilization,vlanId,networkDeviceId,networkDeviceIpAddress,networkDeviceMacAddress,siteName,siteHierarchy,siteHierarchyId]

If length of attribute list is too long, please use 'views' param instead.

Examples:

attributes=name (single attribute requested)

attributes=name,description,duplexOper (multiple attributes with comma separator)


        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/data/api/v1/interfaces/{id}'
        url = url.format(id=id)
        params = {
            'startTime': start_time,
            'endTime': end_time,
            'view': view,
            'attribute': attribute,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_interface_network_device_device_id(self, device_id: Any) -> Dict[str, Any]:
        """Get Interface info by Id

        Returns list of interfaces by specified device

        Args:
            device_id (Any): Device ID

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/interface/network-device/{device_id}'
        url = url.format(device_id=device_id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_data_api_v1_clients_top_n_analytics(self, content__type: Any, x__c_a_l_l_e_r__i_d: Optional[Any] = None) -> Dict[str, Any]:
        """Retrieves the Top-N analytics data related to clients.

         Retrieves the top N analytics data related to clients based on the provided input data. This API facilitates obtaining insights into the top-performing or most impacted clients. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-clients1-1.0.0-resolved.yaml

        Args:
            content__type (Any): Request body content type
            x__c_a_l_l_e_r__i_d (Any): Caller ID is used to trace the origin of API calls and their associated queries executed on the database. It's an optional header parameter that can be added to an API request.


        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/data/api/v1/clients/topNAnalytics'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_task_operation_operation_id_offset_limit(self, operation_id: Any, offset: Any, limit: Any) -> Dict[str, Any]:
        """Get task by OperationId

        Returns root tasks associated with an Operationid

        Args:
            operation_id (Any): operationId
            offset (Any): Index, minimum value is 0
            limit (Any): The maximum value of {limit} supported is 500. <br/> Base 1 indexing for {limit}, minimum value is 1

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/task/operation/{operation_id}/{offset}/{limit}'
        url = url.format(operation_id=operation_id, offset=offset, limit=limit)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_ise_integration_status(self) -> Dict[str, Any]:
        """Cisco ISE Server Integration Status

        API to check Cisco ISE server integration status.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/ise-integration-status'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_topology_l3_topology_type(self, topology_type: Any) -> Dict[str, Any]:
        """Get L3 Topology Details

        Returns the Layer 3 network topology by routing protocol

        Args:
            topology_type (Any): Type of topology(OSPF,ISIS,etc)

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/topology/l3/{topology_type}'
        url = url.format(topology_type=topology_type)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_licenses_smart_account_smart_account_id_virtual_account_virtual_account_name_device_transfer(self, smart_account_id: Any, virtual_account_name: Any) -> Dict[str, Any]:
        """Change Virtual Account

        Transfer device(s) from one virtual account to another within same smart account.

        Args:
            smart_account_id (Any): Id of smart account
            virtual_account_name (Any): Name of target virtual account

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/licenses/smartAccount/{smart_account_id}/virtualAccount/{virtual_account_name}/device/transfer'
        url = url.format(smart_account_id=smart_account_id, virtual_account_name=virtual_account_name)
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_security_advisory_device_device_id(self, device_id: Any) -> Dict[str, Any]:
        """Get Advisory Device Detail

        Retrieves advisory device details for a device

        Args:
            device_id (Any): Device instance UUID

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/security-advisory/device/{device_id}'
        url = url.format(device_id=device_id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_system_api_v1_event_config_connector_types(self) -> Dict[str, Any]:
        """Get Connector Types

        Get the list of connector types

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/system/api/v1/event/config/connector-types'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_data_api_v1_network_devices_query(self, content__type: Any) -> Dict[str, Any]:
        """Gets the list of Network Devices based on the provided complex filters and aggregation functions.

        Gets the list of Network Devices based on the provided complex filters and aggregation functions. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-AssuranceNetworkDevices-1.0.2-resolved.yaml

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/data/api/v1/networkDevices/query'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_tasks_id(self, id: Any) -> Dict[str, Any]:
        """Get tasks by ID

        Returns the task with the given ID

        Args:
            id (Any): the `id` of the task to retrieve

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/tasks/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_licenses_term_smart_account_smart_account_id_virtual_account_virtual_account_name(self, smart_account_id: Any, virtual_account_name: Any, device_type: Any) -> Dict[str, Any]:
        """License Term Details

        Get license term details.

        Args:
            smart_account_id (Any): Id of smart account
            virtual_account_name (Any): Name of virtual account. Putting "All" will give license term detail for all virtual accounts.
            device_type (Any): Type of device like router, switch, wireless or ise

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/licenses/term/smartAccount/{smart_account_id}/virtualAccount/{virtual_account_name}'
        url = url.format(smart_account_id=smart_account_id, virtual_account_name=virtual_account_name)
        params = {
            'device_type': device_type,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_sites_id_dhcp_settings(self, content__type: Any, id: Any) -> Dict[str, Any]:
        """Set dhcp settings for a site

        Set DHCP settings for a site; `null` values indicate that the setting will be inherited from the parent site; empty objects (`{}`) indicate that the settings is unset.

        Args:
            content__type (Any): Request body content type
            id (Any): Site Id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sites/{id}/dhcpSettings'
        url = url.format(id=id)
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sites_id_dhcp_settings(self, id: Any, inherited: Optional[Any] = None) -> Dict[str, Any]:
        """Retrieve DHCP settings for a site

        Retrieve DHCP settings for a site; `null` values indicate that the setting will be inherited from the parent site; empty objects (`{}`) indicate that the setting is unset at a site.

        Args:
            id (Any): Site Id
            inherited (Any): Include settings explicitly set for this site and settings inherited from sites higher in the site hierarchy; when `false`, `null` values indicate that the site inherits that setting from the parent site or a site higher in the site hierarchy.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sites/{id}/dhcpSettings'
        url = url.format(id=id)
        params = {
            '_inherited': inherited,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sda_anycast_gateways_count(self, fabric_id: Optional[Any] = None, virtual_network_name: Optional[Any] = None, ip_pool_name: Optional[Any] = None, vlan_name: Optional[Any] = None, vlan_id: Optional[Any] = None) -> Dict[str, Any]:
        """Get anycast gateway count

        Returns the count of anycast gateways that match the provided query parameters.

        Args:
            fabric_id (Any): ID of the fabric the anycast gateway is assigned to.
            virtual_network_name (Any): Name of the virtual network associated with the anycast gateways.
            ip_pool_name (Any): Name of the IP pool associated with the anycast gateways.
            vlan_name (Any): VLAN name of the anycast gateways.
            vlan_id (Any): VLAN ID of the anycast gateways. The allowed range for vlanId is [2-4093] except for reserved VLANs [1002-1005], 2046, and 4094.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/anycastGateways/count'
        params = {
            'fabricId': fabric_id,
            'virtualNetworkName': virtual_network_name,
            'ipPoolName': ip_pool_name,
            'vlanName': vlan_name,
            'vlanId': vlan_id,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_data_api_v1_network_devices(self, start_time: Optional[Any] = None, end_time: Optional[Any] = None, limit: Optional[Any] = None, offset: Optional[Any] = None, sort_by: Optional[Any] = None, order: Optional[Any] = None, site_hierarchy: Optional[Any] = None, site_hierarchy_id: Optional[Any] = None, site_id: Optional[Any] = None, id: Optional[Any] = None, management_ip_address: Optional[Any] = None, mac_address: Optional[Any] = None, family: Optional[Any] = None, type: Optional[Any] = None, role: Optional[Any] = None, serial_number: Optional[Any] = None, maintenance_mode: Optional[Any] = None, software_version: Optional[Any] = None, health_score: Optional[Any] = None, view: Optional[Any] = None, attribute: Optional[Any] = None) -> Dict[str, Any]:
        """Gets the Network Device details based on the provided query parameters.

        Gets the Network Device details based on the provided query parameters.  When there is no start and end time specified returns the latest device details. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-AssuranceNetworkDevices-1.0.2-resolved.yaml

        Args:
            start_time (Any): Start time from which API queries the data set related to the resource. It must be specified in UNIX epochtime in milliseconds. Value is inclusive.

If `startTime` is not provided, API will default to current time.

            end_time (Any): End time to which API queries the data set related to the resource. It must be specified in UNIX epochtime in milliseconds. Value is inclusive.

            limit (Any): Maximum number of records to return
            offset (Any): Specifies the starting point within all records returned by the API. It's one based offset. The starting value is 1.
            sort_by (Any): A field within the response to sort by.
            order (Any): The sort order of the field ascending or descending.
            site_hierarchy (Any): The full hierarchical breakdown of the site tree starting from Global site name and ending with the specific site name. The Root site is named "Global" (Ex. `Global/AreaName/BuildingName/FloorName`)

This field supports wildcard asterisk (*) character search support. E.g. */San*, */San, /San*

Examples:

`?siteHierarchy=Global/AreaName/BuildingName/FloorName` (single siteHierarchy requested)

`?siteHierarchy=Global/AreaName/BuildingName/FloorName&siteHierarchy=Global/AreaName2/BuildingName2/FloorName2` (multiple siteHierarchies requested)

            site_hierarchy_id (Any): The full hierarchy breakdown of the site tree in id form starting from Global site UUID and ending with the specific site UUID. (Ex. `globalUuid/areaUuid/buildingUuid/floorUuid`)

This field supports wildcard asterisk (*) character search support. E.g. `*uuid*, *uuid, uuid*

Examples:

`?siteHierarchyId=globalUuid/areaUuid/buildingUuid/floorUuid `(single siteHierarchyId requested)

`?siteHierarchyId=globalUuid/areaUuid/buildingUuid/floorUuid&siteHierarchyId=globalUuid/areaUuid2/buildingUuid2/floorUuid2` (multiple siteHierarchyIds requested)

            site_id (Any): The UUID of the site. (Ex. `flooruuid`)

This field supports wildcard asterisk (*) character search support. E.g.*flooruuid*, *flooruuid, flooruuid*

Examples:

`?siteId=id1` (single id requested)

`?siteId=id1&siteId=id2&siteId=id3` (multiple ids requested)

            id (Any): The list of entity Uuids. (Ex."6bef213c-19ca-4170-8375-b694e251101c")
Examples: id=6bef213c-19ca-4170-8375-b694e251101c (single entity uuid requested)
id=6bef213c-19ca-4170-8375-b694e251101c&id=32219612-819e-4b5e-a96b-cf22aca13dd9&id=2541e9a7-b80d-4955-8aa2-79b233318ba0 (multiple entity uuid with '&' separator)

            management_ip_address (Any): The list of entity management IP Address. It can be either Ipv4 or Ipv6 address or combination of both(Ex. "121.1.1.10")

This field supports wildcard (`*`) character-based search.  Ex: `*1.1*` or `1.1*` or `*1.1`

Examples:
managementIpAddresses=121.1.1.10
managementIpAddresses=121.1.1.10&managementIpAddresses=172.20.1.10&managementIpAddresses=200:10&=managementIpAddresses172.20.3.4 (multiple entity IP Address with & separator)

            mac_address (Any): The macAddress of the network device or client
This field supports wildcard (`*`) character-based search. 
Ex: `*AB:AB:AB*` or `AB:AB:AB*` or `*AB:AB:AB`
Examples:

`macAddress=AB:AB:AB:CD:CD:CD` (single macAddress requested)

`macAddress=AB:AB:AB:CD:CD:DC&macAddress=AB:AB:AB:CD:CD:FE` (multiple macAddress requested)

            family (Any): The list of network device family names Examples:family=Switches and Hubs (single network device family name )family=Switches and Hubs&family=Router&family=Wireless Controller (multiple Network device family names with & separator). This field is not case sensitive.
            type (Any): The list of network device type This field supports wildcard (`*`) character-based search. Ex: `*9407R*` or `*9407R` or `9407R*`
Examples:
type=SwitchesCisco Catalyst 9407R Switch (single network device types )
type=Cisco Catalyst 38xx stack-able ethernet switch&type=Cisco 3945 Integrated Services Router G2 (multiple Network device types with & separator)

            role (Any): The list of network device role. Examples:role=CORE, role=CORE&role=ACCESS&role=ROUTER (multiple Network device roles with & separator). This field is not case sensitive.
            serial_number (Any): The list of network device serial numbers. This field supports wildcard (`*`) character-based search.  Ex: `*MS1SV*` or `MS1SV*` or `*MS1SV`
Examples:
serialNumber=9FUFMS1SVAX serialNumber=9FUFMS1SVAX&FCW2333Q0BY&FJC240617JX(multiple Network device serial number with & separator)

            maintenance_mode (Any): The device maintenanceMode status true or false
            software_version (Any): The list of network device software version This field supports wildcard (`*`) character-based search. Ex: `*17.8*` or `*17.8` or `17.8*`
Examples:
softwareVersion=2.3.4.0 (single network device software version )
softwareVersion=17.9.3.23&softwareVersion=17.7.1.2&softwareVersion=*.17.7 (multiple Network device software versions with & separator)

            health_score (Any): The list of entity health score categories

Examples:

healthScore=good,
healthScore=good&healthScore=fair (multiple entity healthscore values with & separator). This field is not case sensitive.

            view (Any): The List of Network Device model views. Please refer to ```NetworkDeviceView``` for the supported list
            attribute (Any): The List of Network Device model attributes. This is helps to specify the interested fields in the request.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/data/api/v1/networkDevices'
        params = {
            'startTime': start_time,
            'endTime': end_time,
            'limit': limit,
            'offset': offset,
            'sortBy': sort_by,
            'order': order,
            'siteHierarchy': site_hierarchy,
            'siteHierarchyId': site_hierarchy_id,
            'siteId': site_id,
            'id': id,
            'managementIpAddress': management_ip_address,
            'macAddress': mac_address,
            'family': family,
            'type': type,
            'role': role,
            'serialNumber': serial_number,
            'maintenanceMode': maintenance_mode,
            'softwareVersion': software_version,
            'healthScore': health_score,
            'view': view,
            'attribute': attribute,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_images_id_download(self, id: Any) -> Dict[str, Any]:
        """Download the software image

        Initiates download of the software image from Cisco.com on the disk for the given `id`. Refer to `/dna/intent/api/v1/images` for obtaining `id`.

        Args:
            id (Any): Software image identifier. Check API `/dna/intent/api/v1/images` for `id` from response.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/images/{id}/download'
        url = url.format(id=id)
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_issues(self, start_time: Optional[Any] = None, end_time: Optional[Any] = None, site_id: Optional[Any] = None, device_id: Optional[Any] = None, mac_address: Optional[Any] = None, priority: Optional[Any] = None, issue_status: Optional[Any] = None, ai_driven: Optional[Any] = None) -> Dict[str, Any]:
        """Issues

        Intent API to get a list of global issues, issues for a specific device, or issue for a specific client device's MAC address.

        Args:
            start_time (Any): Starting epoch time in milliseconds of query time window
            end_time (Any): Ending epoch time in milliseconds of query time window
            site_id (Any): Assurance UUID value of the site in the issue content
            device_id (Any): Assurance UUID value of the device in the issue content
            mac_address (Any): Client's device MAC address of the issue (format xx:xx:xx:xx:xx:xx)
            priority (Any): The issue's priority value: P1, P2, P3, or P4 (case insensitive) (Use only when macAddress and deviceId are not provided)
            issue_status (Any): The issue's status value: ACTIVE, IGNORED, RESOLVED (case insensitive)
            ai_driven (Any): The issue's AI driven value: YES or NO (case insensitive) (Use only when macAddress and deviceId are not provided)

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/issues'
        params = {
            'startTime': start_time,
            'endTime': end_time,
            'siteId': site_id,
            'deviceId': device_id,
            'macAddress': mac_address,
            'priority': priority,
            'issueStatus': issue_status,
            'aiDriven': ai_driven,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_device_tenantinfo_macaddress(self, serial_number: Optional[Any] = None, macaddress: Optional[Any] = None) -> Dict[str, Any]:
        """Get Devices registered for WSA Notification

        It fetches devices which are registered to receive WSA notifications. The device serial number and/or MAC address are required to be provided as query parameters.

        Args:
            serial_number (Any): Serial number of the device
            macaddress (Any): Mac addres of the device

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device/tenantinfo/macaddress'
        params = {
            'serialNumber': serial_number,
            'macaddress': macaddress,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_sites_bulk(self, content__type: Any) -> Dict[str, Any]:
        """Create sites

        Create area/building/floor together in bulk. If site already exist, then that will be ignored. Sites in the request payload need not to be ordered.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sites/bulk'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_interface_ip_address_ip_address(self, ip_address: Any) -> Dict[str, Any]:
        """Get Interface by IP

        Returns list of interfaces for specified device management IP address

        Args:
            ip_address (Any): IP address of the interface

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/interface/ip-address/{ip_address}'
        url = url.format(ip_address=ip_address)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_images_id_addon_images(self, id: Any) -> Dict[str, Any]:
        """Retrieve applicable add-on images for the given software image

        Retrieves the list of applicable add-on images if available for the given software image. `id` can be obtained from the response of API [ /dna/intent/api/v1/images?hasAddonImages=true ].

        Args:
            id (Any): Software image identifier. Check `/dna/intent/api/v1/images?hasAddonImages=true` API to get the same.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/images/{id}/addonImages'
        url = url.format(id=id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_data_api_v1_clients(self, x__c_a_l_l_e_r__i_d: Optional[Any] = None, start_time: Optional[Any] = None, end_time: Optional[Any] = None, limit: Optional[Any] = None, offset: Optional[Any] = None, sort_by: Optional[Any] = None, order: Optional[Any] = None, type: Optional[Any] = None, os_type: Optional[Any] = None, os_version: Optional[Any] = None, site_hierarchy: Optional[Any] = None, site_hierarchy_id: Optional[Any] = None, site_id: Optional[Any] = None, ipv4_address: Optional[Any] = None, ipv6_address: Optional[Any] = None, mac_address: Optional[Any] = None, wlc_name: Optional[Any] = None, connected_network_device_name: Optional[Any] = None, ssid: Optional[Any] = None, band: Optional[Any] = None, view: Optional[Any] = None, attribute: Optional[Any] = None) -> Dict[str, Any]:
        """Retrieves the list of clients, while also offering basic filtering and sorting capabilities.

        Retrieves the list of clients, while also offering basic filtering and sorting capabilities. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-clients1-1.0.0-resolved.yaml

        Args:
            x__c_a_l_l_e_r__i_d (Any): Caller ID is used to trace the origin of API calls and their associated queries executed on the database. It's an optional header parameter that can be added to an API request.

            start_time (Any): Start time from which API queries the data set related to the resource. It must be specified in UNIX epochtime in milliseconds. Value is inclusive.

If `startTime` is not provided, API will default to current time.

            end_time (Any): End time to which API queries the data set related to the resource. It must be specified in UNIX epochtime in milliseconds. Value is inclusive.

            limit (Any): Maximum number of records to return
            offset (Any): Specifies the starting point within all records returned by the API. It's one based offset. The starting value is 1.
            sort_by (Any): A field within the response to sort by.
            order (Any): The sort order of the field ascending or descending.
            type (Any): The client device type whether client is connected to network through Wired or Wireless medium.

            os_type (Any): Client device operating system type.
This field supports wildcard (`*`) character-based search. If the value contains the (`*`) character, please use the /query API for regex search. 
Ex: `*iOS*` or `iOS*` or `*iOS`
Examples:

`osType=iOS` (single osType requested)

`osType=iOS&osType=Android` (multiple osType requested)

            os_version (Any): Client device operating system version
This field supports wildcard (`*`) character-based search. If the value contains the (`*`) character, please use the /query API for regex search. 
Ex: `*14.3*` or `14.3*` or `*14.3`
Examples:

`osVersion=14.3` (single osVersion requested)

`osVersion=14.3&osVersion=10.1` (multiple osVersion requested)

            site_hierarchy (Any): The full hierarchical breakdown of the site tree starting from Global site name and ending with the specific site name. The Root site is named "Global" (Ex. "Global/AreaName/BuildingName/FloorName") This field supports wildcard (`*`) character-based search. If the value contains the (`*`) character, please use the /query API for regex search.  Ex: `*BuildingName*` or `BuildingName*` or `*BuildingName`
Examples:
`siteHierarchy=Global/AreaName/BuildingName/FloorName` (single siteHierarchy requested)
`siteHierarchy=Global/AreaName/BuildingName1/FloorName1&siteHierarchy=Global/AreaName/BuildingName1/FloorName2` (multiple siteHierarchy requested)
            site_hierarchy_id (Any): The full hierarchy breakdown of the site tree in id form starting from Global site UUID and ending with the specific site UUID. (Ex. "globalUuid/areaUuid/buildingUuid/floorUuid") This field supports wildcard (`*`) character-based search.  Ex: `*buildingUuid*` or `buildingUuid*` or `*buildingUuid`
Examples:
`siteHierarchyId=globalUuid/areaUuid/buildingUuid/floorUuid` (single siteHierarchyId requested)
`siteHierarchyId=globalUuid/areaUuid/buildingUuid1/floorUuid1&siteHierarchyId=globalUuid/areaUuid/buildingUuid1/floorUuid2` (multiple siteHierarchyId requested)
            site_id (Any): The site UUID without the top level hierarchy. (Ex."floorUuid") Examples:
`siteId=floorUuid` (single siteId requested)
`siteId=floorUuid1&siteId=floorUuid2` (multiple siteId requested)
            ipv4_address (Any): IPv4 Address of the network entity either network device or client
This field supports wildcard (`*`) character-based search. 
Ex: `*1.1*` or `1.1*` or `*1.1`

Examples:

`ipv4Address=1.1.1.1` (single ipv4Address requested)

`ipv4Address=1.1.1.1&ipv4Address=2.2.2.2` (multiple ipv4Address requested)

            ipv6_address (Any): IPv6 Address of the network entity either network device or client
This field supports wildcard (`*`) character-based search.
Ex: `*2001:db8*` or `2001:db8*` or `*2001:db8`

Examples:

`ipv6Address=2001:db8:0:0:0:0:2:1` (single ipv6Address requested)

`ipv6Address=2001:db8:0:0:0:0:2:1&ipv6Address=2001:db8:85a3:8d3:1319:8a2e:370:7348` (multiple ipv6Address requested)

            mac_address (Any): The macAddress of the network device or client
This field supports wildcard (`*`) character-based search. 
Ex: `*AB:AB:AB*` or `AB:AB:AB*` or `*AB:AB:AB`
Examples:

`macAddress=AB:AB:AB:CD:CD:CD` (single macAddress requested)

`macAddress=AB:AB:AB:CD:CD:DC&macAddress=AB:AB:AB:CD:CD:FE` (multiple macAddress requested)

            wlc_name (Any): Wireless Controller name that reports the wireless client.
This field supports wildcard (`*`) character-based search. If the value contains the (`*`) character, please use the /query API for regex search.
Ex: `*wlc-25*` or `wlc-25*` or `*wlc-25`

Examples:

`wlcName=wlc-25` (single wlcName requested)

`wlcName=wlc-25&wlc-34` (multiple wlcName requested)

            connected_network_device_name (Any): Name of the neighbor network device that client is connected to.
This field supports wildcard (`*`) character-based search. If the value contains the (`*`) character, please use the /query API for regex search.
Ex: `*ap-25*` or `ap-25*` or `*ap-25`

Examples:

`connectedNetworkDeviceName=ap-25` (single connectedNetworkDeviceName requested)

`connectedNetworkDeviceName=ap-25&ap-34` (multiple connectedNetworkDeviceName requested)    

            ssid (Any): SSID is the name of wireless network to which client connects to. It is also referred to as WLAN ID - Wireless Local Area Network Identifier.
This field supports wildcard (`*`) character-based search. If the value contains the (`*`) character, please use the /query API for regex search. 
Ex: `*Alpha*` or `Alpha*` or `*Alpha`

Examples:

`ssid=Alpha` (single ssid requested)

`ssid=Alpha&ssid=Guest` (multiple ssid requested)

            band (Any): WiFi frequency band that client or Access Point operates. Band value is represented in Giga Hertz - GHz
Examples:

`band=5GHZ` (single band requested)

`band=2.4GHZ&band=6GHZ` (multiple band requested)

            view (Any): Client related Views
Refer to ClientView schema for list of views supported
Examples:

`view=Wireless` (single view requested)

`view=WirelessHealth&view=WirelessTraffic` (multiple view requested)

            attribute (Any): List of attributes related to resource that can be requested to only be part of the response along with the required attributes. Refer to ClientAttribute schema for list of attributes supported Examples:
`attribute=band` (single attribute requested)
`attribute=band&attribute=ssid&attribute=overallScore` (multiple attribute requested)

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/data/api/v1/clients'
        params = {
            'startTime': start_time,
            'endTime': end_time,
            'limit': limit,
            'offset': offset,
            'sortBy': sort_by,
            'order': order,
            'type': type,
            'osType': os_type,
            'osVersion': os_version,
            'siteHierarchy': site_hierarchy,
            'siteHierarchyId': site_hierarchy_id,
            'siteId': site_id,
            'ipv4Address': ipv4_address,
            'ipv6Address': ipv6_address,
            'macAddress': mac_address,
            'wlcName': wlc_name,
            'connectedNetworkDeviceName': connected_network_device_name,
            'ssid': ssid,
            'band': band,
            'view': view,
            'attribute': attribute,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_eox_status_summary(self) -> Dict[str, Any]:
        """Get EoX Summary

        Retrieves EoX summary for all devices in the network

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/eox-status/summary'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_sda_fabric_devices_layer3_handoffs_ip_transits_id(self, id: Any) -> Dict[str, Any]:
        """Delete fabric device layer 3 handoff with ip transit by id

        Deletes a layer 3 handoff with ip transit of a fabric device by id.

        Args:
            id (Any): ID of the layer 3 handoff with ip transit of a fabric device.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/fabricDevices/layer3Handoffs/ipTransits/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_diagnostics_system_performance(self, kpi: Optional[Any] = None, function: Optional[Any] = None, start_time: Optional[Any] = None, end_time: Optional[Any] = None) -> Dict[str, Any]:
        """System Performance API

        Retrieves the aggregated metrics (total, average or maximum) of cluster key performance indicators (KPIs), such as CPU utilization, memory utilization or network rates recorded within a specified time period. The data will be available from the past 24 hours.

        Args:
            kpi (Any): Valid values: cpu,memory,network
            function (Any): Valid values: sum,average,max
            start_time (Any): This is the epoch start time in milliseconds from which performance indicator need to be fetched
            end_time (Any): This is the epoch end time in milliseconds upto which performance indicator need to be fetched

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/diagnostics/system/performance'
        params = {
            'kpi': kpi,
            'function': function,
            'startTime': start_time,
            'endTime': end_time,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_data_api_v1_assurance_events_query_count(self, content__type: Any, x__c_a_l_l_e_r__i_d: Optional[Any] = None) -> Dict[str, Any]:
        """Count the number of events with filters

        API to fetch the count of assurance events for the given complex query. Please refer to the 'API Support Documentation' section to understand which fields are supported. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-AssuranceEvents-1.0.0-resolved.yaml

        Args:
            content__type (Any): Request body content type
            x__c_a_l_l_e_r__i_d (Any): Caller ID is used to trace the origin of API calls and their associated queries executed on the database. It's an optional header parameter that can be added to an API request.


        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/data/api/v1/assuranceEvents/query/count'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def post_dna_data_api_v1_clients_id_trend_analytics(self, content__type: Any, id: Any, x__c_a_l_l_e_r__i_d: Optional[Any] = None) -> Dict[str, Any]:
        """Retrieves specific client information over a specified period of time.

        Retrieves the time series information of a specific client by applying complex filters, aggregate functions, and grouping. The data will be grouped based on the specified trend time interval. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-clients1-1.0.0-resolved.yaml

        Args:
            content__type (Any): Request body content type
            id (Any): id is the client mac address. It can be specified in one of the notational conventions 
01:23:45:67:89:AB or 01-23-45-67-89-AB or 0123.4567.89AB and is case insensitive

            x__c_a_l_l_e_r__i_d (Any): Caller ID is used to trace the origin of API calls and their associated queries executed on the database. It's an optional header parameter that can be added to an API request.


        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/data/api/v1/clients/{id}/trendAnalytics'
        url = url.format(id=id)
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_wireless_controllers_network_device_id_managed_ap_locations_count(self, network_device_id: Any) -> Dict[str, Any]:
        """Get Managed AP Locations Count for specific Wireless Controller

        Retrieves the count of Managed AP locations, including Primary Managed AP Locations, Secondary Managed AP Locations, and Anchor Managed AP Locations, associated with the specific Wireless Controller.

        Args:
            network_device_id (Any): Obtain the network device ID value by using the API call GET: /dna/intent/api/v1/network-device/ip-address/${ipAddress}.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/wirelessControllers/{network_device_id}/managedApLocations/count'
        url = url.format(network_device_id=network_device_id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_device_start_index_records_to_return(self, start_index: Any, records_to_return: Any) -> Dict[str, Any]:
        """Get Network Device by pagination range

        Returns the list of network devices for the given pagination range. The maximum number of records that can be retrieved is 500

        Args:
            start_index (Any): Start index [>=1]
            records_to_return (Any): Number of records to return [1<= recordsToReturn <= 500]

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device/{start_index}/{records_to_return}'
        url = url.format(start_index=start_index, records_to_return=records_to_return)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_devices_id_assigned_to_site(self, id: Any) -> Dict[str, Any]:
        """Get site assigned network device

        Get site assigned network device. The items in the list are arranged in an order that corresponds with their internal identifiers.

        Args:
            id (Any): Network Device Id.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/networkDevices/{id}/assignedToSite'
        url = url.format(id=id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_intent_api_v1_custom_issue_definitions_id(self, id: Any, x__c_a_l_l_e_r__i_d: Optional[Any] = None) -> Dict[str, Any]:
        """Get the custom issue definition for the given custom issue definition Id.

        Get the custom issue definition for the given custom issue definition Id. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-AssuranceUserDefinedIssueAPIs-1.0.0-resolved.yaml


        Args:
            id (Any): Get the custom issue definition for the given custom issue definition Id.
            x__c_a_l_l_e_r__i_d (Any): Caller ID can be used to trace the caller for queries executed on database. The caller id is like a optional attribute which can be added to API invocation like ui, python, postman, test-automation etc

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/intent/api/v1/customIssueDefinitions/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_interface(self, offset: Optional[Any] = None, limit: Optional[Any] = None, last_input_time: Optional[Any] = None, last_output_time: Optional[Any] = None) -> Dict[str, Any]:
        """Get all interfaces

        Returns all available interfaces. This endpoint can return a maximum of 500 interfaces

        Args:
            offset (Any): Offset
            limit (Any): Limit
            last_input_time (Any): Last Input Time
            last_output_time (Any): Last Output Time

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/interface'
        params = {
            'offset': offset,
            'limit': limit,
            'lastInputTime': last_input_time,
            'lastOutputTime': last_output_time,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_images_id_addon_images_count(self, id: Any) -> Dict[str, Any]:
        """Returns count of add-on images

        Count of add-on images available for the given software image identifier, `id` can be obtained from the response of API [ /dna/intent/api/v1/images?hasAddonImages=true ].

        Args:
            id (Any): Software image identifier. Check API `/dna/intent/api/v1/images` for id from response.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/images/{id}/addonImages/count'
        url = url.format(id=id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_device_id_wireless_info(self, id: Any) -> Dict[str, Any]:
        """Get wireless lan controller details by Id

        Returns the wireless lan controller info with given device ID

        Args:
            id (Any): Device ID

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device/{id}/wireless-info'
        url = url.format(id=id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_dnac_packages(self) -> Dict[str, Any]:
        """Cisco DNA Center Packages Summary

        Provides information such as name, version of packages installed on the DNA center.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/dnac-packages'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_data_api_v1_clients_summary_analytics(self, content__type: Any, x__c_a_l_l_e_r__i_d: Optional[Any] = None) -> Dict[str, Any]:
        """Retrieves summary analytics data related to clients.

        Retrieves summary analytics data related to clients while applying complex filtering, aggregate functions, and grouping. This API facilitates obtaining consolidated insights into the performance and status of the clients. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-clients1-1.0.0-resolved.yaml

        Args:
            content__type (Any): Request body content type
            x__c_a_l_l_e_r__i_d (Any): Caller ID is used to trace the origin of API calls and their associated queries executed on the database. It's an optional header parameter that can be added to an API request.


        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/data/api/v1/clients/summaryAnalytics'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_wireless_settings_rf_profiles_count(self) -> Dict[str, Any]:
        """Get RF Profiles Count

        This API allows the user to get count of all RF profiles

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/wirelessSettings/rfProfiles/count'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_security_advisory_advisory_advisory_id_device(self, advisory_id: Any) -> Dict[str, Any]:
        """Get Devices Per Advisory

        Retrieves list of devices for an advisory

        Args:
            advisory_id (Any): Advisory ID

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/security-advisory/advisory/{advisory_id}/device'
        url = url.format(advisory_id=advisory_id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_wireless_accesspoint_configuration_details_task_id(self, task_id: Any) -> Dict[str, Any]:
        """Get Access Point Configuration task result

        Users can query the access point configuration result using this intent API

        Args:
            task_id (Any): task id information of ap config

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/wireless/accesspoint-configuration/details/{task_id}'
        url = url.format(task_id=task_id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_template_programmer_project_importprojects(self, content__type: Any, do_version: Optional[Any] = None) -> Dict[str, Any]:
        """Imports the Projects provided

        Imports the Projects provided in the DTO

        Args:
            content__type (Any): Request body content type
            do_version (Any): If this flag is true then it creates a new version of the template with the imported contents in case if the templates already exists. "
If this flag is false and if template already exists, then operation fails with 'Template already exists' error

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/template-programmer/project/importprojects'
        params = {
            'doVersion': do_version,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_compliance_detail(self, compliance_type: Optional[Any] = None, compliance_status: Optional[Any] = None, device_uuid: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None) -> Dict[str, Any]:
        """Get Compliance Detail 

        Return Compliance Detail 

        Args:
            compliance_type (Any): Specify "Compliance type(s)" in commas. The Compliance type can be 'NETWORK_PROFILE', 'IMAGE', 'FABRIC', 'APPLICATION_VISIBILITY', 'FABRIC', RUNNING_CONFIG', 'NETWORK_SETTINGS', 'WORKFLOW' , 'EOX'.
            compliance_status (Any): Specify "Compliance status(es)" in commas. The Compliance status can be 'COMPLIANT', 'NON_COMPLIANT', 'IN_PROGRESS', 'NOT_AVAILABLE', 'NOT_APPLICABLE', 'ERROR'.
            device_uuid (Any): Comma separated "Device Id(s)"
            offset (Any): offset/starting row
            limit (Any): Number of records to be retrieved

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/compliance/detail'
        params = {
            'complianceType': compliance_type,
            'complianceStatus': compliance_status,
            'deviceUuid': device_uuid,
            'offset': offset,
            'limit': limit,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v2_floors_id_upload_image(self, content__type: Any, id: Any) -> Dict[str, Any]:
        """Uploads floor image

        Uploads floor image.

        Args:
            content__type (Any): Request body content type
            id (Any): Floor Id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v2/floors/{id}/uploadImage'
        url = url.format(id=id)
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_sda_port_assignments_id(self, id: Any) -> Dict[str, Any]:
        """Delete port assignment by id

        Deletes a port assignment based on id.

        Args:
            id (Any): ID of the port assignment.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/portAssignments/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sda_fabrics_fabric_id_vlan_to_ssids_count(self, content__type: Any, fabric_id: Any) -> Dict[str, Any]:
        """Returns the count of VLANs mapped to SSIDs in a Fabric Site.

        Returns the count of VLANs mapped to SSIDs in a Fabric Site. The 'fabricId' represents the Fabric ID of a particular Fabric Site.

        Args:
            content__type (Any): Content Type
            fabric_id (Any): The 'fabricId' represents the Fabric ID of a particular Fabric Site

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/sda/fabrics/{fabric_id}/vlanToSsids/count'
        url = url.format(fabric_id=fabric_id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_global_credential(self, credential_sub_type: Any, sort_by: Optional[Any] = None, order: Optional[Any] = None) -> Dict[str, Any]:
        """Get Global credentials

        Returns global credential for the given credential sub type

        Args:
            credential_sub_type (Any): Credential type as CLI / SNMPV2_READ_COMMUNITY / SNMPV2_WRITE_COMMUNITY / SNMPV3 / HTTP_WRITE / HTTP_READ / NETCONF
            sort_by (Any): Field to sort the results by. Sorts by 'instanceId' if no value is provided
            order (Any): Order of sorting. 'asc' or 'des'

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/global-credential'
        params = {
            'credentialSubType': credential_sub_type,
            'sortBy': sort_by,
            'order': order,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_data_api_v1_assurance_issues_trend_analytics(self, content__type: Any, accept__language: Optional[Any] = None, x__c_a_l_l_e_r__i_d: Optional[Any] = None) -> Dict[str, Any]:
        """Get trend analytics data of issues

        Gets the trend analytics data related to issues based on given filters and group by field. This data can be used to find issue counts in different intervals over a period of time. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-IssuesList-1.0.0-resolved.yaml

        Args:
            content__type (Any): Request body content type
            accept__language (Any): This header parameter can be used to specify the language in which issue display name need to be returned. Available options are - 'en' (English), 'ja' (Japanese), 'ko' (Korean), 'zh' (Chinese). If this parameter is not present the issue display name is returned in English language.
            x__c_a_l_l_e_r__i_d (Any): Caller ID can be used to trace the caller for queries executed on database. The caller id is like a optional attribute which can be added to API invocation like ui, python, postman, test-automation etc

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        if accept__language is not None:
            request_headers['Accept-Language'] = str(accept__language)
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/data/api/v1/assuranceIssues/trendAnalytics'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_compliance(self, compliance_status: Optional[Any] = None, device_uuid: Optional[Any] = None) -> Dict[str, Any]:
        """Get Compliance Status 

        Return compliance status of device(s).

        Args:
            compliance_status (Any): Specify "Compliance status(es)" separated by commas. The Compliance status can be 'COMPLIANT', 'NON_COMPLIANT', 'IN_PROGRESS', 'NOT_AVAILABLE', 'NOT_APPLICABLE', 'ERROR'.
            device_uuid (Any): Comma separated 'Device Ids'

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/compliance'
        params = {
            'complianceStatus': compliance_status,
            'deviceUuid': device_uuid,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_dna_event_snmp_config(self, config_id: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None, sort_by: Optional[Any] = None, order: Optional[Any] = None) -> Dict[str, Any]:
        """Get SNMP Destination

        Get SNMP Destination

        Args:
            config_id (Any): List of SNMP configurations
            offset (Any): The number of SNMP configuration's to offset in the resultset whose default value 0
            limit (Any): The number of SNMP configuration's to limit in the resultset whose default value 10
            sort_by (Any): SortBy field name
            order (Any): order(asc/desc)

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/dna-event/snmp-config'
        params = {
            'configId': config_id,
            'offset': offset,
            'limit': limit,
            'sortBy': sort_by,
            'order': order,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_image_activation_device(self, content__type: Any, client__type: Optional[Any] = None, client__url: Optional[Any] = None, schedule_validate: Optional[Any] = None) -> Dict[str, Any]:
        """Trigger software image activation

        Activates a software image on a given device. Software image must be present in the device flash

        Args:
            content__type (Any): Request body content type
            client__type (Any): Client-type (Optional)
            client__url (Any): Client-url (Optional)
            schedule_validate (Any): scheduleValidate, validates data before schedule (Optional)

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        if client__type is not None:
            request_headers['Client-Type'] = str(client__type)
        if client__url is not None:
            request_headers['Client-Url'] = str(client__url)
        url = self.base_url + '/dna/intent/api/v1/image/activation/device'
        params = {
            'scheduleValidate': schedule_validate,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sda_provision_devices_count(self, site_id: Optional[Any] = None) -> Dict[str, Any]:
        """Get Provisioned Devices count

        Returns the count of provisioned devices based on query parameters.


        Args:
            site_id (Any): ID of the site hierarchy.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sda/provisionDevices/count'
        params = {
            'siteId': site_id,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_images(self, site_id: Optional[Any] = None, product_name_ordinal: Optional[Any] = None, supervisor_product_name_ordinal: Optional[Any] = None, imported: Optional[Any] = None, name: Optional[Any] = None, version: Optional[Any] = None, golden: Optional[Any] = None, integrity: Optional[Any] = None, has_addon_images: Optional[Any] = None, is_addon_images: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None) -> Dict[str, Any]:
        """Returns list of software images

        A list of available images for the specified site is provided. The default value of the site is set to global. The list includes images that have been imported onto the disk, as well as the latest and suggested images from Cisco.com. 

        Args:
            site_id (Any): Site identifier to get the list of all available products under the site. The default value is the global site.  See https://developer.cisco.com/docs/dna-center/get-site for `siteId`
            product_name_ordinal (Any): The product name ordinal is a unique value for each network device product. The productNameOrdinal can be obtained from the response of API `/dna/intent/api/v1/siteWiseProductNames`
            supervisor_product_name_ordinal (Any): The supervisor engine module ordinal is a unique value for each supervisor module. The `supervisorProductNameOrdinal` can be obtained from the response of API `/dna/intent/api/v1/siteWiseProductNames`
            imported (Any): When the value is set to `true`, it will include physically imported images. Conversely, when the value is set to `false`, it will include image records from the cloud. The identifier for cloud images can be utilized to download images from Cisco.com to the disk.
            name (Any): Filter with software image or add-on name. Supports partial case-insensitive search. A minimum of 3 characters is required for the search.
            version (Any): Filter with image version. Supports partial case-insensitive search. A minimum of 3 characters is required for the search.
            golden (Any): When set to `true`, it will retrieve the images marked as tagged golden. When set to `false`, it will retrieve the images marked as not tagged golden.
            integrity (Any): Filter with verified images using Integrity Verification Available values: UNKNOWN, VERIFIED
            has_addon_images (Any): When set to `true`, it will retrieve the images which have add-on images. When set to `false`, it will retrieve the images which do not have add-on images.
            is_addon_images (Any): When set to `true`, it will retrieve the images that an add-on image.  When set to `false`, it will retrieve the images that are not add-on images
            offset (Any): The first record to show for this page; the first record is numbered 1. The minimum value is 1.
            limit (Any): The number of records to show for this page. The minimum and maximum values are 1 and 500, respectively.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/images'
        params = {
            'siteId': site_id,
            'productNameOrdinal': product_name_ordinal,
            'supervisorProductNameOrdinal': supervisor_product_name_ordinal,
            'imported': imported,
            'name': name,
            'version': version,
            'golden': golden,
            'integrity': integrity,
            'hasAddonImages': has_addon_images,
            'isAddonImages': is_addon_images,
            'offset': offset,
            'limit': limit,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_wireless_settings_interfaces_count(self) -> Dict[str, Any]:
        """Get Interfaces Count

        This API allows the user to get count of all interfaces

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/wirelessSettings/interfaces/count'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_wireless_controllers_wireless_mobility_groups_mobility_reset(self, content__type: Any) -> Dict[str, Any]:
        """Mobility Reset

        This API is used to reset wireless mobility which in turn sets mobility group name as 'default'

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/wirelessControllers/wirelessMobilityGroups/mobilityReset'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_data_api_v1_site_health_summaries(self, x__c_a_l_l_e_r__i_d: Optional[Any] = None, start_time: Optional[Any] = None, end_time: Optional[Any] = None, limit: Optional[Any] = None, offset: Optional[Any] = None, sort_by: Optional[Any] = None, order: Optional[Any] = None, site_hierarchy: Optional[Any] = None, site_hierarchy_id: Optional[Any] = None, site_type: Optional[Any] = None, id: Optional[Any] = None, view: Optional[Any] = None, attribute: Optional[Any] = None) -> Dict[str, Any]:
        """Read list of site health summaries.

        Get a paginated list of site health summaries. Use the available query parameters to identify a subset of sites you want health summaries for.
This API provides the latest health data from a given `endTime`
If data is not ready for the provided endTime, the request will fail, and the error message will indicate the recommended endTime to use to retrieve a complete data set.
This behavior may occur if the provided endTime=currentTime, since we are not a real time system.
When `endTime` is not provided, the API returns the latest data.
This API also provides issue data. The `startTime` query param can be used to specify the beginning point of time range to retrieve the active issue counts in. When this param is not provided, the default `startTime` will be 24 hours before endTime.
Valid values for `sortBy` param in this API are limited to the attributes provided in the `site` view.
Default sortBy is 'siteHierarchy' in order 'asc' (ascending). For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-siteHealthSummaries-1.0.3-resolved.yaml


        Args:
            x__c_a_l_l_e_r__i_d (Any): Caller ID is used to trace the origin of API calls and their associated queries executed on the database. It's an optional header parameter that can be added to an API request.

            start_time (Any): Start time from which API queries the data set related to the resource. It must be specified in UNIX epochtime in milliseconds. Value is inclusive.

If `startTime` is not provided, API will default to current time.

            end_time (Any): End time to which API queries the data set related to the resource. It must be specified in UNIX epochtime in milliseconds. Value is inclusive.

            limit (Any): Maximum number of records to return
            offset (Any): Specifies the starting point within all records returned by the API. It's one based offset. The starting value is 1.
            sort_by (Any): A field within the response to sort by.
            order (Any): The sort order of the field ascending or descending.
            site_hierarchy (Any): The full hierarchical breakdown of the site tree starting from Global site name and ending with the specific site name. The Root site is named "Global" (Ex. `Global/AreaName/BuildingName/FloorName`)

This field supports wildcard asterisk (`*`) character search support. E.g. `*/San*, */San, /San*`

Examples:

`?siteHierarchy=Global/AreaName/BuildingName/FloorName` (single siteHierarchy requested)

`?siteHierarchy=Global/AreaName/BuildingName/FloorName&siteHierarchy=Global/AreaName2/BuildingName2/FloorName2` (multiple siteHierarchies requested)

            site_hierarchy_id (Any): The full hierarchy breakdown of the site tree in id form starting from Global site UUID and ending with the specific site UUID. (Ex. `globalUuid/areaUuid/buildingUuid/floorUuid`)

This field supports wildcard asterisk (`*`) character search support. E.g. `*uuid*, *uuid, uuid*`

Examples:

`?siteHierarchyId=globalUuid/areaUuid/buildingUuid/floorUuid `(single siteHierarchyId requested)

`?siteHierarchyId=globalUuid/areaUuid/buildingUuid/floorUuid&siteHierarchyId=globalUuid/areaUuid2/buildingUuid2/floorUuid2` (multiple siteHierarchyIds requested)

            site_type (Any): The type of the site. A site can be an area, building, or floor.

Default when not provided will be `[floor,building,area]`

Examples:

`?siteType=area` (single siteType requested)

`?siteType=area&siteType=building&siteType=floor` (multiple siteTypes requested)

            id (Any): The list of entity Uuids. (Ex."6bef213c-19ca-4170-8375-b694e251101c")
Examples: id=6bef213c-19ca-4170-8375-b694e251101c (single entity uuid requested)
id=6bef213c-19ca-4170-8375-b694e251101c&id=32219612-819e-4b5e-a96b-cf22aca13dd9&id=2541e9a7-b80d-4955-8aa2-79b233318ba0 (multiple entity uuid with '&' separator)

            view (Any): The specific summary view being requested. This is an optional parameter which can be passed to get one or more of the specific health data summaries associated with sites.

### Response data proviced by each view:  

1. **site**
[id, siteHierarchy, siteHierarchyId, siteType, latitude, longitude]  

2. **network**
[id, networkDeviceCount, networkDeviceGoodHealthCount,wirelessDeviceCount, wirelessDeviceGoodHealthCount, accessDeviceCount, accessDeviceGoodHealthCount, coreDeviceCount, coreDeviceGoodHealthCount, distributionDeviceCount, distributionDeviceGoodHealthCount, routerDeviceCount, routerDeviceGoodHealthCount, apDeviceCount, apDeviceGoodHealthCount, wlcDeviceCount, wlcDeviceGoodHealthCount, switchDeviceCount, switchDeviceGoodHealthCount, networkDeviceGoodHealthPercentage, accessDeviceGoodHealthPercentage, coreDeviceGoodHealthPercentage, distributionDeviceGoodHealthPercentage, routerDeviceGoodHealthPercentage, apDeviceGoodHealthPercentage, wlcDeviceGoodHealthPercentage, switchDeviceGoodHealthPercentage, wirelessDeviceGoodHealthPercentage]  

3. **client**
[id, clientCount, clientGoodHealthCount, wiredClientCount, wirelessClientCount, wiredClientGoodHealthCount, wirelessClientGoodHealthCount, clientGoodHealthPercentage, wiredClientGoodHealthPercentage, wirelessClientGoodHealthPercentage, clientDataUsage]  

4. **issue**
[id, p1IssueCount, p2IssueCount, p3IssueCount, p4IssueCount, issueCount]  

When this query parameter is not added the default summaries are:  

**[site,client,network,issue]**

Examples:

view=client (single view requested)

view=client&view=network&view=issue (multiple views requested)

            attribute (Any): Supported Attributes:

[id, siteHierarchy, siteHierarchyId, siteType, latitude, longitude, networkDeviceCount, networkDeviceGoodHealthCount,wirelessDeviceCount, wirelessDeviceGoodHealthCount, accessDeviceCount, accessDeviceGoodHealthCount, coreDeviceCount, coreDeviceGoodHealthCount, distributionDeviceCount, distributionDeviceGoodHealthCount, routerDeviceCount, routerDeviceGoodHealthCount, apDeviceCount, apDeviceGoodHealthCount, wlcDeviceCount, wlcDeviceGoodHealthCount, switchDeviceCount, switchDeviceGoodHealthCount, networkDeviceGoodHealthPercentage, accessDeviceGoodHealthPercentage, coreDeviceGoodHealthPercentage, distributionDeviceGoodHealthPercentage, routerDeviceGoodHealthPercentage, apDeviceGoodHealthPercentage, wlcDeviceGoodHealthPercentage, switchDeviceGoodHealthPercentage, wirelessDeviceGoodHealthPercentage, clientCount, clientGoodHealthCount, wiredClientCount, wirelessClientCount, wiredClientGoodHealthCount, wirelessClientGoodHealthCount, clientGoodHealthPercentage, wiredClientGoodHealthPercentage, wirelessClientGoodHealthPercentage, clientDataUsage, p1IssueCount, p2IssueCount, p3IssueCount, p4IssueCount, issueCount]

If length of attribute list is too long, please use 'view' param instead.

Examples:

attribute=siteHierarchy (single attribute requested)

attribute=siteHierarchy&attribute=clientCount (multiple attributes requested)


        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/data/api/v1/siteHealthSummaries'
        params = {
            'startTime': start_time,
            'endTime': end_time,
            'limit': limit,
            'offset': offset,
            'sortBy': sort_by,
            'order': order,
            'siteHierarchy': site_hierarchy,
            'siteHierarchyId': site_hierarchy_id,
            'siteType': site_type,
            'id': id,
            'view': view,
            'attribute': attribute,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_onboarding_pnp_device(self, limit: Optional[Any] = None, offset: Optional[Any] = None, sort: Optional[Any] = None, sort_order: Optional[Any] = None, serial_number: Optional[Any] = None, state: Optional[Any] = None, onb_state: Optional[Any] = None, name: Optional[Any] = None, pid: Optional[Any] = None, source: Optional[Any] = None, workflow_id: Optional[Any] = None, workflow_name: Optional[Any] = None, smart_account_id: Optional[Any] = None, virtual_account_id: Optional[Any] = None, last_contact: Optional[Any] = None, mac_address: Optional[Any] = None, hostname: Optional[Any] = None, site_name: Optional[Any] = None) -> Dict[str, Any]:
        """Get Device list

        Returns list of devices from Plug & Play based on filter criteria. Returns 50 devices by default. This endpoint supports Pagination and Sorting.

        Args:
            limit (Any): Limits number of results
            offset (Any): Index of first result
            sort (Any): Comma seperated list of fields to sort on
            sort_order (Any): Sort Order Ascending (asc) or Descending (des)
            serial_number (Any): Device Serial Number
            state (Any): Device State
            onb_state (Any): Device Onboarding State
            name (Any): Device Name
            pid (Any): Device ProductId
            source (Any): Device Source
            workflow_id (Any): Device Workflow Id
            workflow_name (Any): Device Workflow Name
            smart_account_id (Any): Device Smart Account
            virtual_account_id (Any): Device Virtual Account
            last_contact (Any): Device Has Contacted lastContact > 0
            mac_address (Any): Device Mac Address
            hostname (Any): Device Hostname
            site_name (Any): Device Site Name

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/onboarding/pnp-device'
        params = {
            'limit': limit,
            'offset': offset,
            'sort': sort,
            'sortOrder': sort_order,
            'serialNumber': serial_number,
            'state': state,
            'onbState': onb_state,
            'name': name,
            'pid': pid,
            'source': source,
            'workflowId': workflow_id,
            'workflowName': workflow_name,
            'smartAccountId': smart_account_id,
            'virtualAccountId': virtual_account_id,
            'lastContact': last_contact,
            'macAddress': mac_address,
            'hostname': hostname,
            'siteName': site_name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_onboarding_pnp_device(self, content__type: Any) -> Dict[str, Any]:
        """Add Device

        Adds a device to the PnP database.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/onboarding/pnp-device'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def post_dna_data_api_v1_clients_query(self, content__type: Any, x__c_a_l_l_e_r__i_d: Optional[Any] = None) -> Dict[str, Any]:
        """Retrieves the list of clients by applying complex filters while also supporting aggregate attributes.

        Retrieves the list of clients by applying complex filters while also supporting aggregate attributes. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-clients1-1.0.0-resolved.yaml

        Args:
            content__type (Any): Request body content type
            x__c_a_l_l_e_r__i_d (Any): Caller ID is used to trace the origin of API calls and their associated queries executed on the database. It's an optional header parameter that can be added to an API request.


        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        if x__c_a_l_l_e_r__i_d is not None:
            request_headers['X-CALLER-ID'] = str(x__c_a_l_l_e_r__i_d)
        url = self.base_url + '/dna/data/api/v1/clients/query'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_task(self, start_time: Optional[Any] = None, end_time: Optional[Any] = None, data: Optional[Any] = None, error_code: Optional[Any] = None, service_type: Optional[Any] = None, username: Optional[Any] = None, progress: Optional[Any] = None, is_error: Optional[Any] = None, failure_reason: Optional[Any] = None, parent_id: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None, sort_by: Optional[Any] = None, order: Optional[Any] = None) -> Dict[str, Any]:
        """Get tasks

        Returns task(s) based on filter criteria

        Args:
            start_time (Any): This is the epoch start time from which tasks need to be fetched
            end_time (Any): This is the epoch end time upto which audit records need to be fetched
            data (Any): Fetch tasks that contains this data
            error_code (Any): Fetch tasks that have this error code
            service_type (Any): Fetch tasks with this service type
            username (Any): Fetch tasks with this username
            progress (Any): Fetch tasks that contains this progress
            is_error (Any): Fetch tasks ended as success or failure. Valid values: true, false
            failure_reason (Any): Fetch tasks that contains this failure reason
            parent_id (Any): Fetch tasks that have this parent Id
            offset (Any): offset
            limit (Any): limit
            sort_by (Any): Sort results by this field
            order (Any): Sort order - asc or dsc

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/task'
        params = {
            'startTime': start_time,
            'endTime': end_time,
            'data': data,
            'errorCode': error_code,
            'serviceType': service_type,
            'username': username,
            'progress': progress,
            'isError': is_error,
            'failureReason': failure_reason,
            'parentId': parent_id,
            'offset': offset,
            'limit': limit,
            'sortBy': sort_by,
            'order': order,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_device_module(self, device_id: Any, limit: Optional[Any] = None, offset: Optional[Any] = None, name_list: Optional[Any] = None, vendor_equipment_type_list: Optional[Any] = None, part_number_list: Optional[Any] = None, operational_state_code_list: Optional[Any] = None) -> Dict[str, Any]:
        """Get Modules

        Returns modules by specified device id

        Args:
            device_id (Any): deviceId
            limit (Any): limit
            offset (Any): offset
            name_list (Any): nameList
            vendor_equipment_type_list (Any): vendorEquipmentTypeList
            part_number_list (Any): partNumberList
            operational_state_code_list (Any): operationalStateCodeList

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device/module'
        params = {
            'deviceId': device_id,
            'limit': limit,
            'offset': offset,
            'nameList': name_list,
            'vendorEquipmentTypeList': vendor_equipment_type_list,
            'partNumberList': part_number_list,
            'operationalStateCodeList': operational_state_code_list,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_images_image_id_site_wise_product_names_count(self, image_id: Any, product_name: Optional[Any] = None, product_id: Optional[Any] = None, recommended: Optional[Any] = None, assigned: Optional[Any] = None) -> Dict[str, Any]:
        """Retrieves the count of assigned network device products

        Returns count of assigned network device product for a given image identifier. Refer `/dna/intent/api/v1/images` API for obtaining `imageId`

        Args:
            image_id (Any): Software image identifier. Refer `/dna/intent/api/v/images` API for obtaining `imageId`
            product_name (Any): Filter with network device product name. Supports partial case-insensitive search. A minimum of 3 characters are required for search.
            product_id (Any): Filter with product ID (PID)
            recommended (Any): Filter with recommended source. If `CISCO` then the network device product assigned was recommended by Cisco and `USER` then the user has manually assigned. Available values : CISCO, USER
            assigned (Any): Filter with the assigned/unassigned, `ASSIGNED` option will filter network device products that are associated with the given image. The `NOT_ASSIGNED` option will filter network device products that have not yet been associated with the given image but apply to it. Available values: ASSIGNED, NOT_ASSIGNED

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/images/{image_id}/siteWiseProductNames/count'
        url = url.format(image_id=image_id)
        params = {
            'productName': product_name,
            'productId': product_id,
            'recommended': recommended,
            'assigned': assigned,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_event_subscription_details_rest(self, name: Optional[Any] = None, instance_id: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None, sort_by: Optional[Any] = None, order: Optional[Any] = None) -> Dict[str, Any]:
        """Get Rest/Webhook Subscription Details

        Gets the list of subscription details for specified connectorType

        Args:
            name (Any): Name of the specific configuration
            instance_id (Any): Instance Id of the specific configuration
            offset (Any): The number of Rest/Webhook Subscription detail's to offset in the resultset whose default value 0
            limit (Any): The number of Rest/Webhook Subscription detail's to limit in the resultset whose default value 10
            sort_by (Any): SortBy field name
            order (Any): order(asc/desc)

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/event/subscription-details/rest'
        params = {
            'name': name,
            'instanceId': instance_id,
            'offset': offset,
            'limit': limit,
            'sortBy': sort_by,
            'order': order,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_onboarding_pnp_device_history(self, serial_number: Any, sort: Optional[Any] = None, sort_order: Optional[Any] = None) -> Dict[str, Any]:
        """Get Device History

        Returns history for a specific device. Serial number is a required parameter

        Args:
            serial_number (Any): Device Serial Number
            sort (Any): Comma seperated list of fields to sort on
            sort_order (Any): Sort Order Ascending (asc) or Descending (des)

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/onboarding/pnp-device/history'
        params = {
            'serialNumber': serial_number,
            'sort': sort,
            'sortOrder': sort_order,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_app_policy_queuing_profile_count(self) -> Dict[str, Any]:
        """Get Application Policy Queuing Profile Count

        Get the number of all existing  application policy queuing profile

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/app-policy-queuing-profile-count'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_data_api_v1_network_devices_count(self, start_time: Optional[Any] = None, end_time: Optional[Any] = None, id: Optional[Any] = None, site_hierarchy: Optional[Any] = None, site_hierarchy_id: Optional[Any] = None, site_id: Optional[Any] = None, management_ip_address: Optional[Any] = None, mac_address: Optional[Any] = None, family: Optional[Any] = None, type: Optional[Any] = None, role: Optional[Any] = None, serial_number: Optional[Any] = None, maintenance_mode: Optional[Any] = None, software_version: Optional[Any] = None, health_score: Optional[Any] = None, view: Optional[Any] = None, attribute: Optional[Any] = None) -> Dict[str, Any]:
        """Gets the total Network device counts based on the provided query parameters.

        Gets the total Network device counts. When there is no start and end time specified returns the latest interfaces total count. For detailed information about the usage of the API, please refer to the Open API specification document - https://github.com/cisco-en-programmability/catalyst-center-api-specs/blob/main/Assurance/CE_Cat_Center_Org-AssuranceNetworkDevices-1.0.2-resolved.yaml

        Args:
            start_time (Any): Start time from which API queries the data set related to the resource. It must be specified in UNIX epochtime in milliseconds. Value is inclusive.

If `startTime` is not provided, API will default to current time.

            end_time (Any): End time to which API queries the data set related to the resource. It must be specified in UNIX epochtime in milliseconds. Value is inclusive.

            id (Any): The list of entity Uuids. (Ex."6bef213c-19ca-4170-8375-b694e251101c")
Examples: id=6bef213c-19ca-4170-8375-b694e251101c (single entity uuid requested)
id=6bef213c-19ca-4170-8375-b694e251101c&id=32219612-819e-4b5e-a96b-cf22aca13dd9&id=2541e9a7-b80d-4955-8aa2-79b233318ba0 (multiple entity uuid with '&' separator)

            site_hierarchy (Any): The full hierarchical breakdown of the site tree starting from Global site name and ending with the specific site name. The Root site is named "Global" (Ex. `Global/AreaName/BuildingName/FloorName`)

This field supports wildcard asterisk (*) character search support. E.g. */San*, */San, /San*

Examples:

`?siteHierarchy=Global/AreaName/BuildingName/FloorName` (single siteHierarchy requested)

`?siteHierarchy=Global/AreaName/BuildingName/FloorName&siteHierarchy=Global/AreaName2/BuildingName2/FloorName2` (multiple siteHierarchies requested)

            site_hierarchy_id (Any): The full hierarchy breakdown of the site tree in id form starting from Global site UUID and ending with the specific site UUID. (Ex. `globalUuid/areaUuid/buildingUuid/floorUuid`)

This field supports wildcard asterisk (*) character search support. E.g. `*uuid*, *uuid, uuid*

Examples:

`?siteHierarchyId=globalUuid/areaUuid/buildingUuid/floorUuid `(single siteHierarchyId requested)

`?siteHierarchyId=globalUuid/areaUuid/buildingUuid/floorUuid&siteHierarchyId=globalUuid/areaUuid2/buildingUuid2/floorUuid2` (multiple siteHierarchyIds requested)

            site_id (Any): The UUID of the site. (Ex. `flooruuid`)

This field supports wildcard asterisk (*) character search support. E.g.*flooruuid*, *flooruuid, flooruuid*

Examples:

`?siteId=id1` (single id requested)

`?siteId=id1&siteId=id2&siteId=id3` (multiple ids requested)

            management_ip_address (Any): The list of entity management IP Address. It can be either Ipv4 or Ipv6 address or combination of both(Ex. "121.1.1.10")

This field supports wildcard (`*`) character-based search.  Ex: `*1.1*` or `1.1*` or `*1.1`

Examples:
managementIpAddresses=121.1.1.10
managementIpAddresses=121.1.1.10&managementIpAddresses=172.20.1.10&managementIpAddresses=200:10&=managementIpAddresses172.20.3.4 (multiple entity IP Address with & separator)

            mac_address (Any): The macAddress of the network device or client
This field supports wildcard (`*`) character-based search. 
Ex: `*AB:AB:AB*` or `AB:AB:AB*` or `*AB:AB:AB`
Examples:

`macAddress=AB:AB:AB:CD:CD:CD` (single macAddress requested)

`macAddress=AB:AB:AB:CD:CD:DC&macAddress=AB:AB:AB:CD:CD:FE` (multiple macAddress requested)

            family (Any): The list of network device family names Examples:family=Switches and Hubs (single network device family name )family=Switches and Hubs&family=Router&family=Wireless Controller (multiple Network device family names with & separator). This field is not case sensitive.
            type (Any): The list of network device type This field supports wildcard (`*`) character-based search. Ex: `*9407R*` or `*9407R` or `9407R*`Examples:type=SwitchesCisco Catalyst 9407R Switch (single network device types )type=Cisco Catalyst 38xx stack-able ethernet switch&type=Cisco 3945 Integrated Services Router G2 (multiple Network device types with & separator)
            role (Any): The list of network device role. Examples:role=CORE, role=CORE&role=ACCESS&role=ROUTER (multiple Network device roles with & separator). This field is not case sensitive.
            serial_number (Any): The list of network device serial numbers. This field supports wildcard (`*`) character-based search.  Ex: `*MS1SV*` or `MS1SV*` or `*MS1SV`
Examples:
serialNumber=9FUFMS1SVAX serialNumber=9FUFMS1SVAX&FCW2333Q0BY&FJC240617JX(multiple Network device serial number with & separator)

            maintenance_mode (Any): The device maintenanceMode status true or false
            software_version (Any): The list of network device software version This field supports wildcard (`*`) character-based search. Ex: `*17.8*` or `*17.8` or `17.8*`
Examples:
softwareVersion=2.3.4.0 (single network device software version )
softwareVersion=17.9.3.23&softwareVersion=17.7.1.2&softwareVersion=*.17.7 (multiple Network device software versions with & separator)

            health_score (Any): The list of entity health score categories Examples:healthScore=good,healthScore=good&healthScore=fair (multiple entity healthscore values with & separator). This field is not case sensitive.
            view (Any): The List of Network Device model views. Please refer to ```NetworkDeviceView``` for the supported list
            attribute (Any): The List of Network Device model attributes. This is helps to specify the interested fields in the request.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/data/api/v1/networkDevices/count'
        params = {
            'startTime': start_time,
            'endTime': end_time,
            'id': id,
            'siteHierarchy': site_hierarchy,
            'siteHierarchyId': site_hierarchy_id,
            'siteId': site_id,
            'managementIpAddress': management_ip_address,
            'macAddress': mac_address,
            'family': family,
            'type': type,
            'role': role,
            'serialNumber': serial_number,
            'maintenanceMode': maintenance_mode,
            'softwareVersion': software_version,
            'healthScore': health_score,
            'view': view,
            'attribute': attribute,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_template_programmer_template_version(self, content__type: Any) -> Dict[str, Any]:
        """Version Template

        API to version the current contents of the template.

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/template-programmer/template/version'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_task_task_id_tree(self, task_id: Any) -> Dict[str, Any]:
        """Get task tree

        Returns a task with its children tasks by based on their id

        Args:
            task_id (Any): UUID of the Task

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/task/{task_id}/tree'
        url = url.format(task_id=task_id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_discovery_id_network_device(self, id: Any, task_id: Optional[Any] = None) -> Dict[str, Any]:
        """Get Discovered network devices by discovery Id

        Returns the network devices discovered for the given Discovery ID. Discovery ID can be obtained using the "Get Discoveries by range" API.

        Args:
            id (Any): Discovery ID
            task_id (Any): taskId

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/discovery/{id}/network-device'
        url = url.format(id=id)
        params = {
            'taskId': task_id,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_compliance(self, content__type: Any) -> Dict[str, Any]:
        """Run Compliance

        Run compliance check for device(s).

        Args:
            content__type (Any): Request body content type

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/compliance/'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_event_api_status_execution_id(self, execution_id: Any) -> Dict[str, Any]:
        """Get Status API for Events

        Get the Status of events API calls with provided executionId as mandatory path parameter

        Args:
            execution_id (Any): Execution ID

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/event/api-status/{execution_id}'
        url = url.format(execution_id=execution_id)
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_maps_export_site_hierarchy_uuid(self, content__type: Any, site_hierarchy_uuid: Any) -> Dict[str, Any]:
        """Export Map Archive

        Allows exporting a Map archive in an XML interchange format along with the associated images. 

        Args:
            content__type (Any): Request body content type
            site_hierarchy_uuid (Any): The site hierarchy element UUID to export, all child elements starting at this hierarchy element will be included. Limited to a hierarchy that contains 500 or fewer maps.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if content__type is not None:
            request_headers['Content-Type'] = str(content__type)
        url = self.base_url + '/dna/intent/api/v1/maps/export/{site_hierarchy_uuid}'
        url = url.format(site_hierarchy_uuid=site_hierarchy_uuid)
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_devices_assigned_to_site_count(self, site_id: Any) -> Dict[str, Any]:
        """Get site assigned network devices count

        Get all network devices count under the given site in the network hierarchy.

        Args:
            site_id (Any): Site Id. It must be area Id or building Id or floor Id.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/networkDevices/assignedToSite/count'
        params = {
            'siteId': site_id,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v2_network(self, site_id: Any) -> Dict[str, Any]:
        """Get Network V2

        API to get SNMP, NTP, Network AAA, Client and Endpoint AAA, and/or DNS center server settings.

        Args:
            site_id (Any): Site Id to get the network settings associated with the site.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v2/network'
        params = {
            'siteId': site_id,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network_device_autocomplete(self, vrf_name: Optional[Any] = None, management_ip_address: Optional[Any] = None, hostname: Optional[Any] = None, mac_address: Optional[Any] = None, family: Optional[Any] = None, collection_status: Optional[Any] = None, collection_interval: Optional[Any] = None, software_version: Optional[Any] = None, software_type: Optional[Any] = None, reachability_status: Optional[Any] = None, reachability_failure_reason: Optional[Any] = None, error_code: Optional[Any] = None, platform_id: Optional[Any] = None, series: Optional[Any] = None, type: Optional[Any] = None, serial_number: Optional[Any] = None, up_time: Optional[Any] = None, role: Optional[Any] = None, role_source: Optional[Any] = None, associated_wlc_ip: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None) -> Dict[str, Any]:
        """Get Device Values that match fully or partially an Attribute

        Returns the list of values of the first given required parameter. You can use the .* in any value to conduct a wildcard search.
For example, to get all the devices with the management IP address starting with 10.10. , issue the following request: GET /dna/inten/api/v1/network-device/autocomplete?managementIpAddress=10.10..*
It will return the device management IP addresses that match fully or partially the provided attribute. {[10.10.1.1, 10.10.20.2, …]}.

        Args:
            vrf_name (Any): vrfName
            management_ip_address (Any): managementIpAddress
            hostname (Any): hostname
            mac_address (Any): macAddress
            family (Any): family
            collection_status (Any): collectionStatus
            collection_interval (Any): collectionInterval
            software_version (Any): softwareVersion
            software_type (Any): softwareType
            reachability_status (Any): reachabilityStatus
            reachability_failure_reason (Any): reachabilityFailureReason
            error_code (Any): errorCode
            platform_id (Any): platformId
            series (Any): series
            type (Any): type
            serial_number (Any): serialNumber
            up_time (Any): upTime
            role (Any): role
            role_source (Any): roleSource
            associated_wlc_ip (Any): associatedWlcIp
            offset (Any): offset
            limit (Any): limit

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network-device/autocomplete'
        params = {
            'vrfName': vrf_name,
            'managementIpAddress': management_ip_address,
            'hostname': hostname,
            'macAddress': mac_address,
            'family': family,
            'collectionStatus': collection_status,
            'collectionInterval': collection_interval,
            'softwareVersion': software_version,
            'softwareType': software_type,
            'reachabilityStatus': reachability_status,
            'reachabilityFailureReason': reachability_failure_reason,
            'errorCode': error_code,
            'platformId': platform_id,
            'series': series,
            'type': type,
            'serialNumber': serial_number,
            'upTime': up_time,
            'role': role,
            'roleSource': role_source,
            'associatedWlcIp': associated_wlc_ip,
            'offset': offset,
            'limit': limit,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_sensor(self) -> Dict[str, Any]:
        """Create sensor test template

        Intent API to create a SENSOR test template with a new SSID, existing SSID, or both new and existing SSID

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sensor'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_sensor(self, template_name: Any) -> Dict[str, Any]:
        """Delete sensor test

        Intent API to delete an existing SENSOR test template

        Args:
            template_name (Any): 

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sensor'
        params = {
            'templateName': template_name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_sensor(self, site_id: Optional[Any] = None) -> Dict[str, Any]:
        """Sensors

        Intent API to get a list of SENSOR devices

        Args:
            site_id (Any): 

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sensor'
        params = {
            'siteId': site_id,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_business_sda_device(self, device_management_ip_address: Any) -> Dict[str, Any]:
        """Get device info from SDA Fabric

        Get device info from SDA Fabric

        Args:
            device_management_ip_address (Any): deviceManagementIpAddress

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/device'
        params = {
            'deviceManagementIpAddress': device_management_ip_address,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_business_sda_hostonboarding_access_point(self, device_management_ip_address: Any, interface_name: Any) -> Dict[str, Any]:
        """Delete Port assignment for access point in SDA Fabric

        Delete Port assignment for access point in SDA Fabric

        Args:
            device_management_ip_address (Any): deviceManagementIpAddress
            interface_name (Any): interfaceName

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/hostonboarding/access-point'
        params = {
            'deviceManagementIpAddress': device_management_ip_address,
            'interfaceName': interface_name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_business_sda_hostonboarding_access_point(self, device_management_ip_address: Any, interface_name: Any) -> Dict[str, Any]:
        """Get Port assignment for access point in SDA Fabric

        Get Port assignment for access point in SDA Fabric

        Args:
            device_management_ip_address (Any): deviceManagementIpAddress
            interface_name (Any): interfaceName

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/hostonboarding/access-point'
        params = {
            'deviceManagementIpAddress': device_management_ip_address,
            'interfaceName': interface_name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_business_sda_hostonboarding_access_point(self) -> Dict[str, Any]:
        """Add Port assignment for access point in SDA Fabric

        Add Port assignment for access point in SDA Fabric

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/hostonboarding/access-point'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_business_sda_wireless_controller(self, device_i_p_address: Any, persistbapioutput: Optional[Any] = None) -> Dict[str, Any]:
        """Remove WLC from Fabric Domain

        Remove WLC from Fabric Domain

        Args:
            device_i_p_address (Any): Device Management IP Address
            persistbapioutput (Any): Enable this parameter to execute the API and return a response asynchronously.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if persistbapioutput is not None:
            request_headers['__persistbapioutput'] = str(persistbapioutput)
        url = self.base_url + '/dna/intent/api/v1/business/sda/wireless-controller'
        params = {
            'deviceIPAddress': device_i_p_address,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_business_sda_wireless_controller(self, persistbapioutput: Optional[Any] = None) -> Dict[str, Any]:
        """Add WLC to Fabric Domain

        Add WLC to Fabric Domain

        Args:
            persistbapioutput (Any): Enable this parameter to execute the API and return a response asynchronously.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if persistbapioutput is not None:
            request_headers['__persistbapioutput'] = str(persistbapioutput)
        url = self.base_url + '/dna/intent/api/v1/business/sda/wireless-controller'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_business_sda_virtualnetwork_ippool(self) -> Dict[str, Any]:
        """Add IP Pool in SDA Virtual Network

        Add IP Pool in SDA Virtual Network

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/virtualnetwork/ippool'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_business_sda_virtualnetwork_ippool(self, site_name_hierarchy: Any, virtual_network_name: Any, ip_pool_name: Any) -> Dict[str, Any]:
        """Delete IP Pool from SDA Virtual Network

        Delete IP Pool from SDA Virtual Network

        Args:
            site_name_hierarchy (Any): siteNameHierarchy
            virtual_network_name (Any): virtualNetworkName
            ip_pool_name (Any): ipPoolName

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/virtualnetwork/ippool'
        params = {
            'siteNameHierarchy': site_name_hierarchy,
            'virtualNetworkName': virtual_network_name,
            'ipPoolName': ip_pool_name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_business_sda_virtualnetwork_ippool(self, site_name_hierarchy: Any, virtual_network_name: Any, ip_pool_name: Any) -> Dict[str, Any]:
        """Get IP Pool from SDA Virtual Network

        Get IP Pool from SDA Virtual Network

        Args:
            site_name_hierarchy (Any): siteNameHierarchy
            virtual_network_name (Any): virtualNetworkName
            ip_pool_name (Any): ipPoolName. Note: Use vlanName as a value for this parameter if same ip pool is assigned to multiple virtual networks (e.g.. ipPoolName=vlan1021)

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/virtualnetwork/ippool'
        params = {
            'siteNameHierarchy': site_name_hierarchy,
            'virtualNetworkName': virtual_network_name,
            'ipPoolName': ip_pool_name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_business_sda_edge_device(self, device_management_ip_address: Any) -> Dict[str, Any]:
        """Delete edge device from SDA Fabric

        Delete edge device from SDA Fabric.

        Args:
            device_management_ip_address (Any): deviceManagementIpAddress

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/edge-device'
        params = {
            'deviceManagementIpAddress': device_management_ip_address,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_business_sda_edge_device(self, device_management_ip_address: Any) -> Dict[str, Any]:
        """Get edge device from SDA Fabric

        Get edge device from SDA Fabric

        Args:
            device_management_ip_address (Any): deviceManagementIpAddress

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/edge-device'
        params = {
            'deviceManagementIpAddress': device_management_ip_address,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_business_sda_edge_device(self) -> Dict[str, Any]:
        """Add edge device in SDA Fabric

        Add edge device in SDA Fabric

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/edge-device'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_business_sda_multicast(self, site_name_hierarchy: Any) -> Dict[str, Any]:
        """Delete multicast from SDA fabric

        Delete multicast from SDA fabric

        Args:
            site_name_hierarchy (Any): siteNameHierarchy

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/multicast'
        params = {
            'siteNameHierarchy': site_name_hierarchy,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_business_sda_multicast(self, site_name_hierarchy: Any) -> Dict[str, Any]:
        """Get multicast details from SDA fabric

        Get multicast details from SDA fabric

        Args:
            site_name_hierarchy (Any): fabric site name hierarchy

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/multicast'
        params = {
            'siteNameHierarchy': site_name_hierarchy,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_business_sda_multicast(self) -> Dict[str, Any]:
        """Add multicast in SDA fabric

        Add multicast in SDA fabric

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/multicast'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_applications(self) -> Dict[str, Any]:
        """Edit Application

        Edit the attributes of an existing application

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/applications'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_applications(self, offset: Optional[Any] = None, limit: Optional[Any] = None, name: Optional[Any] = None) -> Dict[str, Any]:
        """Get Applications

        Get applications by offset/limit or by name

        Args:
            offset (Any): The offset of the first application to be returned
            limit (Any): The maximum number of applications to be returned
            name (Any): Application's name

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/applications'
        params = {
            'offset': offset,
            'limit': limit,
            'name': name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_applications(self, id: Any) -> Dict[str, Any]:
        """Delete Application

        Delete existing application by its id

        Args:
            id (Any): Application's Id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/applications'
        params = {
            'id': id,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_applications(self) -> Dict[str, Any]:
        """Create Application

        Create new Custom application

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/applications'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_wireless_rf_profile(self, rf_profile_name: Optional[Any] = None) -> Dict[str, Any]:
        """Retrieve RF profiles

        Retrieve all RF profiles

        Args:
            rf_profile_name (Any): RF Profile Name

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/wireless/rf-profile'
        params = {
            'rf-profile-name': rf_profile_name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_wireless_rf_profile(self) -> Dict[str, Any]:
        """Create or Update RF profile

        Create or Update RF profile

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/wireless/rf-profile'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_network(self, site_id: Optional[Any] = None) -> Dict[str, Any]:
        """Get Network

        API to get  DHCP and DNS center server details.

        Args:
            site_id (Any): Site id to get the network settings associated with the site.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/network'
        params = {
            'siteId': site_id,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_reserve_ip_subpool(self, site_id: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None, ignore_inherited_groups: Optional[Any] = None, pool_usage: Optional[Any] = None, group_name: Optional[Any] = None) -> Dict[str, Any]:
        """Get Reserve IP Subpool

        API to get the ip subpool info.

        Args:
            site_id (Any): site id of site from which to retrieve associated reserve pools. Either siteId (per site queries) or ignoreInheritedGroups must be used. They can also be used together. 
            offset (Any): offset/starting row. Indexed from 1.
            limit (Any): Number of reserve pools to be retrieved. Default is 25 if not specified. Maximum allowed limit is 500.
            ignore_inherited_groups (Any): Ignores pools inherited from parent site. Either siteId or ignoreInheritedGroups must be passed. They can also be used together.
            pool_usage (Any): Can take values empty, partially-full or empty-partially-full
            group_name (Any): Name of the group

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/reserve-ip-subpool'
        params = {
            'siteId': site_id,
            'offset': offset,
            'limit': limit,
            'ignoreInheritedGroups': ignore_inherited_groups,
            'poolUsage': pool_usage,
            'groupName': group_name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_business_sda_transit_peer_network(self, transit_peer_network_name: Any) -> Dict[str, Any]:
        """Get Transit Peer Network Info

        Get Transit Peer Network Info from SD-Access

        Args:
            transit_peer_network_name (Any): Transit or Peer Network Name

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/transit-peer-network'
        params = {
            'transitPeerNetworkName': transit_peer_network_name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_business_sda_transit_peer_network(self) -> Dict[str, Any]:
        """Add Transit Peer Network

        Add Transit Peer Network in SD-Access

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/transit-peer-network'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_business_sda_transit_peer_network(self, transit_peer_network_name: Any) -> Dict[str, Any]:
        """Delete Transit Peer Network

        Delete Transit Peer Network from SD-Access

        Args:
            transit_peer_network_name (Any): Transit Peer Network Name

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/transit-peer-network'
        params = {
            'transitPeerNetworkName': transit_peer_network_name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_client_proximity(self, username: Any, number_days: Optional[Any] = None, time_resolution: Optional[Any] = None) -> Dict[str, Any]:
        """Client Proximity

        This intent API will provide client proximity information for a specific wireless user. Proximity is defined as presence on the same floor at the same time as the specified wireless user. The Proximity workflow requires the subscription to the following event (via the Event Notification workflow) prior to making this API call: NETWORK-CLIENTS-3-506 - Client Proximity Report.

        Args:
            username (Any): Wireless client username for which proximity information is required
            number_days (Any): Number of days to track proximity until current date. Defaults and maximum up to 14 days.
            time_resolution (Any): Time interval (in minutes) to measure proximity. Defaults to 15 minutes with a minimum 5 minutes.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/client-proximity'
        params = {
            'username': username,
            'number_days': number_days,
            'time_resolution': time_resolution,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_device_credential_id(self, id: Any) -> Dict[str, Any]:
        """Delete Device Credential

        Delete device credential. This API has been deprecated and will not be available in a Cisco DNA Center release after August 1st 2024 23:59:59 GMT. Please refer new Intent API : Delete Global Credentials V2

        Args:
            id (Any): global credential id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/device-credential/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_sp_profile_sp_profile_name(self, sp_profile_name: Any) -> Dict[str, Any]:
        """Delete SP Profile

        API to delete Service Provider Profile (QoS).

        Args:
            sp_profile_name (Any): sp profile name

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sp-profile/{sp_profile_name}'
        url = url.format(sp_profile_name=sp_profile_name)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_application_health(self, site_id: Optional[Any] = None, device_id: Optional[Any] = None, mac_address: Optional[Any] = None, start_time: Optional[Any] = None, end_time: Optional[Any] = None, application_health: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None, application_name: Optional[Any] = None) -> Dict[str, Any]:
        """Applications

        Intent API to get a list of applications for a specific site, a device, or a client device's MAC address. For a combination of a specific application with site and/or device the API gets list of issues/devices/endpoints.

        Args:
            site_id (Any): Assurance site UUID value (Cannot be submitted together with deviceId and clientMac)
            device_id (Any): Assurance device UUID value (Cannot be submitted together with siteId and clientMac)
            mac_address (Any): Client device's MAC address (Cannot be submitted together with siteId and deviceId)
            start_time (Any): Starting epoch time in milliseconds of time window
            end_time (Any): Ending epoch time in milliseconds of time window
            application_health (Any): Application health category (POOR, FAIR, or GOOD.  Optionally use with siteId only)
            offset (Any): The offset of the first application in the returned data (optionally used with siteId only)
            limit (Any): The max number of application entries in returned data [1, 1000] (optionally used with siteId only)
            application_name (Any): The name of the application to get information on

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/application-health'
        params = {
            'siteId': site_id,
            'deviceId': device_id,
            'macAddress': mac_address,
            'startTime': start_time,
            'endTime': end_time,
            'applicationHealth': application_health,
            'offset': offset,
            'limit': limit,
            'applicationName': application_name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_application_policy_application_set(self) -> Dict[str, Any]:
        """Create Application Set

        Create new custom application-set/s

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/application-policy-application-set'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_application_policy_application_set(self, id: Any) -> Dict[str, Any]:
        """Delete Application Set

        Delete existing application-set by it's id

        Args:
            id (Any): 

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/application-policy-application-set'
        params = {
            'id': id,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_application_policy_application_set(self, offset: Optional[Any] = None, limit: Optional[Any] = None, name: Optional[Any] = None) -> Dict[str, Any]:
        """Get Application Sets

        Get appllication-sets by offset/limit or by name

        Args:
            offset (Any): 
            limit (Any): 
            name (Any): 

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/application-policy-application-set'
        params = {
            'offset': offset,
            'limit': limit,
            'name': name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_applications_count(self) -> Dict[str, Any]:
        """Get Applications Count

        Get the number of all existing applications

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/applications-count'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_global_pool_id(self, id: Any) -> Dict[str, Any]:
        """Delete Global IP Pool

        API to delete global IP pool.

        Args:
            id (Any): global pool id

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/global-pool/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_global_pool(self) -> Dict[str, Any]:
        """Update Global Pool

        API to update global pool

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/global-pool'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_global_pool(self, offset: Optional[Any] = None, limit: Optional[Any] = None) -> Dict[str, Any]:
        """Get Global Pool

        API to get the global pool.

        Args:
            offset (Any): Offset/starting row. Indexed from 1. Default value of 1.
            limit (Any): Number of Global Pools to be retrieved. Default is 25 if not specified.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/global-pool'
        params = {
            'offset': offset,
            'limit': limit,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_global_pool(self, persistbapioutput: Optional[Any] = None) -> Dict[str, Any]:
        """Create Global Pool

        API to create global pool.

        Args:
            persistbapioutput (Any): 	Persist bapi sync response

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if persistbapioutput is not None:
            request_headers['__persistbapioutput'] = str(persistbapioutput)
        url = self.base_url + '/dna/intent/api/v1/global-pool'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_business_ssid(self, persistbapioutput: Any) -> Dict[str, Any]:
        """Create and Provision SSID

        Creates SSID, updates the SSID to the corresponding site profiles and provision it to the devices matching the given sites

        Args:
            persistbapioutput (Any): Enable this parameter to execute the API and return a response asynchronously.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if persistbapioutput is not None:
            request_headers['__persistbapioutput'] = str(persistbapioutput)
        url = self.base_url + '/dna/intent/api/v1/business/ssid'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_wireless_rf_profile_rf_profile_name(self, rf_profile_name: Any) -> Dict[str, Any]:
        """Delete RF profiles

        Delete RF profile

        Args:
            rf_profile_name (Any): RF profile name to be deleted(required) *non-custom RF profile cannot be deleted

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/wireless/rf-profile/{rf_profile_name}'
        url = url.format(rf_profile_name=rf_profile_name)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_business_sda_virtual_network(self, virtual_network_name: Any, site_name_hierarchy: Any) -> Dict[str, Any]:
        """Get VN from SDA Fabric

        Get virtual network (VN) from SDA Fabric

        Args:
            virtual_network_name (Any): virtualNetworkName
            site_name_hierarchy (Any): siteNameHierarchy

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/virtual-network'
        params = {
            'virtualNetworkName': virtual_network_name,
            'siteNameHierarchy': site_name_hierarchy,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_business_sda_virtual_network(self) -> Dict[str, Any]:
        """Add VN in fabric

        Add virtual network (VN) in SDA Fabric	

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/virtual-network'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_business_sda_virtual_network(self, virtual_network_name: Any, site_name_hierarchy: Any) -> Dict[str, Any]:
        """Delete VN from SDA Fabric

        Delete virtual network (VN) from SDA Fabric	

        Args:
            virtual_network_name (Any): virtualNetworkName
            site_name_hierarchy (Any): siteNameHierarchy

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/virtual-network'
        params = {
            'virtualNetworkName': virtual_network_name,
            'siteNameHierarchy': site_name_hierarchy,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_business_sda_authentication_profile(self, site_name_hierarchy: Any) -> Dict[str, Any]:
        """Delete default authentication profile from SDA Fabric

        Delete default authentication profile in SDA Fabric

        Args:
            site_name_hierarchy (Any): siteNameHierarchy

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/authentication-profile'
        params = {
            'siteNameHierarchy': site_name_hierarchy,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_business_sda_authentication_profile(self) -> Dict[str, Any]:
        """Update default authentication profile in SDA Fabric

        Update default authentication profile in SDA Fabric

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/authentication-profile'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_business_sda_authentication_profile(self, site_name_hierarchy: Any, authenticate_template_name: Optional[Any] = None) -> Dict[str, Any]:
        """Get default authentication profile from SDA Fabric

        Get default authentication profile from SDA Fabric

        Args:
            site_name_hierarchy (Any): siteNameHierarchy
            authenticate_template_name (Any): authenticateTemplateName

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/authentication-profile'
        params = {
            'siteNameHierarchy': site_name_hierarchy,
            'authenticateTemplateName': authenticate_template_name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_business_sda_authentication_profile(self) -> Dict[str, Any]:
        """Add default authentication template in SDA Fabric

        Add default authentication template in SDA Fabric

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/authentication-profile'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_reserve_ip_subpool_site_id(self, site_id: Any) -> Dict[str, Any]:
        """Reserve IP Subpool

        API to reserve an ip subpool from the global pool

        Args:
            site_id (Any): Site id to reserve the ip sub pool.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/reserve-ip-subpool/{site_id}'
        url = url.format(site_id=site_id)
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_reserve_ip_subpool_site_id(self, site_id: Any, id: Any) -> Dict[str, Any]:
        """Update Reserve IP Subpool

        API to update ip subpool from the global pool

        Args:
            site_id (Any): Site id of site to update sub pool.
            id (Any): Id of subpool group

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/reserve-ip-subpool/{site_id}'
        url = url.format(site_id=site_id)
        params = {
            'id': id,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_wireless_psk_override(self) -> Dict[str, Any]:
        """PSK override

        Update/Override passphrase of SSID

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/wireless/psk-override'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_credential_to_site_site_id(self, persistbapioutput: Any, site_id: Any) -> Dict[str, Any]:
        """Assign Device Credential To Site

        Assign Device Credential to a site.

        Args:
            persistbapioutput (Any): Persist bapi sync response
            site_id (Any): site id to assign credential.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if persistbapioutput is not None:
            request_headers['__persistbapioutput'] = str(persistbapioutput)
        url = self.base_url + '/dna/intent/api/v1/credential-to-site/{site_id}'
        url = url.format(site_id=site_id)
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_business_sda_provision_device(self) -> Dict[str, Any]:
        """Re-Provision Wired Device

        Re-Provision Wired Device

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/provision-device'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_business_sda_provision_device(self) -> Dict[str, Any]:
        """Provision Wired Device

        Provision Wired Device

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/provision-device'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_business_sda_provision_device(self, device_management_ip_address: Any) -> Dict[str, Any]:
        """Delete provisioned Wired Device

        Delete provisioned Wired Device

        Args:
            device_management_ip_address (Any): Valid IP address of the device currently provisioned in a fabric site

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/provision-device'
        params = {
            'deviceManagementIpAddress': device_management_ip_address,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_business_sda_provision_device(self, device_management_ip_address: Any) -> Dict[str, Any]:
        """Get Provisioned Wired Device

        Get Provisioned Wired Device

        Args:
            device_management_ip_address (Any): deviceManagementIpAddress

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/provision-device'
        params = {
            'deviceManagementIpAddress': device_management_ip_address,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_device_credential(self) -> Dict[str, Any]:
        """Update Device Credentials

        API to update device credentials. This API has been deprecated and will not be available in a Cisco DNA Center release after August 1st 2024 23:59:59 GMT. Please refer new Intent API : Update Global Credentials V2

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/device-credential'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_device_credential(self, site_id: Optional[Any] = None) -> Dict[str, Any]:
        """Get Device Credential Details

        API to get device credential details. This API has been deprecated and will not be available in a Cisco DNA Center release after August 1st 2024 23:59:59 GMT. Please refer new Intent API : Get All Global Credentials V2

        Args:
            site_id (Any): Site id to retrieve the credential details associated with the site.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/device-credential'
        params = {
            'siteId': site_id,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_device_credential(self) -> Dict[str, Any]:
        """Create Device Credentials

        API to create device credentials. This API has been deprecated and will not be available in a Cisco DNA Center release after August 1st 2024 23:59:59 GMT. Please refer new Intent API : Create Global Credentials V2

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/device-credential'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_business_sda_fabric_site(self, site_name_hierarchy: Any) -> Dict[str, Any]:
        """Delete Site from SDA Fabric

        Delete Site from SDA Fabric

        Args:
            site_name_hierarchy (Any): Site Name Hierarchy

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/fabric-site'
        params = {
            'siteNameHierarchy': site_name_hierarchy,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_business_sda_fabric_site(self, site_name_hierarchy: Any) -> Dict[str, Any]:
        """Get Site from SDA Fabric

        Get Site info from SDA Fabric

        Args:
            site_name_hierarchy (Any): Site Name Hierarchy

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/fabric-site'
        params = {
            'siteNameHierarchy': site_name_hierarchy,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_business_sda_fabric_site(self) -> Dict[str, Any]:
        """Add Site in SDA Fabric

        Add Site in SDA Fabric

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/fabric-site'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_service_provider(self) -> Dict[str, Any]:
        """Update SP Profile

        API to update Service Provider Profile (QoS).

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/service-provider'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_service_provider(self) -> Dict[str, Any]:
        """Get Service provider Details

        API to get service provider details (QoS).

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/service-provider'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_service_provider(self) -> Dict[str, Any]:
        """Create SP Profile

        API to create Service Provider Profile(QOS).

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/service-provider'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_site(self, runsync: Any, persistbapioutput: Any, timeout: Optional[Any] = None) -> Dict[str, Any]:
        """Create Site

        Creates site with area/building/floor with specified hierarchy.

        Args:
            runsync (Any): Enable this parameter to execute the API and return a response synchronously
            persistbapioutput (Any): Persist bapi sync response
            timeout (Any): During synchronous execution, this defines the maximum time to wait for a response, before the API execution is terminated

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if runsync is not None:
            request_headers['__runsync'] = str(runsync)
        if persistbapioutput is not None:
            request_headers['__persistbapioutput'] = str(persistbapioutput)
        if timeout is not None:
            request_headers['__timeout'] = str(timeout)
        url = self.base_url + '/dna/intent/api/v1/site'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_site(self, name: Optional[Any] = None, site_id: Optional[Any] = None, type: Optional[Any] = None, offset: Optional[Any] = None, limit: Optional[Any] = None) -> Dict[str, Any]:
        """Get Site

        Get site(s) by site-name-hierarchy or siteId or type. List all sites if these parameters are not given as an input.

        Args:
            name (Any): Site name hierarchy (E.g Global/USA/CA)
            site_id (Any): Site Id
            type (Any): Site type (Ex: area, building, floor)
            offset (Any): Offset/starting index for pagination. Indexed from 1.
            limit (Any): Number of sites to be listed

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/site'
        params = {
            'name': name,
            'siteId': site_id,
            'type': type,
            'offset': offset,
            'limit': limit,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_network_site_id(self, site_id: Any, persistbapioutput: Optional[Any] = None) -> Dict[str, Any]:
        """Update Network

        API to update network settings for DHCP,  Syslog, SNMP, NTP, Network AAA, Client and EndPoint AAA, and/or DNS server settings.

        Args:
            site_id (Any): Site id to update the network settings which is associated with the site
            persistbapioutput (Any): Persist bapi sync response

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if persistbapioutput is not None:
            request_headers['__persistbapioutput'] = str(persistbapioutput)
        url = self.base_url + '/dna/intent/api/v1/network/{site_id}'
        url = url.format(site_id=site_id)
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_network_site_id(self, site_id: Any, persistbapioutput: Optional[Any] = None) -> Dict[str, Any]:
        """Create Network

        API to create a network for DHCP,  Syslog, SNMP, NTP, Network AAA, Client and EndPoint AAA, and/or DNS center server settings.

        Args:
            site_id (Any): Site id to which site details to associate with the network settings.
            persistbapioutput (Any): Persist bapi sync response

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if persistbapioutput is not None:
            request_headers['__persistbapioutput'] = str(persistbapioutput)
        url = self.base_url + '/dna/intent/api/v1/network/{site_id}'
        url = url.format(site_id=site_id)
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_business_sda_virtual_network_summary(self, site_name_hierarchy: Any) -> Dict[str, Any]:
        """Get Virtual Network Summary

        Get Virtual Network Summary

        Args:
            site_name_hierarchy (Any): Complete fabric siteNameHierarchy Path

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/virtual-network/summary'
        params = {
            'siteNameHierarchy': site_name_hierarchy,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_wireless_profile(self) -> Dict[str, Any]:
        """Create Wireless Profile

        Creates Wireless Network Profile on Cisco DNA Center and associates sites and SSIDs to it.	

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/wireless/profile'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_wireless_profile(self, profile_name: Optional[Any] = None) -> Dict[str, Any]:
        """Get Wireless Profile

        Gets either one or all the wireless network profiles if no name is provided for network-profile.	

        Args:
            profile_name (Any): Wireless Network Profile Name

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/wireless/profile'
        params = {
            'profileName': profile_name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_wireless_profile(self) -> Dict[str, Any]:
        """Update Wireless Profile

        Updates the wireless Network Profile with updated details provided. All sites to be present in the network profile should be provided. 

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/wireless/profile'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_reserve_ip_subpool_id(self, id: Any) -> Dict[str, Any]:
        """Release Reserve IP Subpool

        API to delete the reserved ip subpool

        Args:
            id (Any): Id of reserve ip subpool to be deleted.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/reserve-ip-subpool/{id}'
        url = url.format(id=id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_sensor_test_template(self) -> Dict[str, Any]:
        """Duplicate sensor test template

        Intent API to duplicate an existing SENSOR test template

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sensorTestTemplate'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_issue_enrichment_details(self, entity_type: Any, entity_value: Any, persistbapioutput: Optional[Any] = None) -> Dict[str, Any]:
        """Get Issue Enrichment Details

        Enriches a given network issue context (an issue id or end user’s Mac Address) with details about the issue(s), impacted hosts and suggested actions for remediation

        Args:
            entity_type (Any): Issue enrichment details can be fetched based on either Issue ID or Client MAC address. This parameter value must either be issue_id/mac_address
            entity_value (Any): Contains the actual value for the entity type that has been defined
            persistbapioutput (Any): 

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if entity_type is not None:
            request_headers['entity_type'] = str(entity_type)
        if entity_value is not None:
            request_headers['entity_value'] = str(entity_value)
        if persistbapioutput is not None:
            request_headers['__persistbapioutput'] = str(persistbapioutput)
        url = self.base_url + '/dna/intent/api/v1/issue-enrichment-details'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_wireless_provision(self, persistbapioutput: Any) -> Dict[str, Any]:
        """Provision update

        Updates wireless provisioning

        Args:
            persistbapioutput (Any): Enable this parameter to execute the API and return a response asynchronously.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if persistbapioutput is not None:
            request_headers['__persistbapioutput'] = str(persistbapioutput)
        url = self.base_url + '/dna/intent/api/v1/wireless/provision'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_wireless_provision(self, persistbapioutput: Any) -> Dict[str, Any]:
        """Provision

        Provision wireless device

        Args:
            persistbapioutput (Any): Enable this parameter to execute the API and return a response asynchronously.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if persistbapioutput is not None:
            request_headers['__persistbapioutput'] = str(persistbapioutput)
        url = self.base_url + '/dna/intent/api/v1/wireless/provision'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_assurance_get_sensor_test_results(self, site_id: Optional[Any] = None, start_time: Optional[Any] = None, end_time: Optional[Any] = None, test_failure_by: Optional[Any] = None) -> Dict[str, Any]:
        """Sensor Test Results

        Intent API to get SENSOR test result summary

        Args:
            site_id (Any): Assurance site UUID
            start_time (Any): The epoch time in milliseconds
            end_time (Any): The epoch time in milliseconds
            test_failure_by (Any): Obtain failure statistics group by "area", "building", or "floor" (case insensitive)

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/AssuranceGetSensorTestResults'
        params = {
            'siteId': site_id,
            'startTime': start_time,
            'endTime': end_time,
            'testFailureBy': test_failure_by,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_business_sda_device_role(self, device_management_ip_address: Any) -> Dict[str, Any]:
        """Get device role in SDA Fabric

        Get device role in SDA Fabric

        Args:
            device_management_ip_address (Any): Device Management IP Address

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/device/role'
        params = {
            'deviceManagementIpAddress': device_management_ip_address,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_enterprise_ssid(self) -> Dict[str, Any]:
        """Create Enterprise SSID

        Creates enterprise SSID	

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/enterprise-ssid'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_enterprise_ssid(self) -> Dict[str, Any]:
        """Update Enterprise SSID

        Update enterprise SSID	

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/enterprise-ssid'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_enterprise_ssid(self, ssid_name: Optional[Any] = None) -> Dict[str, Any]:
        """Get Enterprise SSID

        Get Enterprise SSID

        Args:
            ssid_name (Any): Enter the enterprise SSID name that needs to be retrieved. If not entered, all the enterprise SSIDs will be retrieved.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/enterprise-ssid'
        params = {
            'ssidName': ssid_name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_assign_device_to_site_site_id_device(self, runsync: Any, persistbapioutput: Any, site_id: Any, timeout: Optional[Any] = None) -> Dict[str, Any]:
        """Assign Devices To Site

        Assigns unassigned devices to a site. This API does not move assigned devices to other sites.

        Args:
            runsync (Any): Enable this parameter to execute the API and return a response synchronously
            persistbapioutput (Any): Persist bapi sync response
            site_id (Any): Site Id where device(s) needs to be assigned
            timeout (Any): During synchronous execution, this defines the maximum time to wait for a response, before the API execution is terminated

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if runsync is not None:
            request_headers['__runsync'] = str(runsync)
        if persistbapioutput is not None:
            request_headers['__persistbapioutput'] = str(persistbapioutput)
        if timeout is not None:
            request_headers['__timeout'] = str(timeout)
        url = self.base_url + '/dna/intent/api/v1/assign-device-to-site/{site_id}/device'
        url = url.format(site_id=site_id)
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_business_sda_border_device(self, device_management_ip_address: Any) -> Dict[str, Any]:
        """Get border device detail from SDA Fabric

        Get border device detail from SDA Fabric

        Args:
            device_management_ip_address (Any): deviceManagementIpAddress

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/border-device'
        params = {
            'deviceManagementIpAddress': device_management_ip_address,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_business_sda_border_device(self) -> Dict[str, Any]:
        """Add border device in SDA Fabric

        Add border device in SDA Fabric

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/border-device'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_business_sda_border_device(self, device_management_ip_address: Any) -> Dict[str, Any]:
        """Delete border device from SDA Fabric

        Delete border device from SDA Fabric

        Args:
            device_management_ip_address (Any): deviceManagementIpAddress

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/border-device'
        params = {
            'deviceManagementIpAddress': device_management_ip_address,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_business_sda_hostonboarding_user_device(self) -> Dict[str, Any]:
        """Add Port assignment for user device in SDA Fabric

        Add Port assignment for user device in SDA Fabric.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/hostonboarding/user-device'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_business_sda_hostonboarding_user_device(self, device_management_ip_address: Any, interface_name: Any) -> Dict[str, Any]:
        """Get Port assignment for user device in SDA Fabric

        Get Port assignment for user device in SDA Fabric.

        Args:
            device_management_ip_address (Any): deviceManagementIpAddress
            interface_name (Any): interfaceName

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/hostonboarding/user-device'
        params = {
            'deviceManagementIpAddress': device_management_ip_address,
            'interfaceName': interface_name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_business_sda_hostonboarding_user_device(self, device_management_ip_address: Any, interface_name: Any) -> Dict[str, Any]:
        """Delete Port assignment for user device in SDA Fabric

        Delete Port assignment for user device in SDA Fabric.

        Args:
            device_management_ip_address (Any): deviceManagementIpAddress
            interface_name (Any): interfaceName

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/hostonboarding/user-device'
        params = {
            'deviceManagementIpAddress': device_management_ip_address,
            'interfaceName': interface_name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_integration_events(self, instance_id: Optional[Any] = None) -> Dict[str, Any]:
        """Get Failed ITSM Events

        Used to retrieve the list of integration events that failed to create tickets in ITSM

        Args:
            instance_id (Any): Instance Id of the failed event as in the Runtime Dashboard

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/integration/events'
        params = {
            'instanceId': instance_id,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_integration_events(self) -> Dict[str, Any]:
        """Retry Integration Events

        Allows retry of multiple failed ITSM event instances. The retry request payload can be given as a list of strings: ["instance1","instance2","instance3",..] A minimum of one instance Id is mandatory. The list of failed event instance Ids can be retrieved using the 'Get Failed ITSM Events' API in the 'instanceId' attribute.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/integration/events'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_business_sda_hostonboarding_ssid_ippool(self) -> Dict[str, Any]:
        """Update SSID to IP Pool Mapping

        Update SSID to IP Pool Mapping

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/hostonboarding/ssid-ippool'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_business_sda_hostonboarding_ssid_ippool(self) -> Dict[str, Any]:
        """Add SSID to IP Pool Mapping

        Add SSID to IP Pool Mapping

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/hostonboarding/ssid-ippool'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_business_sda_hostonboarding_ssid_ippool(self, vlan_name: Any, site_name_hierarchy: Any) -> Dict[str, Any]:
        """Get SSID to IP Pool Mapping

        Get SSID to IP Pool Mapping

        Args:
            vlan_name (Any): VLAN Name
            site_name_hierarchy (Any): Site Name Heirarchy

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/hostonboarding/ssid-ippool'
        params = {
            'vlanName': vlan_name,
            'siteNameHierarchy': site_name_hierarchy,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_business_sda_control_plane_device(self, device_management_ip_address: Any) -> Dict[str, Any]:
        """Get control plane device from SDA Fabric

        Get control plane device from SDA Fabric

        Args:
            device_management_ip_address (Any): deviceManagementIpAddress

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/control-plane-device'
        params = {
            'deviceManagementIpAddress': device_management_ip_address,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_business_sda_control_plane_device(self) -> Dict[str, Any]:
        """Add control plane device in SDA Fabric

        Add control plane device in SDA Fabric

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/control-plane-device'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_business_sda_control_plane_device(self, device_management_ip_address: Any) -> Dict[str, Any]:
        """Delete control plane device in SDA Fabric

        Delete control plane device in SDA Fabric

        Args:
            device_management_ip_address (Any): deviceManagementIpAddress

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/business/sda/control-plane-device'
        params = {
            'deviceManagementIpAddress': device_management_ip_address,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_cmdb_sync_detail(self, status: Optional[Any] = None, date: Optional[Any] = None) -> Dict[str, Any]:
        """Get CMDB Sync Status

        This API allows to retrieve the detail of CMDB sync status.It accepts two query parameter "status","date".The supported values for status field are "Success","Failed","Unknown" and date field should be in "YYYY-MM-DD" format. By default all the cmdb sync status will be send as response and based on the query parameter filtered detail will be send as response.

        Args:
            status (Any): Supported values are "Success","Failed" and "Unknown". Providing other values will result in all the available sync job status.
            date (Any): Provide date in "YYYY-MM-DD" format

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/cmdb-sync/detail'
        params = {
            'status': status,
            'date': date,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_site_count(self, site_id: Optional[Any] = None) -> Dict[str, Any]:
        """Get Site Count

        Get the site count of the specified site's sub-hierarchy (inclusive of the provided site)

        Args:
            site_id (Any): Site instance UUID

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/site/count'
        params = {
            'siteId': site_id,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_client_enrichment_details(self, entity_type: Any, entity_value: Any, issue_category: Optional[Any] = None, persistbapioutput: Optional[Any] = None) -> Dict[str, Any]:
        """Get Client Enrichment Details

        Enriches a given network End User context (a network user-id or end user’s device Mac Address) with details about the user, the devices that the user is connected to and the assurance issues that the user is impacted by

        Args:
            entity_type (Any): Client enrichment details can be fetched based on either User ID or Client MAC address. This parameter value must either be network_user_id/mac_address
            entity_value (Any): Contains the actual value for the entity type that has been defined
            issue_category (Any): The category of the DNA event based on which the underlying issues need to be fetched
            persistbapioutput (Any): 

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if entity_type is not None:
            request_headers['entity_type'] = str(entity_type)
        if entity_value is not None:
            request_headers['entity_value'] = str(entity_value)
        if issue_category is not None:
            request_headers['issueCategory'] = str(issue_category)
        if persistbapioutput is not None:
            request_headers['__persistbapioutput'] = str(persistbapioutput)
        url = self.base_url + '/dna/intent/api/v1/client-enrichment-details'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_virtual_network(self) -> Dict[str, Any]:
        """Update virtual network with scalable groups

        Update virtual network with scalable groups

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/virtual-network'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_virtual_network(self, virtual_network_name: Any) -> Dict[str, Any]:
        """Delete virtual network with scalable groups

        Delete virtual network with scalable groups

        Args:
            virtual_network_name (Any): virtualNetworkName

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/virtual-network'
        params = {
            'virtualNetworkName': virtual_network_name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_virtual_network(self) -> Dict[str, Any]:
        """Add virtual network with scalable groups

        Add virtual network with scalable groups at global level

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/virtual-network'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_virtual_network(self, virtual_network_name: Any) -> Dict[str, Any]:
        """Get virtual network with scalable groups

        Get virtual network with scalable groups

        Args:
            virtual_network_name (Any): virtualNetworkName

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/virtual-network'
        params = {
            'virtualNetworkName': virtual_network_name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_assurance_schedule_sensor_test(self) -> Dict[str, Any]:
        """Edit sensor test template

        Intent API to deploy, schedule, or edit and existing SENSOR test template

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/AssuranceScheduleSensorTest'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_enterprise_ssid_ssid_name(self, ssid_name: Any) -> Dict[str, Any]:
        """Delete Enterprise SSID

        Deletes given enterprise SSID	

        Args:
            ssid_name (Any): Enter the SSID name to be deleted

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/enterprise-ssid/{ssid_name}'
        url = url.format(ssid_name=ssid_name)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_wireless_dynamic_interface(self, runsync: Optional[Any] = None, timeout: Optional[Any] = None, interface_name: Optional[Any] = None) -> Dict[str, Any]:
        """Get dynamic interface

        Get one or all dynamic interface(s)

        Args:
            runsync (Any): Enable this parameter to execute the API and return a response synchronously
            timeout (Any): If __runsync is set to ‘true’, this defines the maximum time before which if the API completes its execution, then a synchronous response is returned.  If the time taken for the API to complete the execution, exceeds this time, then an asynchronous response is returned with an execution id, that can be used to get the status and response associated with the API execution
            interface_name (Any): dynamic-interface name, if not specified all the existing dynamic interfaces will be retrieved

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if runsync is not None:
            request_headers['__runsync'] = str(runsync)
        if timeout is not None:
            request_headers['__timeout'] = str(timeout)
        url = self.base_url + '/dna/intent/api/v1/wireless/dynamic-interface'
        params = {
            'interface-name': interface_name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_wireless_dynamic_interface(self, runsync: Optional[Any] = None, timeout: Optional[Any] = None) -> Dict[str, Any]:
        """Create Update Dynamic interface

        API to create or update an dynamic interface	

        Args:
            runsync (Any): Enable this parameter to execute the API and return a response synchronously
            timeout (Any): If __runsync is set to ‘true’, this defines the maximum time before which if the API completes its execution, then a synchronous response is returned.  If the time taken for the API to complete the execution, exceeds this time, then an asynchronous response is returned with an execution id, that can be used to get the status and response associated with the API execution

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if runsync is not None:
            request_headers['__runsync'] = str(runsync)
        if timeout is not None:
            request_headers['__timeout'] = str(timeout)
        url = self.base_url + '/dna/intent/api/v1/wireless/dynamic-interface'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_wireless_dynamic_interface(self, interface_name: Any, runsync: Optional[Any] = None, timeout: Optional[Any] = None) -> Dict[str, Any]:
        """Delete dynamic interface

        Delete a dynamic interface	

        Args:
            interface_name (Any): valid interface-name to be deleted
            runsync (Any): Enable this parameter to execute the API and return a response synchronously
            timeout (Any): If __runsync is set to ‘true’, this defines the maximum time before which if the API completes its execution, then a synchronous response is returned.  If the time taken for the API to complete the execution, exceeds this time, then an asynchronous response is returned with an execution id, that can be used to get the status and response associated with the API execution

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if runsync is not None:
            request_headers['__runsync'] = str(runsync)
        if timeout is not None:
            request_headers['__timeout'] = str(timeout)
        url = self.base_url + '/dna/intent/api/v1/wireless/dynamic-interface'
        params = {
            'interfaceName': interface_name,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_execute_suggested_actions_commands(self) -> Dict[str, Any]:
        """Execute Suggested Actions Commands

        This API triggers the execution of the suggested actions for an issue, given the Issue Id. It will return an execution Id. At the completion of the execution, the output of the commands associated with the suggested actions will be provided

Invoking this API would provide the execution id. Execute the 'Get Business API Execution Details' API with this execution id, to receive the suggested actions commands output.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/execute-suggested-actions-commands'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_application_policy_application_set_count(self) -> Dict[str, Any]:
        """Get Application Sets Count

        Get the number of existing application-sets 

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/application-policy-application-set-count'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_user_enrichment_details(self, entity_type: Any, entity_value: Any, persistbapioutput: Optional[Any] = None) -> Dict[str, Any]:
        """Get User Enrichment Details

        Enriches a given network End User context (a network user-id or end user’s device Mac Address) with details about the user and devices that the user is connected to

        Args:
            entity_type (Any): User enrichment details can be fetched based on either User ID or Client MAC address. This parameter value must either be network_user_id/mac_address
            entity_value (Any): Contains the actual value for the entity type that has been defined
            persistbapioutput (Any): 

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if entity_type is not None:
            request_headers['entity_type'] = str(entity_type)
        if entity_value is not None:
            request_headers['entity_value'] = str(entity_value)
        if persistbapioutput is not None:
            request_headers['__persistbapioutput'] = str(persistbapioutput)
        url = self.base_url + '/dna/intent/api/v1/user-enrichment-details'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def post_dna_intent_api_v1_wireless_ap_provision(self, persistbapioutput: Optional[Any] = None) -> Dict[str, Any]:
        """AP Provision

        Access Point Provision and ReProvision	

        Args:
            persistbapioutput (Any): 

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if persistbapioutput is not None:
            request_headers['__persistbapioutput'] = str(persistbapioutput)
        url = self.base_url + '/dna/intent/api/v1/wireless/ap-provision'
        params = {}
        return self._handle_request('post', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_device_enrichment_details(self, entity_type: Any, entity_value: Any, persistbapioutput: Optional[Any] = None) -> Dict[str, Any]:
        """Get Device Enrichment Details

        Enriches a given network device context (device id or device Mac Address or device management IP address) with details about the device and neighbor topology

        Args:
            entity_type (Any): Device enrichment details can be fetched based on either Device ID or Device MAC address or Device IP Address. This parameter value must either be device_id/mac_address/ip_address
            entity_value (Any): Contains the actual value for the entity type that has been defined
            persistbapioutput (Any): 

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if entity_type is not None:
            request_headers['entity_type'] = str(entity_type)
        if entity_value is not None:
            request_headers['entity_value'] = str(entity_value)
        if persistbapioutput is not None:
            request_headers['__persistbapioutput'] = str(persistbapioutput)
        url = self.base_url + '/dna/intent/api/v1/device-enrichment-details'
        params = {}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_site_site_id(self, site_id: Any) -> Dict[str, Any]:
        """Delete Site

        Delete site with area/building/floor by siteId.

        Args:
            site_id (Any): Site id to which site details to be deleted.

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/site/{site_id}'
        url = url.format(site_id=site_id)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_site_site_id(self, persistbapioutput: Any, site_id: Any, runsync: Optional[Any] = None, timeout: Optional[Any] = None) -> Dict[str, Any]:
        """Update Site

        Update site area/building/floor with specified hierarchy and new values

        Args:
            persistbapioutput (Any): Persist bapi sync response
            site_id (Any): Site id to which site details to be updated.
            runsync (Any): Enable this parameter to execute the API and return a response synchronously
            timeout (Any): During synchronous execution, this defines the maximum time to wait for a response, before the API execution is terminated

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if persistbapioutput is not None:
            request_headers['__persistbapioutput'] = str(persistbapioutput)
        if runsync is not None:
            request_headers['__runsync'] = str(runsync)
        if timeout is not None:
            request_headers['__timeout'] = str(timeout)
        url = self.base_url + '/dna/intent/api/v1/site/{site_id}'
        url = url.format(site_id=site_id)
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def get_dna_intent_api_v1_membership_site_id(self, site_id: Any, offset: Optional[Any] = None, limit: Optional[Any] = None, device_family: Optional[Any] = None, serial_number: Optional[Any] = None) -> Dict[str, Any]:
        """Get Membership

        Getting the site children details and device details.

        Args:
            site_id (Any): Site id to retrieve device associated with the site.
            offset (Any): offset/starting row
            limit (Any): Number of sites to be retrieved
            device_family (Any): Device family name 
            serial_number (Any): Device serial number

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/membership/{site_id}'
        url = url.format(site_id=site_id)
        params = {
            'offset': offset,
            'limit': limit,
            'deviceFamily': device_family,
            'serialNumber': serial_number,
        }
        params = {k: v for k, v in params.items() if v is not None}
        return self._handle_request('get', url, params=params, headers=request_headers)

    def put_dna_intent_api_v1_sensor_run_now(self) -> Dict[str, Any]:
        """Run now sensor test

        Intent API to run a deployed SENSOR test

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/sensor-run-now'
        params = {}
        return self._handle_request('put', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_wireless_profile_wireless_profile_name(self, wireless_profile_name: Any) -> Dict[str, Any]:
        """Delete Wireless Profile

        Delete the Wireless Profile whose name is provided.

        Args:
            wireless_profile_name (Any): Wireless Profile Name

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        url = self.base_url + '/dna/intent/api/v1/wireless-profile/{wireless_profile_name}'
        url = url.format(wireless_profile_name=wireless_profile_name)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)

    def delete_dna_intent_api_v1_business_ssid_ssid_name_managed_a_p_locations(self, persistbapioutput: Any, ssid_name: Any, managed_a_p_locations: Any) -> Dict[str, Any]:
        """Delete SSID and provision it to devices

        Removes SSID or WLAN from the network profile, reprovision the device(s) and deletes the SSID or WLAN from DNA Center	

        Args:
            persistbapioutput (Any): Enable this parameter to execute the API and return a response asynchronously.
            ssid_name (Any): SSID Name. This parameter needs to be encoded as per UTF-8 encoding.
            managed_a_p_locations (Any): List of managed AP locations (Site Hierarchies). This parameter needs to be encoded as per UTF-8 encoding

        Returns:
            Dict[str, Any]: API response

        Raises:
            requests.exceptions.RequestException: If the API request fails
        """

        request_headers = self.session.headers.copy()
        if persistbapioutput is not None:
            request_headers['__persistbapioutput'] = str(persistbapioutput)
        url = self.base_url + '/dna/intent/api/v1/business/ssid/{ssid_name}/{managed_a_p_locations}'
        url = url.format(ssid_name=ssid_name, managed_a_p_locations=managed_a_p_locations)
        params = {}
        return self._handle_request('delete', url, params=params, headers=request_headers)


# Create a singleton instance
client = APIClient()

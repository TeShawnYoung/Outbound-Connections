# Outbound-C2-Beacon-Destinations

## Project Overview

This project demonstrates the implementation of a Microsoft Sentinel security visualization focused on outbound network activity using **DeviceNetworkEvents**. By filtering external connections, removing known Microsoft and Windows-related destinations, enriching public IP addresses with geographic information, and aggregating connection activity, this project transforms raw endpoint network telemetry into an interactive **KQL (Kusto Query Language) Workbook**.

The primary objective was to build a geographic visualization that identifies where endpoints are connecting externally and highlights destinations receiving repeated connections from the environment.

---

## Core Visualization & Scenario Implemented

### 1. Outbound C2 / Beacon Destinations

* **Log Source:** `DeviceNetworkEvents`
* **Objective:** Maps public external destination IP addresses (`RemoteIP`) that endpoints connect to in order to identify geographic patterns and potentially unusual shared destinations.
* **Business Value:** Provides analysts with destination-level context for investigating repeated outbound connections, potentially suspicious infrastructure, and connections shared across multiple devices.

#### Visual Dashboard

### Outbound C2 / Beacon Destinations — DeviceNetworkEvents

<img width="1492" height="458" alt="Outbound-Connections" src="https://github.com/user-attachments/assets/da06aad3-826f-4a35-8460-831837c85524" />

#### The KQL Query

```kusto
DeviceNetworkEvents
| where RemoteIPType == "Public" and isnotempty(RemoteIP)
| where isempty(RemoteUrl) or RemoteUrl !endswith "microsoft.com"
| where isempty(RemoteUrl) or RemoteUrl !endswith "windows.com"
| where isempty(RemoteUrl) or RemoteUrl !endswith "windowsupdate.com"
| where isempty(RemoteUrl) or RemoteUrl !endswith "azure.com"
| where isempty(RemoteUrl) or RemoteUrl !endswith "office.com"
| where isempty(RemoteUrl) or RemoteUrl !endswith "msftncsi.com"
| extend geo = geo_info_from_ip_address(RemoteIP)
| extend Latitude  = toreal(geo.latitude),
        Longitude = toreal(geo.longitude),
        Country   = tostring(geo.country),
        State     = tostring(geo.state),
        City      = tostring(geo.city)
| where isnotempty(Latitude) and isnotempty(Longitude)
| summarize Connections = count(),
           Devices     = dcount(DeviceName),
           Processes   = make_set(InitiatingProcessFileName, 25),
           Ports       = make_set(RemotePort, 15),
           SampleUrl   = take_any(RemoteUrl)
        by RemoteIP, Country, State, City, Latitude, Longitude
| where Connections >= 5
| extend MapLabel = strcat(SampleUrl, " (", City, ", ", State, ", ", Country, ") — ", Devices, " devices")
| project Latitude, Longitude, MapLabel, Devices, Connections, Processes, Ports, SampleUrl, RemoteIP, Country, State, City
| order by Devices desc, Connections desc
```

### 📊 Dashboard Analysis & Key Findings

### 🔍 KQL Query Breakdown

* **Filters Public Destinations:** Uses `RemoteIPType == "Public"` and `isnotempty(RemoteIP)` to focus on externally routable destination addresses.
* **Reduces Known-Good Microsoft Traffic:** Excludes destinations associated with common Microsoft, Windows, Azure, Office, and Windows connectivity services using `RemoteUrl` suffix filtering.
* **Enriches Destination IPs:** Uses the native `geo_info_from_ip_address()` function to associate public destination IPs with approximate geographic information.
* **Aggregates Network Activity:** Calculates total connections, distinct devices, initiating processes, and destination ports for each external IP.
* **Reduces Low-Volume Noise:** Requires a minimum of five connections to a destination before it is displayed on the map.
* **Creates Analyst-Friendly Labels:** Builds a `MapLabel` containing the destination URL, geographic location, and number of devices connecting to the destination.

---

## 🗺️ Map Visualization & Legend Key

* **Outbound Destinations:** Bubbles represent the approximate geographic location of public destination IP addresses contacted by endpoints.
* **Bubble Size:** Represents the number of distinct devices connecting to the destination.
* **Device Fan-In:** A destination contacted by multiple devices can provide useful context when investigating shared infrastructure or potentially coordinated activity.
* **Connection Volume:** `Connections` represents the total number of network events associated with the destination.
* **Initiating Processes:** `Processes` identifies the applications responsible for connections to the destination.
* **Destination Ports:** `Ports` provides visibility into the remote ports associated with the destination.
* **Geographic Context:** Country, state, and city information provide an additional layer of investigative context.

> Geographic information is approximate. VPNs, proxies, cloud infrastructure, hosting providers, CDNs, and IP address reassignment can cause the geographic location of an IP address to differ from the physical location of the associated infrastructure or user.

---

## ⚠️ Key Security Anomalies Detected

* **Repeated Connections to an External Destination:** A destination receiving repeated connections may warrant investigation depending on the communicating process, destination reputation, and expected business activity.
* **High Device Fan-In:** A single external destination contacted by numerous endpoints can represent shared legitimate infrastructure, but may also warrant investigation when the destination is unexpected or associated with suspicious processes.
* **Unusual Geographic Destinations:** Connections to unexpected countries or regions can provide an investigative signal when correlated with the organization's expected network activity.
* **Suspicious Initiating Processes:** Reviewing `Processes` can help distinguish expected applications such as browsers from unusual or unexpected executables communicating externally.
* **Unusual Destination Ports:** `Ports` provides additional context for determining whether connections are occurring over expected services or less common ports.
* **Repeated Beacon-Like Activity:** Consistent outbound communication to the same external destination may be worth investigating for potential command-and-control or beaconing behavior.

> A repeated outbound connection or unusual geographic destination is an investigative signal, not standalone proof of malicious activity. Analysts should correlate the destination with process information, threat intelligence, device context, DNS activity, user activity, and other available telemetry before determining whether the activity is suspicious.

---

## 🔍 Investigation Workflow

When an external destination is identified as potentially suspicious, an analyst can use the visualization to pivot through several pieces of contextual information:

1. **Identify the destination IP:** Review `RemoteIP` to determine the external infrastructure being contacted.
2. **Review connection volume:** Examine `Connections` to determine how frequently the destination was contacted.
3. **Determine device scope:** Review `Devices` to identify how many endpoints communicated with the destination.
4. **Review initiating processes:** Examine `Processes` to identify which executables generated the connections.
5. **Review destination ports:** Examine `Ports` for additional network-level context.
6. **Review geographic information:** Use `Country`, `State`, and `City` as investigative context.
7. **Correlate with additional telemetry:** Pivot into endpoint, DNS, identity, threat intelligence, and other available security data.

---

## Technical Architecture & Workflow

1. **Ingestion:** Network telemetry is collected in **Microsoft Sentinel / Log Analytics** through the `DeviceNetworkEvents` data source.
2. **Data Extraction:** Used **Kusto Query Language (KQL)** to filter public outbound connections and exclude common Microsoft-related destinations.
3. **Data Enrichment:** Public destination IP addresses are enriched using the native `geo_info_from_ip_address()` function.
4. **Aggregation:** Network events are grouped by destination IP and geographic information while calculating connection volume, device fan-in, initiating processes, and destination ports.
5. **Visualization:** Configured a **Microsoft Sentinel Workbook** using a geographic map to transform raw network telemetry into an analyst-friendly outbound connection visualization.

---

## Skills Demonstrated

* **Microsoft Sentinel:** Building and configuring security workbooks and geographic visualizations.
* **KQL & Data Analysis:** Filtering, aggregating, and transforming endpoint network telemetry.
* **Network Security Monitoring:** Analyzing outbound connections, destination IPs, ports, and initiating processes.
* **Security Data Enrichment:** Using `geo_info_from_ip_address()` to add geographic context to public IP addresses.
* **Threat Hunting & Investigation:** Identifying repeated external connections, high device fan-in, and potentially unusual destinations.
* **C2 / Beacon Analysis:** Using outbound connection patterns as investigative signals for potential command-and-control activity.
* **Data Visualization:** Translating raw network events into geographic security dashboards.

# Web Server Monitoring: Security Tools

The Wazuh will be installed using the IP address (`172.16.57.2`) from the internal network and Cassandra and Elasticsearch the localhost IP address (`127.0.0.1`). TheHIve will be listening on port 9000 (`http://0.0.0.0:9000`) and Wazuh will be listening on port 443 (`https://0.0.0.0:443`). The IP address with 0s means that both services can receive connections destined to any of their IP addresses.

## Outline

1. [Wazuh Installation on Ubuntu Server](#wazuh-installation-on-ubuntu-server)
2. [Suricata Installation on Ubuntu Server](#suricata-installation-on-ubuntu-server)
3. [TheHive Installation on Ubuntu Server](#thehive-installation-on-ubuntu-server)
4. [Docker Installation on Ubuntu Server](#docker-installation-on-ubuntu-server)
4. [Admyral Installation on Ubuntu Server using Docker](#admyral-installation-on-ubunu-server-using-docker)
5. [DVWA Installation on Debian](#dvwa-installation-on-debian)

### Ideas to implement

Homelab tools diagram:
- https://medium.com/@khalid.chbail4/building-a-home-soc-lab-part-1-elk-stack-siem-solution-b82dd396836f


----------------------------------------------------------------------------------------------


## Wazuh Installation on Ubuntu Server

Wazuh is a security monitoring platform that combines intrusion detection, log management, and security information and event management (SIEM) capabilities. It helps organizations detect and respond to security threats in real-time. Here, we walk through the Wazuh installation on the Ubuntu Server. For reference, check [Wazuh documentation](https://documentation.wazuh.com/current/getting-started/index.html).


<!---------- Step 1: Installing the Wazuh indexer step by step ---------->
<details>
<summary>
<h3>Step 1: Installing the Wazuh indexer step by step</h3>
</summary>

Wazuh indexer is a highly scalable full-text search engine and offers advanced security, alerting, index management, deep performance analysis, and several other features. Here, we will install and configure the Wazuh indexer as a single-node cluster.

1. Certificates creation:
    1. Download the `wazuh-certs-tool.sh` script and the `config.yml` configuration file. This creates the certificates that encrypt communications between the Wazuh central components.
        ```bash
        $ sudo curl -sO https://packages.wazuh.com/4.8/wazuh-certs-tool.sh
        $ sudo curl -sO https://packages.wazuh.com/4.8/config.yml
        ```
    2. Edit `config.yml` and replace the node names and IP values:
        ```bash
        $ sudo nano config.yml
        ```
        - Set the parameters below:
        ```yml
        nodes:
        # Wazuh indexer nodes
        indexer:
            - name: node-1
            ip: "127.0.0.1"
        ...

        # Wazuh server nodes
        server:
            - name: wazuh-1
            ip: "127.0.0.1"
        ...
        # Wazuh dashboard nodes
        dashboard:
            - name: dashboard
            ip: "192.168.57.3"
        ````
    3. Run `./wazuh-certs-tool.sh` to create the certificates:
        ```bash
        $ sudo bash ./wazuh-certs-tool.sh -A
        ```
    4. Compress all the necessary files:
        ```bash
        $ sudo tar -cvf ./wazuh-certificates.tar -C ./wazuh-certificates/ .
        $ sudo rm -rf ./wazuh-certificates
        ```
2. Dependencies and the Wazuh repository:
    1. Install package dependencies:
        ```bash
        $ sudo apt install debconf adduser procps gnupg apt-transport-https
        ```
    2. Add the Wazuh repository:
        1. Install the GPG key:
            ```bash
            $ curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && sudo chmod 644 /usr/share/keyrings/wazuh.gpg
            ```
        2. Add the repository:
            ```bash
            $ echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee -a /etc/apt/sources.list.d/wazuh.list
            ```
        3. Update the package information:
            ```bash
            $ sudo apt update
            ```
3. Nodes installation:
    1. Install the Wazuh indexer:
        ```bash
        $ sudo apt install wazuh-indexer
        ```
    2. Configure the Wazuh indexer by editing its configuration file:
        ```bash
        $ sudo nano /etc/wazuh-indexer/opensearch.yml
        ```
        - On `network.host`, set the address of this node for both HTTP and transport traffic. Use the same node address defined in `config.yml` to create the SSL certificates.
        - On `node.name`, use the same as defined in `config.yml`.
        ```yml
        network.host: "127.0.0.1"
        node.name: "node-1"
        ```
    3. To deploy the  certificates, run the commands below:
        ```bash
        $ NODE_NAME=node-1
        $ sudo mkdir /etc/wazuh-indexer/certs
        $ sudo tar -xf ./wazuh-certificates.tar -C /etc/wazuh-indexer/certs/ ./$NODE_NAME.pem ./$NODE_NAME-key.pem ./admin.pem ./admin-key.pem ./root-ca.pem
        $ sudo mv -n /etc/wazuh-indexer/certs/$NODE_NAME.pem /etc/wazuh-indexer/certs/indexer.pem
        $ sudo mv -n /etc/wazuh-indexer/certs/$NODE_NAME-key.pem /etc/wazuh-indexer/certs/indexer-key.pem
        $ sudo chmod 400 -R /etc/wazuh-indexer/certs
        $ sudo chmod 500 /etc/wazuh-indexer/certs
        $ sudo chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs
        ```
    4. Enable and start the Wazuh indexer service:
        ```bash
        $ sudo systemctl daemon-reload
        $ sudo systemctl enable wazuh-indexer
        $ sudo systemctl start wazuh-indexer
        ```
    5. File location:
        ```yml
        config: /etc/wazuh-indexer/opensearch.yml
        data: /var/lib/wazuh-indexer/
        logs: /var/lib/wazuh-indexer/
        ```
3. Cluster initialization:
    1. Run the Wazuh indexer script to load the new certificate information and start the single-node cluster:
        ```bash
        $ sudo /usr/share/wazuh-indexer/bin/indexer-security-init.sh
        ```
    2. Test the cluster installation by running the command below:
        ```bash
        $ sudo curl -k -u admin:admin https://127.0.0.1:9200
        ```
    3. Run the command below to check if the single-node cluster is working correctly:
        ```bash
        $ sudo curl -k -u admin:admin https://127.0.0.1:9200/_cat/nodes?v
        ```
</details>



<!---------- Step 2: Install Wazuh server step by step ---------->
<details>
<summary>
<h3>Step 2: Install Wazuh server step by step</h3>
</summary>

The Wazuh server is a central component that includes the Wazuh manager and Filebeat. The Wazuh manager collects and analyzes data from the deployed Wazuh agents, and triggers alerts when threats of anomalies are detected. Filebeat securely forwards alerts and archived events to the Wazuh indexer.

1. Wazuh server node installation:
    1. Install the Wazuh manager package:
        ```bash
        $ sudo apt install wazuh-manager
        ```
    2. Install Filebeat:
        ```bash
        $ sudo apt install filebeat
        ```
    3. Configure Filebeat:
        1. Download the preconfigured Filebeat configuration file to the `/etc/filebeat/` directory:
            ```bash
            $ sudo curl -so /etc/filebeat/filebeat.yml https://packages.wazuh.com/4.8/tpl/wazuh/filebeat/filebeat.yml
            ```
        2. Edit the Filebeat configuration file:
            ```bash
            $ sudo nano /etc/filebeat/filebeat.yml
            ```
            - `hosts` specifies the list of Wazuh indexer nodes to connect to, set it as below.
            ```yml
            hosts: ["localhost:9200"]
            ```
        3. Create a Filebeat keystore to securely store authentication credentials:
            ```bash
            $ sudo filebeat keystore create
            ```
        4. Add the default username and password `admin`:`admin` to the secrets keystore.
            ```bash
            $ echo admin | sudo filebeat keystore add username --stdin --force
            $ echo admin | sudo filebeat keystore add password --stdin --force
            ```
        5. Download the alerts template for the Wazuh indexer:
            ```bash
            $ sudo curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/v4.8.0/extensions/elasticsearch/7.x/wazuh-template.json
            $ sudo chmod go+r /etc/filebeat/wazuh-template.json
            ```
        6. Install the Wazuh module for Filebeat:
            ```bash
            $ curl -s https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.4.tar.gz | sudo tar -xvz -C /usr/share/filebeat/module
            ```
    4. To deploy the certificates run the commands below:
        ```bash
        $ NODE_NAME=wazuh-1
        $ sudo mkdir /etc/filebeat/certs
        $ sudo tar -xf ./wazuh-certificates.tar -C /etc/filebeat/certs/ ./$NODE_NAME.pem ./$NODE_NAME-key.pem ./root-ca.pem
        $ sudo mv -n /etc/filebeat/certs/$NODE_NAME.pem /etc/filebeat/certs/filebeat.pem
        $ sudo mv -n /etc/filebeat/certs/$NODE_NAME-key.pem /etc/filebeat/certs/filebeat-key.pem
        $ sudo chmod 400 -R /etc/filebeat/certs
        $ sudo chmod 500 /etc/filebeat/certs
        $ sudo chown -R root:root /etc/filebeat/certs
        ```
    5. (Optional) Configure the Wazuh indexer connection for the vulnerability detection capability:
        1. Save the Wazuh indexer username and password into the Wazuh manager keystore using the wazuh-keystore tool:
            ```bash
            $ sudo /var/ossec/bin/wazuh-keystore -f indexer -k username -v admin
            $ sudo /var/ossec/bin/wazuh-keystore -f indexer -k password -v admin
            ```
        2. Edit `/var/ossec/etc/ossec.conf` to configure the indexer connection:
            ```bash
            $ sudo nano /var/ossec/etc/ossec.conf
            ```
            - On `<indexer>`, replace the host address `0.0.0.0` with your Wazuh indexer node IP address `127.0.0.1`.
            ```html
            <indexer>
              <enabled>yes</enabled>
              <hosts>
                <host>https://127.0.0.1:9200</host>
              </hosts>
            ```
    6. Start the Wazuh manager:
        1. Enable and start the Wazuh manager service:
            ```bash
            $ sudo systemctl daemon-reload
            $ sudo systemctl enable wazuh-manager
            $ sudo systemctl start wazuh-manager
            ```
        2. Verify the Wazuh manager status:
            ```bash
            $ systemctl status wazuh-manager
            ```
    7. Start the Filebeat service:
        1. Enable and start the Filebeat service.
            ```bash
            $ sudo systemctl daemon-reload
            $ sudo systemctl enable filebeat
            $ sudo systemctl start filebeat
            ```
        2. Verify that Filebeat is successfully installed:
            ```bash
            $ sudo filebeat test output
            ```
</details>


<!---------- Step 3: Install Wazuh dashboard step by step ---------->
<details>
<summary>
<h3>Step 3: Install Wazuh dashboard step by step</h3>
</summary>

The Wazuh dashboard is a web interface for mining and visualizing the Wazuh server alerts and archived events.

1. Install package dependencies if missing:
    ```bash
    $ sudo apt install debhelper tar curl libcap2-bin
    ```
2. Install the Wazuh dashboard package:
    ```bash
    $ sudo apt install wazuh-dashboard
    ```
3. Configure the Wazuh dashboard by editing its configuration file:
    ```bash
    $ sudo nano /etc/wazuh-dashboard/opensearch_dashboards.yml
    ```
    - `server.host` specifies the host address of the Wazuh dashboard server to allow remote users to connect. Set it to `192.168.57.3`.
    - `opensearch.hosts` specifies the Wazuh indexer node address to use for all your queries. Set it to `127.0.0.1` which is the same as `localhost`.
    ```yml
    server.host: 192.168.57.3
    server.port: 443
    opensearch.hosts: https://127.0.0.1:9200
    opensearch.ssl.verificationMode: certificate
    ```
4. To deploy the certificates run the commands below:
    ```bash
    $ NODE_NAME=dashboard
    $ sudo mkdir /etc/wazuh-dashboard/certs
    $ sudo tar -xf ./wazuh-certificates.tar -C /etc/wazuh-dashboard/certs/ ./$NODE_NAME.pem ./$NODE_NAME-key.pem ./root-ca.pem
    $ sudo mv -n /etc/wazuh-dashboard/certs/$NODE_NAME.pem /etc/wazuh-dashboard/certs/dashboard.pem
    $ sudo mv -n /etc/wazuh-dashboard/certs/$NODE_NAME-key.pem /etc/wazuh-dashboard/certs/dashboard-key.pem
    $ sudo chmod 400 -R /etc/wazuh-dashboard/certs
    $ sudo chmod 500 /etc/wazuh-dashboard/certs
    $ sudo chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs
    ```
5. Enable and start the Wazuh dashboard service:
    ```bash
    $ sudo systemctl daemon-reload
    $ sudo systemctl enable wazuh-dashboard
    $ sudo systemctl start wazuh-dashboard
    ```
6. Edit the Wazuh dashboard App configuration file:
    ```bash
    $ sudo nano /usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml
    ```
    - Replace the `url` value with the IP address of the Wazuh server master node:
    ```yml
    hosts:
        - default:
            url: https://127.0.0.1
            port: 55000
            username: wazuh-wui
            password: wazuh-wui
            run_as: false
    ```
7. Access the Wazuh web interface with your credentials:
    - URL: `https://192.168.57.3` (Because of the `https` protocol, port `443` is automatically used)
    - Username: `admin`
    - Password: `admin`

</details>


<!---------- Wazuh Agent: Installation on Kali Linux ---------->
<details>
<summary>
<h3>Wazuh Agent: Installation on Kali Linux</h3>
</summary>

1. Open the Wazuh dashboard on the browser by accessing `https://<server-ip>:443`.
2. On the Wazuh homepage, click on **Add agent**.
3. On the first step of Deploy new agent, select **DEB amd64** under LINUX.
4. On Server address, enter the IP address of the server with Wazuh manager installed.
5. On step four, copy the command and run it on the client machine. It should look similar to the one below:
	```bash
	$wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.8.0-1_amd64.deb && sudo WAZUH_MANAGER='192.168.57.3' dpkg -i ./wazuh-agent_4.8.0-1_amd64.deb
	```
6. Enable and start the agent, then check its status:
	```bash
	$ sudo systemctl deamon-reload
	$ sudo systemctl enable wazuh-agent
	$ sudo systemctl start wazuh-agent
	$ sudo systemctl status wazuh-agent
	```
</details>


<!---------- Wazuh Agent: Installation on Debian ---------->
<details>
<summary>
<h3>Wazuh Agent: Installation on Debian</h3>
</summary>

1. Open the Wazuh dashboard on the browser by accessing `https://<server-ip>:443`.
2. On the Wazuh homepage, click on any legend label under AGENTS SUMMARY.
3. Click on **Deploy new agent**.
3. On the first step of Deploy new agent, select **DEB amd64** under LINUX.
4. On Server address, enter the IP address of the server with Wazuh manager installed.
5. On step four, copy the command and run it on the client machine. It should look similar to the one below:
	```bash
	$ wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.8.0-1_amd64.deb && sudo WAZUH_MANAGER='192.168.57.3' dpkg -i ./wazuh-agent_4.8.0-1_amd64.deb
	```
6. Enable and start the agent, then check its status:
	```bash
	$ sudo systemctl deamon-reload
	$ sudo systemctl enable wazuh-agent
	$ sudo systemctl start wazuh-agent
	$ sudo systemctl status wazuh-agent
	```
</details>


<!---------- Troubleshooting: Wazuh-modulesd high CPU usage ---------->
<details>
<summary>
<h3>Troubleshooting: Wazuh-modulesd high CPU usage</h3>
</summary>

1. Disable the vulnerability detection feature
	1. Open the Wazuh server configuration file:
		```bash
		$ sudo nano /var/ossec/etc/ossec.conf
		```
		- Set the \<enable\> tag to "no" on \<vulnerability-detection\>:
		```html
		<vulnerability-detection>
    	  <enabled>no</enabled>
    	  <index-status>yes</index-status>
    	  <feed-update-interval>60m</feed-update-interval>
  		</vulnerability-detection>
		```
</details>


<!---------- Troubleshooting: False positive from Docker Overlays ---------->
<details>
<summary>
<h3>Troubleshooting: False positive from Docker Overlays</h3>
</summary>

Edit the agent configuration file to fix the problem:

1. If the Wazuh client has Docker installed:
	1. Edit the shared config file on the client machine:
		```bash
		$ sudo nano /var/ossec/etc/shared/agent.conf
		```
		- Add the following lines in between the \<agent_config\> tag:
		```html
		<rootcheck>
			<ignore>/var/lib/docker/overlay2</ignore>
		</rootcheck>
		```
	2. Restart the Wazuh agent service:
		```bash
		$ sudo systemctl restart wazuh-agent.service
		```
2. If the Wazuh server has Docker installed:
	1. Edit the shared config file on the server machine:
		```bash
		$ sudo nano /var/ossec/etc/ossec.conf
		```
		- Add the following lines in between the \<ignore\> tag within the \<rootcheck\> tag:
		```html
		<rootcheck>
			...
			<ignore>/var/lib/docker/overlay2</ignore>
		</rootcheck>
		```
	2. Restart the Wazuh manager service:
		```bash
		$ sudo systemctl restart wazuh-manager.service
		```
3. Edit the template file for new agents on the Wazuh server:
	1. Open the template file with the shared agent configuration for new agents:
		```bash
		$ sudo nano /var/ossec/etc/shared/default/agent.conf
		```
		- Add the following lines in between the \<agent_config\> tag:
		```html
		<rootcheck>
			<ignore>/var/lib/docker/overlay2</ignore>
		</rootcheck>
		```
	2. Restart the Wazuh server:
		```bash
		$ sudo systemctl restart wazuh-manager
		```
</details>


---------------------------------------------------------------------------------------------------


## Wazuh Integrations

Wazuh Integrations provide seamless connectivity between the Wazuh platform and third-party tools, allowing for enhanced security monitoring and threat detection capabilities. By integrating with various security solutions, Wazuh enables organizations to centralize their security operations and streamline incident response processes.

### Refresh fields

To refresh the field list, follow the instructions below:

1. Go to "Dashboards Management" > "Dashboards Management" on the left menu.
2. Click on "Index Patterns" under "Dashboards Management" on the left menu.
3. Click on "wazuh-alerts-*" under "Index patterns", then click on the "Refresh field list" icon on the top right.



<!---------- Suricata Integration with Wazuh ---------->
<details>
<summary>
<h3>Suricata Integration with Wazuh</h3>
</summary>

1. Open `ossec.conf` to configure the Wazuh manager:
    ```bash
    $ sudo nano /var/ossec/etc/ossec.conf
    ```
    - Add the Suricata log file to ossec config:
    ```yml
    <ossec_confi>
      ...
      <localfile>
        <log_format>syslog</log_format>
        <location>/var/log/suricata/eve.json</location>
      </localfile>
    </ossec_config>
    ```
2. Increase the number of field allowed in the log files by chaging the file below:
    ```bash
    $ sudo nano /var/ossec/etc/local_internal_options.conf
    ```
    - Add the lines below at the bottom of the file:
    ```yml
    # Maximum number of fields in a decoder (order tag) [32..1024]
    analysisd.decoder_order_size=1024
    ```
3. Restart the Wazuh manager:
    ```bash
    $ sudo systemctl restart wazuh-manager.service
    ```
4. On the Wazuh left menu, click on "Server management", then click on "Settings".
5. On the "Configuration" page, click on "Edit configuration" at the top-right and check if the Suricata log was added at the bottom of the `ossec.conf` file.
6. Refresh the field list:
	1. Go to "Dashboards Management" > "Dashboards Management" on the left menu.
	2. Click on "Index Patterns" under "Dashboards Management" on the left menu.
	3. Click on "wazuh-alerts-*" under "Index patterns", then click on the "Refresh field list" icon on the top right.

</details>


<!---------- TheHive Integration with Wazuh ---------->
<details>
<summary>
<h3>TheHive Integration with Wazuh</h3>
</summary>

### Create User Account on TheHive

1. On **Organisations**, click on the organization name.
2. On the organisaton page, under **Users** click on the **plus sign** to add an user.
	1. Fill the fields on **Adding a User**
		- **Type:** Normal
		- **Organisation:** JASHWS
		- **Login:** admin@jah.com
		- **Name:** Admin
		- **Profile:** org-admin
	2. Then, click **Confirm**.
	3. To set the passowrd of the created **Admin** user, click on **Preview**:
		1. Under **Password**, click on **Set a new password**.
		2. Type the passowrd and click on **Confirm**.
3. Create an user with the analyst profile to generate the API key. On the organisaton page, under **Users** click on the **plus sign** to add an user.
	1. Fill the fields on **Adding a User**
		- **Type:** Normal
		- **Organisation:** JASHWS
		- **Login:** user1@jah.com
		- **Name:** User1
		- **Profile:** Analyst
	2. Then, click **Confirm**.
	3. To create the API kei, click on **Preview** on the created user:
		1. Under **API Key**, click on **Create**.
		2. Copy the created API key for future use.
		- dsv6aWgxlPbibBDtZCgDDPNSj87ltVvs

### Configure Wazuh manager

1. First, install the TheHive Python module:
	1. thehive4py v1.x:
	```bash
	$ sudo /var/ossec/framework/python/bin/pip3 install thehive4py==1.8.1
	```
	2. thehive4py v2.x:
	```bash
	$ pip install "thehive4py>=2.0.0b"
	```
2. Create the custom integration script called `custom-w2thive.py` and save it at `/var/ossec/integrations/`:
	```bash
	$ sudo nano /var/ossec/integrations/custom-w2thive.py
	```
	- Set the content below to the python script and save it:
	```python
	#!/var/ossec/framework/python/bin/python3
	import json
	import sys
	import os
	import re
	import logging
	import uuid
	from thehive4py.api import TheHiveApi
	from thehive4py.models import Alert, AlertArtifact

	#start user config

	# Global vars

	#threshold for wazuh rules level
	lvl_threshold=0
	#threshold for suricata rules level
	suricata_lvl_threshold=3

	debug_enabled = False
	#info about created alert
	info_enabled = True

	#end user config

	# Set paths
	pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
	log_file = '{0}/logs/integrations.log'.format(pwd)
	logger = logging.getLogger(__name__)
	#set logging level
	logger.setLevel(logging.WARNING)
	if info_enabled:
		logger.setLevel(logging.INFO)
	if debug_enabled:
		logger.setLevel(logging.DEBUG)
	# create the logging file handler
	fh = logging.FileHandler(log_file)
	formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
	fh.setFormatter(formatter)
	logger.addHandler(fh)

	def main(args):
		logger.debug('#start main')
		logger.debug('#get alert file location')
		alert_file_location = args[1]
		logger.debug('#get TheHive url')
		thive = args[3]
		logger.debug('#get TheHive api key')
		thive_api_key = args[2]
		thive_api = TheHiveApi(thive, thive_api_key )
		logger.debug('#open alert file')
		w_alert = json.load(open(alert_file_location))
		logger.debug('#alert data')
		logger.debug(str(w_alert))
		logger.debug('#gen json to dot-key-text')
		alt = pr(w_alert,'',[])
		logger.debug('#formatting description')
		format_alt = md_format(alt)
		logger.debug('#search artifacts')
		artifacts_dict = artifact_detect(format_alt)
		alert = generate_alert(format_alt, artifacts_dict, w_alert)
		logger.debug('#threshold filtering')
		if w_alert['rule']['groups']==['ids','suricata']:
			#checking the existence of the data.alert.severity field
			if 'data' in w_alert.keys():
				if 'alert' in w_alert['data']:
					#checking the level of the source event
					if int(w_alert['data']['alert']['severity'])<=suricata_lvl_threshold:
						send_alert(alert, thive_api)
		elif int(w_alert['rule']['level'])>=lvl_threshold:
			#if the event is different from suricata AND suricata-event-type: alert check lvl_threshold
			send_alert(alert, thive_api)

	def pr(data,prefix, alt):
		for key,value in data.items():
			if hasattr(value,'keys'):
				pr(value,prefix+'.'+str(key),alt=alt)
			else:
				alt.append((prefix+'.'+str(key)+'|||'+str(value)))
		return alt

	def md_format(alt,format_alt=''):
		md_title_dict = {}
		#sorted with first key
		for now in alt:
			now = now[1:]
			#fix first key last symbol
			dot = now.split('|||')[0].find('.')
			if dot==-1:
				md_title_dict[now.split('|||')[0]] =[now]
			else:
				if now[0:dot] in md_title_dict.keys():
					(md_title_dict[now[0:dot]]).append(now)
				else:
					md_title_dict[now[0:dot]]=[now]
		for now in md_title_dict.keys():
			format_alt+='### '+now.capitalize()+'\n'+'| key | val |\n| ------ | ------ |\n'
			for let in md_title_dict[now]:
				key,val = let.split('|||')[0],let.split('|||')[1]
				format_alt+='| **' + key + '** | ' + val + ' |\n'
		return format_alt

	def artifact_detect(format_alt):
		artifacts_dict = {}
		artifacts_dict['ip'] = re.findall(r'\d+\.\d+\.\d+\.\d+',format_alt)
		artifacts_dict['url'] =  re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',format_alt)
		artifacts_dict['domain'] = []
		for now in artifacts_dict['url']: artifacts_dict['domain'].append(now.split('//')[1].split('/')[0])
		return artifacts_dict

	def generate_alert(format_alt, artifacts_dict,w_alert):
		#generate alert sourceRef
		sourceRef = str(uuid.uuid4())[0:6]
		artifacts = []
		if 'agent' in w_alert.keys():
			if 'ip' not in w_alert['agent'].keys():
				w_alert['agent']['ip']='no agent ip'
		else:
			w_alert['agent'] = {'id':'no agent id', 'name':'no agent name'}

		for key,value in artifacts_dict.items():
			for val in value:
				artifacts.append(AlertArtifact(dataType=key, data=val))
		alert = Alert(title=w_alert['rule']['description'],
				tlp=2,
				tags=['wazuh',
				'rule='+w_alert['rule']['id'],
				'agent_name='+w_alert['agent']['name'],
				'agent_id='+w_alert['agent']['id'],
				'agent_ip='+w_alert['agent']['ip'],],
				description=format_alt ,
				type='wazuh_alert',
				source='wazuh',
				sourceRef=sourceRef,
				artifacts=artifacts,)
		return alert

	def send_alert(alert, thive_api):
		response = thive_api.create_alert(alert)
		if response.status_code == 201:
			logger.info('Create TheHive alert: '+ str(response.json()['id']))
		else:
			logger.error('Error create TheHive alert: {}/{}'.format(response.status_code, response.text))

	if __name__ == "__main__":

		try:
		logger.debug('debug mode') # if debug enabled
		# Main function
		main(sys.argv)

		except Exception:
		logger.exception('EGOR')
	```
4. Create a bash script as `/var/ossec/integrations/custom-w2thive`. This will properly execute the .py script created in the previous step:
	```bash
	$ sudo nano /var/ossec/integrations/custom-w2thive
	```
	- Set the content below to the bash script and save it:
	```bash
	#!/bin/sh
	# Copyright (C) 2015-2020, Wazuh Inc.
	# Created by Wazuh, Inc. <info@wazuh.com>.
	# This program is free software; you can redistribute it and/or modify it under the terms of GP>

	WPYTHON_BIN="framework/python/bin/python3"

	SCRIPT_PATH_NAME="$0"

	DIR_NAME="$(cd $(dirname ${SCRIPT_PATH_NAME}); pwd -P)"
	SCRIPT_NAME="$(basename ${SCRIPT_PATH_NAME})"

	case ${DIR_NAME} in
		*/active-response/bin | */wodles*)
			if [ -z "${WAZUH_PATH}" ]; then
				WAZUH_PATH="$(cd ${DIR_NAME}/../..; pwd)"
			fi

		PYTHON_SCRIPT="${DIR_NAME}/${SCRIPT_NAME}.py"
		;;
		*/bin)
		if [ -z "${WAZUH_PATH}" ]; then
			WAZUH_PATH="$(cd ${DIR_NAME}/..; pwd)"
		fi

		PYTHON_SCRIPT="${WAZUH_PATH}/framework/scripts/${SCRIPT_NAME}.py"
		;;
		*/integrations)
			if [ -z "${WAZUH_PATH}" ]; then
				WAZUH_PATH="$(cd ${DIR_NAME}/..; pwd)"
			fi

		PYTHON_SCRIPT="${DIR_NAME}/${SCRIPT_NAME}.py"
		;;
	esac


	${WAZUH_PATH}/${WPYTHON_BIN} ${PYTHON_SCRIPT} $@
	```
5. Change files' permissions and ownership:
	```bash
	$ sudo chmod 750 /var/ossec/integrations/custom-w2thive.py
	$ sudo chmod 750 /var/ossec/integrations/custom-w2thive
	$ sudo chown root:wazuh /var/ossec/integrations/custom-w2thive.py
	$ sudo chown root:wazuh /var/ossec/integrations/custom-w2thive
	```
6. Enable the integration in the Wazuh manager configuration file:
	```bash
	$ sudo nano /var/ossec/etc/ossec.conf
	```
	- Set the content below to the configuration file:
	```html
	<ossec_config>
	…
	<integration>
		<name>custom-w2thive</name>
		<hook_url>http://<TheHive_Server_IP>:9000</hook_url>
		<api_key><TheHive_User_API_Key></api_key>
		<alert_format>json</alert_format>
	</integration>
	…
	</ossec_config>
	```
	- Where `<TheHive_Server_IP>` is the IP a
f the TheHive user.
7. Then, restart the Wazuh manager:
	```bash
	$ sudo systemctl restart wazuh-manager
	```
</details>


<!---------- Admyral Integration with Wazuh ---------->
<details>
<summary>
<h3>Admyral integration with Wazuh</h3>
</summary>

Configure **Wazuh** to connect to **Admyral**:

1. First, create a bash script called `custom-admryral` at the `/var/ossec/integrations/` directory. This will properly execute the `custom-admyral.py` script, which will be responsible for the API request:
	```bash
	$ sudo nano /var/ossec/integrations/custom-admyral
	```
	- Set to the bash script the content below and save it:
	```bash
	#!/bin/sh
	# Copyright (C) 2015, Wazuh Inc.
	# Created by Wazuh, Inc. <info@wazuh.com>.
	# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

	WPYTHON_BIN="framework/python/bin/python3"

	SCRIPT_PATH_NAME="$0"

	DIR_NAME="$(cd $(dirname ${SCRIPT_PATH_NAME}); pwd -P)"
	SCRIPT_NAME="$(basename ${SCRIPT_PATH_NAME})"

	case ${DIR_NAME} in
		*/active-response/bin | */wodles*)
			if [ -z "${WAZUH_PATH}" ]; then
				WAZUH_PATH="$(cd ${DIR_NAME}/../..; pwd)"
			fi

			PYTHON_SCRIPT="${DIR_NAME}/${SCRIPT_NAME}.py"
		;;
		*/bin)
			if [ -z "${WAZUH_PATH}" ]; then
				WAZUH_PATH="$(cd ${DIR_NAME}/..; pwd)"
			fi

			PYTHON_SCRIPT="${WAZUH_PATH}/framework/scripts/$(echo ${SCRIPT_NAME} | sed 's/\-/_/g').py"
		;;
		*/integrations)
			if [ -z "${WAZUH_PATH}" ]; then
				WAZUH_PATH="$(cd ${DIR_NAME}/..; pwd)"
			fi

			PYTHON_SCRIPT="${DIR_NAME}/${SCRIPT_NAME}.py"
		;;
	esac

	${WAZUH_PATH}/${WPYTHON_BIN} ${PYTHON_SCRIPT} "$@"
	```
2. Now let's create on the integrations directory the python script `custom-admyral.py`, which will fetch the alert and make the API request to Admyral:
	```bash
	$ sudo nano /var/ossec/integrations/custom-admyral.py
	```
	- Set to the bash script the content below and save it:
	```bash
	# Created by Robson K. Nazareth. <robson.knazareth@gmail.com>.
	# Based on the Shuffle integration using Webhooks
	#
	# This program is free software; you can redistribute it
	# and/or modify it under the terms of the GNU General Public
	# License (version 2) as published by the FSF - Free Software
	# Foundation.

	# Error Codes:
	#   1 - Module requests not found
	#   2 - Incorrect input arguments
	#   3 - Alert File does not exist
	#   4 - Error getting json_alert

	import json
	import os
	import sys
	import time

	# Exit error codes
	ERR_NO_REQUEST_MODULE   = 1
	ERR_BAD_ARGUMENTS       = 2
	ERR_FILE_NOT_FOUND      = 6
	ERR_INVALID_JSON        = 7

	try:
		import requests
		from requests.auth import HTTPBasicAuth
	except ModuleNotFoundError as e:
		print("Module 'requests' not found. To install run: pip install requests")
		sys.exit(ERR_NO_REQUEST_MODULE)

	# Configuration structure on ossec.conf within the <ossec_config> tag
	"""
	<integration>
	<name>custom-admyral</name>
	<hook_url>http://<ADMYRAL_IP>:8000/webhooks/HOOK_ID/HOOK_SECRET </hook_url> <!-- Replace with your Admyral webhook URL -->
	<level>3</level>
	<rule_id>86601</rule_id>
	<alert_format>json</alert_format>
	<options>{"field":"data"}</options> <!-- Replace with your custom JSON object -->
	</integration>
	"""

	# Global vars
	debug_enabled   = False
	pwd             = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
	json_alert      = {}
	SKIP_RULE_IDS   = []

	# Log path
	LOG_FILE        = f'{pwd}/logs/integrations.log'

	# Constants - args[] indexes
	ALERT_INDEX     = 1
	WEBHOOK_INDEX   = 3


	def main(args):
		global debug_enabled
		try:
			# Read arguments
			bad_arguments: bool = False
			if len(args) >= 4:
				msg = '{0} {1} {2} {3} {4}'.format(
					args[1],
					args[2],
					args[3],
					args[4] if len(sys.argv) > 4 else '',
					args[5] if len(sys.argv) > 5 else ''
				)
				debug_enabled = (len(args) > 4 and args[4] == 'debug')
			else:
				msg = '# ERROR: Wrong arguments'
				bad_arguments = True

			# Logging the call
			with open(LOG_FILE, "a") as f:
				f.write(msg + '\n')

			if bad_arguments:
				debug("# ERROR: Exiting, bad arguments. Inputted: %s" % args)
				sys.exit(ERR_BAD_ARGUMENTS)

			# Core function
			process_args(args)

		except Exception as e:
			debug(str(e))
			raise


	def process_args(args) -> None:
		"""
			This is the core function, creates a message with all valid fields
			and overwrite or add with the optional fields

			Parameters
			----------
			args : list[str]
				The argument list from main call

			Raises
			------
			FileNotFoundError
				If no alert file or optional file are presents.
			JSONDecodeError
				If no valid JSON file are used
		"""
		debug("# Running Shuffle script")

		# Read args
		alert_file_location: str     = args[ALERT_INDEX]
		webhook: str                 = args[WEBHOOK_INDEX]
		options_file_location: str   = ''
		json_options: str            = ''

		# Look for options file location
		for idx in range(4, len(args)):
			if(args[idx][-7:] == "options"):
				options_file_location = args[idx]
				break

		# Load options. Parse JSON object.
		json_options = get_json_options(options_file_location)
		debug(f"# Opening options file at '{options_file_location}' with '{json_options}'")

		# Load alert. Parse JSON object.
		json_alert  = get_json_alert(alert_file_location)
		debug(f"# Opening alert file at '{alert_file_location}' with '{json_alert}'")

		debug("# Generating message")
		msg: str = generate_msg(json_alert, json_options)

		# Check if alert is skipped
		if isinstance(msg, str):
			if not msg:
				return

		debug(f"# Sending message {msg} to Admyral server")
		send_msg(msg, webhook)

	def debug(msg: str) -> None:
		"""
			Log the message in the log file with the timestamp, if debug flag
			is enabled

			Parameters
			----------
			msg : str
				The message to be logged.
		"""
		if debug_enabled:
			print(msg)
			with open(LOG_FILE, "a") as f:
				f.write(msg + '\n')


	# Skips container kills to stop self-recursion
	def filter_msg(alert) -> bool:
		# SKIP_RULE_IDS need to be filtered because Shuffle starts Docker containers, therefore those alerts are triggered

		return not alert["rule"]["id"] in SKIP_RULE_IDS


	def generate_msg(alert: any, options: any) -> str:
		"""
			Generate the JSON object with the message to be send

			Parameters
			----------
			alert : any
				JSON alert object.
			options: any
				JSON options object.

			Returns
			-------

			msg: str
				The JSON message to send
		"""
		if not filter_msg(alert):
			print("Skipping rule %s" % alert["rule"]["id"])
			return ""

		level = alert['rule']['level']

		if (level <= 4):
			severity = 1
		elif (level >= 5 and level <= 7):
			severity = 2
		else:
			severity = 3

		msg = {'severity': severity, 'pretext': "WAZUH Alert",
			'title': alert['rule']['description'] if 'description' in alert['rule'] else "N/A",
			'text': alert.get('full_log'),
			'rule_id': alert["rule"]["id"],
			'timestamp': alert["timestamp"],
			'id': alert['id'], "all_fields": alert}

		if(options):
			msg.update(options)

		return json.dumps(msg)

	def send_msg(msg: str, url: str) -> None:
		"""
			Send the message to the API

			Parameters
			----------
			msg : str
				JSON message.
			url: str
				URL of the integration.
		"""
		headers = {'content-type': 'application/json', 'Accept-Charset': 'UTF-8'}
		res     = requests.post(url, data=msg, headers=headers, timeout=10)
		debug("# Response received: %s" % res.json)

	def get_json_alert(file_location: str) -> any:
		"""
			Read JSON alert object from file

			Parameters
			----------
			file_location : str
				Path to the JSON file location.

			Returns
			-------
			{}: any
				The JSON object read it.

			Raises
			------
			FileNotFoundError
				If no JSON file is found.
			JSONDecodeError
				If no valid JSON file are used
		"""
		try:
			with open(file_location) as alert_file:
				return json.load(alert_file)
		except FileNotFoundError:
			debug("# JSON file for alert %s doesn't exist" % file_location)
			sys.exit(ERR_FILE_NOT_FOUND)
		except json.decoder.JSONDecodeError as e:
			debug("Failed getting JSON alert. Error: %s" % e)
			sys.exit(ERR_INVALID_JSON)

	def get_json_options(file_location: str) -> any:
		"""
			Read JSON options object from file

			Parameters
			----------
			file_location : str
				Path to the JSON file location.

			Returns
			-------
			{}: any
				The JSON object read it.

			Raises
			------
			JSONDecodeError
				If no valid JSON file are used
		"""
		try:
			with open(file_location) as options_file:
				return json.load(options_file)
		except FileNotFoundError:
			debug("# JSON file for options %s doesn't exist" % file_location)
		except BaseException as e:
			debug("Failed getting JSON options. Error: %s" % e)
			sys.exit(ERR_INVALID_JSON)

	if __name__ == "__main__":
		main(sys.argv)

	```
3. Change files' permissions and ownership:
	```bash
	$ sudo chmod 750 /var/ossec/integrations/custom-w2thive
	$ sudo chmod 750 /var/ossec/integrations/custom-w2thive.py
	$ sudo chown root:wazuh /var/ossec/integrations/custom-w2thive
	$ sudo chown root:wazuh /var/ossec/integrations/custom-w2thive.py
	```
4. Enable the integration in the Wazuh manager configuration file:
	```bash
	$ sudo nano /var/ossec/etc/ossec.conf
	```
	- Set the content below to the configuration file within the <ossec_config> tag:
	```html
	<ossec_config>
	…
	  <integration>
		<name>custom-admyral</name>
		<hook_url>http://<ADMYRAL_IP>:8000/webhooks/<HOOK_ID>/<HOOK_SECRET> </hook_url>
		<level>3</level>
		<rule_id>86601</rule_id>
		<alert_format>json</alert_format>
	  </integration>
	…
	</ossec_config>
	```
5. Then, restart the Wazuh manager:
	```bash
	$ sudo systemctl restart wazuh-manager
	```
</details>


<!---------- MISP Integration with Wazuh ---------->
<details>
<summary>
<h3>MISP integration with Wazuh</h3>
</summary>

1. Installing MISP:
	1. Update your system:
		```bash
		$ sudo apt update && sudo apt upgrade
		```
	2. Install the client for mysql:
		```bash
		$ sudo apt install mysql-client
		```
	3. Download MISP installation script:
		```bash
		$ wget https://raw.githubusercontent.com/MISP/MISP/2.4/INSTALL/INSTALL.sh
		```
	4. Add execution permission to the script and run it:
		```bash
		$ chmod +x INSTALL.sh
		$ ./INSTALL.sh -A
		```
		- Output:
		```yml
		MISP Installed, access here:

		User: admin@admin.test
		Password: admin
		----------------------------------------------------------------------------------------------
		The following files were created and need either protection or removal (shred on the CLI)
		/home/user/mysql.txt
		Contents:
		Admin (root) DB Password: e8c75d8d78a2e01281b42e2c0d4ac668a333de31c56283cab695a69eb6d31330
		User  (misp) DB Password: 2cf81c7b9bdb0a704785b5da7da106e3ad9a1b04e6d8306fcfbd59d4c9e33d17
		/home/user/MISP-authkey.txt
		Contents:
		Authkey: DMVZLTkH9BOUo7DAX5pKbWaCT8TBFnqd81gnTdgK
		----------------------------------------------------------------------------------------------
		The LOCAL system credentials:
		User: user
		Password: 29fefbbfc917e97504a2eb60f1fd50f3c4ada637b5033c8dcf00736f24908827 # Or the password you used of your custom user
		----------------------------------------------------------------------------------------------
		GnuPG Passphrase is: e9689f40df4b2628bb834c9e53568e4f8efc2d90fb469dfab222cfd28c5ff812
		----------------------------------------------------------------------------------------------
		To enable outgoing mails via postfix set a permissive SMTP server for the domains you want to contact:

		sudo postconf -e 'relayhost = example.com'
		sudo postfix reload
		----------------------------------------------------------------------------------------------
		Enjoy using MISP. For any issues see here: https://github.com/MISP/MISP/issues
		----------------------------------------------------------------------------------------------
		```
	5. Allow connections on port 80 and 443:
		```bash
		$ sudo ufw allow 80/tcp
		$ sudo ufw allow 443/tcp
		```
2. Change admin password:
	1. Browse to https://<"your misp instance ip">/users/login
		- Username: admin@admin.test
		- Password: admin
		- Enter new password
3. Create an organization:
	1. Select **Administration** > **Add Organisations**.
	2. Enter **ORG name** into **Organisation Identifier**.
	3. Select **Generate UUID**.
	4. Select **Submit** at the bottom.

</details>


---------------------------------------------------------------------------------------------


## Suricata Installation on Ubuntu Server

Suricata is an open-source intrusion detection and prevention system that provides real-time network security monitoring and threat detection capabilities. It is designed to protect networks from a wide range of cyber threats and attacks.


<!---------- 1. Suricata installation ---------->
<details>
<summary>
<h3>1. Suricata installation</h3>
</summary>

1. First, install the dependency package, `jq` tool, and add the Suricata PPA repository to Apt:
	```bash
	$ sudo apt install software-properties-common jq
	$ sudo add-apt-repository ppa:oisf/suricata-stable
	$ sudo apt update
	```
2. Then, install the latest stable Suricata:
	```bash
	$ sudo apt install suricata
	```
3. Check Suricata version:
	```bash
	$ sudo suricata --build-info
	```
4. Start Suricata service, enable it to start on-boot, and check its running status:
	```bash
	$ sudo systemctl start suricata
	$ sudo systemctl enable suricata
	$ systemctl status suricata
	```
5. Suricata files and directories:
    1. Suricata configuration file: `/etc/suricata/suricata.yaml`
    2. Suricata pre-defined rules: `/usr/share/suricata/rules`
    3. Suricata default rule path: `/var/lib/suricata/rules`
    5. Suricata log directory: `/var/log/suricata`

</details>


<!---------- 2. Basic setup ---------->
<details>
<summary>
<h3>2. Basic setup</h3>
</summary>

1. To configure Suricata open `suricata.yaml`:
	```bash
	$ sudo nano /etc/suricata/suricata.yaml
	```
	- Set the parameters below and save:
	```yaml
	# Step 1: Inform Suricata about your network
	vars:
		# more specific is better for alert accuracy and performance
		address-groups:
			HOME_NET: "[192.168.57.0/24,10.0.2.0/24]"
	...
	# Step 2: Select outputs to enable
	# Configure the type of alert (and other) logging you would like.
	outputs:
		# Extensible Event Format (nicknamed EVE) event log in JSON format
		- eve-log:
			enabled: yes
			filetype: regular
			filename: eve.json
			pcap-file: false
			community-id: true
			community-id-seed: 0
	...
	# Step 3: configure common capture settings
	# Linux high speed capture support
	af-packet:
		- interface: enp0s8
			cluster-id: 99
			cluster-type: cluster_flow
			defrag: yes
			use-mmap: yes
			tpacket-v3: yes

		- interface: enp0s3
			cluster-id: 98
			cluster-type: cluster_flow
			defrag: yes
			use-mmap: yes
			tpacket-v3: yes
	...
	# Cross platform libcap capture support
	pcap:
		- interface: enp0s8

		- interface: enp0s3
	```
2. Restart Suricata:
	```bash
	$ sudo systemctl restart suricata
	```
</details>


<!---------- 3. Update Suricata Signatures/Rules ---------->
<details>
<summary>
<h3>3. Update Suricata Signatures/Rules</h3>
</summary>

1. Run the default mode which fetches the ET Open ruleset:
	```bash
	$ sudo suricata-update
	```
	- The rules are saved in the `/var/lib/suricata/rules/suricata.rules` file.
	- Always after modify the Suricata config file `suricata.yaml`, restart the Suricata service and run the `suricata-update`.

</details>


<!---------- 4. Running Suricata ---------->
<details>
<summary>
<h3>4. Running Suricata</h3>
</summary>

1. Check the Suricata log to make sure it is running:
	```bash
	$ sudo tail /var/log/suricata/suricata.log
	```
	- The last line should say **Engine started** at the end.
2. Check the `stats.log` file to see statistics:
	```bash
	$ sudo tail -f /var/log/suricata/stats.log
	```
	- By default it is updated every 8 seconds.

</details>


<!---------- 5. Alerting ---------->
<details>
<summary>
<h3>5. Alerting</h3>
</summary>

1. Let's test the IDS functionality of Suricata with the signature with ID 2100498:
	```bash
	alert ip any any -> any any (msg:"GPL ATTACK_RESPONSE id check returned root"; content:"uid=0|28|root|29|"; classtype:bad-unknown; sid:2100498; rev:7; metadata:created_at 2010_09_23, updated_at 2010_09_23;)
	```
	- This will allert on any IP traffic that has the content within its payload.
2. Make sure Suricata service is running:
	```bash
	systemctl status suricata
	```
3. Run the command below to see the updates to `fast.log`.
	```bash
	$ sudo tail -f /var/log/suricata/fast.log
	```
4. In another terminal, run `curl` to trigger the rule:
	```bash
	$ curl http://testmynids.org/uid/index.html
	```
</details>


<!---------- 6. EVE Json ---------->
<details>
<summary>
<h3>6. EVE Json</h3>
</summary>

1. Use `jq` to parse the JSON output:
	1. Display the alerts:
		```bash
		$ sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="alert")'
		```
	2. Display the stats:
		```bash
		$ sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="stats")|.stats.capture.kernel_packets'
		$ sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="stats")'
		```
</details>


<!---------- 7. Suricata files and troubleshooting ---------->
<details>
<summary>
<h3>7. Suricata files and troubleshooting</h3>
</summary>

1. Suricata files and directories:
    1. Default location of the Suricata configuration file: `/etc/suricata/suricata.yaml`
    2. Default Suricata log directory: `/var/log/suricata`
2. Troubleshooting:
    1. Look into the `suricata-start.log` and `suricata.log` files for errors and other events during the suricata startup and operation respectively:
        ```bash
        $ cat /var/log/suricata/suricata-start.log | grep -Pi "error|fail|warn|info"
        $ cat /var/log/suricata/suricata.log | grep -Pi "error|fail|warn|info"
        ```
</details>


<!---------- 8. Suricata docummentaion ---------->
<details>
<summary>
<h3>8. Suricata docummentaion</h3>
</summary>

1. Suricata User Guide:
	- [User Guide](https://docs.suricata.io/en/latest/index.html).
	- [3.2. Binary packages](https://docs.suricata.io/en/latest/install.html#binary-packages)
	- [5.1. Running as a User Other Than Root](https://docs.suricata.io/en/latest/security.html#running-as-a-user-other-than-root)
	- [9.1. Rule Management with Suricata-Update](https://docs.suricata.io/en/latest/rule-management/suricata-update.html) on **Rule Management**.
	- [12.6. Dropping Privileges After Startup](https://docs.suricata.io/en/latest/configuration/dropping-privileges.html) on **Configuration**.
	- [17. Output](https://docs.suricata.io/en/latest/output/index.html)
	- [24.1.3. OPTIONS](https://docs.suricata.io/en/latest/manpages/suricata.html#options) on **Man Pages** > **Suricata**.
3. Suricata-Update 1.3.3 documentation:
	- [Quick Start](https://suricata-update.readthedocs.io/en/latest/quickstart.html)
4. Github:
	- [Evebox](https://github.com/jasonish/evebox)

</details>


---------------------------------------------------------------------------------------------------


## TheHive Installation on Ubuntu Server

TheHive is a collaborative security and incident response platform that enables organizations to manage and investigate security incidents efficiently. It provides a centralized hub for teams to coordinate and track their response efforts. The steps below describe the standalone installation of an instance of TheHive, where everything is on the same server.


<!---------- STEP 1: DEPENDENCIES ---------->
<details>
<summary>
<h3>Step 1: Dependencies</h3>
</summary>

1. Run the command below to install the dependencies if not already installed:
    ```bash
    $ sudo apt install wget gnupg apt-transport-https git ca-certificates ca-certificates-java curl  software-properties-common python3-pip lsb-core
    ```
</details>


<!---------- STEP 2: JAVA VIRTUAL MACHINE ---------->
<details>
<summary>
<h3>Step 2: Java Virtual Machine</h3>
</summary>

Install Java Virtual Machine:

1. Add Corretto repository references:
    ```bash
    $ wget -qO- https://apt.corretto.aws/corretto.key | sudo gpg --dearmor -o /usr/share/keyrings/corretto.gpg
    $ echo "deb [signed-by=/usr/share/keyrings/corretto.gpg] https://apt.corretto.aws stable main" |  sudo tee -a /etc/apt/sources.list.d/corretto.sources.list
    ```
2. Install Java:
    ```bash
    $ sudo apt update
    $ sudo apt install java-common java-11-amazon-corretto-jdk
    ```
3. Set the `JAVA_HOME` environment variable.
    ```bash
    $ echo JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto" | sudo tee -a /etc/environment
    $ export JAVA_HOME="/usr/lib/jvm/java-11-amazon-corretto"
    ```
4. Verify the installation by running:
    ```bash
    $ java -version
    ```
</details>


<!---------- STEP 3: APACHE CASSANDRA ---------->
<details>
<summary>
<h3>Step 3: Apache Cassandra</h3>
</summary>

Apache Cassandra is a scalable and highly available database.

#### Installation

1. Add Apache Cassandra repository references by downloading the repository keys and add the repository to the Apt sources list:
    ```bash
    $ wget -qO -  https://downloads.apache.org/cassandra/KEYS | sudo gpg --dearmor  -o /usr/share/keyrings/cassandra-archive.gpg
    $ echo "deb [signed-by=/usr/share/keyrings/cassandra-archive.gpg] https://debian.cassandra.apache.org 40x main" |  sudo tee -a /etc/apt/sources.list.d/cassandra.sources.list
    ```
2. Install Cassandra package:
    ```bash
    $ sudo apt update
    $ sudo apt install cassandra
    ```
- By default, data is stored at `/var/lib/cassandra`

#### Configuration

1. Configure Cassandra by editing the `/etc/cassandra/cassandra.yaml` file:
    ```bash
    $ sudo nano /etc/cassandra/cassandra.yaml
    ```
    - Set the following parameters:
    ```yml
    cluster_name: 'thehive-db'
    hints_directory: /var/lib/cassandra/hints
    data_file_directories:
        - /var/lib/cassandra/data
    commitlog_directory: /var/lib/cassandra/commitlog
    saved_caches_directory: /var/lib/cassandra/saved_caches
    seed_provider:
        - class_name: org.apache.cassandra.locator.SimpleSeedProvider
        parameters:
            # Ex: "<ip1>,<ip2>,<ip3>"
            - seeds: "127.0.0.1:7000"           # Self for the first node
    listen_address: 127.0.0.1                   # Address for nodes
    rpc_address: 127.0.0.1                      # Address for clients
    ```
    - `cluster_name` helps identify the Cassandra cluster.
    - `listen_address` is the IP address of the node used by other nodes within the cluster to communicate.
    - `rpc_address` is the IP address of the node used by the clients to connect to the Cassandra cluster.
    - In the `seed_provider` the `seed` parameter is the IP address(es) of the seed node(s) in the cluster.
    - The directory paths are for storage of hints, data, commit log, and saved caches.
2. Start and enable Cassandra service:
    ```bash
    $ sudo systemctl start cassandra.service
    $ sudo systemctl enable cassandra.service
    ```
2. To remove existing data and restart Cassandra, run the commands below:
    ```bash
    $ sudo systemctl stop cassandra.service
    $ sudo rm -rf /var/lib/cassandra/*
    $ sudo systemctl start cassandra.service
    $ sudo systemctl status cassandra.service
    ```
- By default, Cassandra listens on the following ports:
    - 7000/tcp (inter-node)
    - 9042/tcp (client)
    - 7199
    - 46315

</details>


<!---------- STEP 4: ELASTICSEARCH ---------->
<details>
<summary>
<h3>Step 4: Elasticsearch</h3>
</summary>

Elasticsearch is a robust data indexing and search engine. It is used by TheHive to manage data indicies efficiently.

#### Installation

1. Add Elasticsearch repository keys and dependency package:
    ```bash
    $ wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch |  sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
    $ sudo apt-get install apt-transport-https
    ```
2. Add the DEB repository of Elasticsearch:
    ```bash
    $ echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/7.x/apt stable main" |  sudo tee /etc/apt/sources.list.d/elastic-7.x.list
    ```
3. Update the package manager and install Elasticsearch package:
    ```bash
    $ sudo apt update
    $ sudo apt install elasticsearch
    ```

#### Configuration

1. Configure Elasticsearch by editing the `/etc/elasticsearch/elasticsearch.yml` file:
    ```bash
    $ sudo nano /etc/elasticsearch/elasticsearch.yml
    ```
    - Set the following parameters:
    ```yml
    # Cluster
    cluster.name: thehive-engine
    http.host: 127.0.0.1
    http.port: 9201
    transport.host: 127.0.0.1
    transport.port: 9301
    ...
    # Paths
    path.logs: "/var/log/elasticsearch"
    path.data: "/var/lib/elasticsearch"
    ...
    thread_pool.search.queue_size: 100000
    xpack.security.enabled: false
    script.allowed_types: "inline,stored"
    ```
2. Create the file below with the custom JVM options:
    ```bash
    nano /etc/elasticsearch/jvm.options.d/jvm.options
    ```
    - Set the following parameters:
    ```yml
    -Dlog4j2.formatMsgNoLookups=true
    -Xms2g
    -Xmx2g
    ```
3. Start and enable Elasticsearch service:
    ```bash
    $ sudo systemctl start elasticsearch
    $ sudo systemctl enable elasticsearch
    $ sudo systemctl status elasticsearch
    ```
4. To remove the existing data and restart Elasticsearch service, run the commands below:
    ```bash
    $ sudo systemctl stop elasticsearch
    $ sudo rm -rf /var/lib/elasticsearch/*
    $ sudo systemctl start elasticsearch
    $ sudo systemctl status elasticsearch
    ```
- Elasticsearch will be listening on the following ports:
    - 9201 (http)
    - 9301

</details>


<!---------- STEP 5: FILE STORAGE ---------->
<details>
<summary>
<h3>Step 5: File storage</h3>
</summary>

1. To store files on the local filesystem, start by choosing the dedicated folder (by default `/opt/thp/thehive/files`):
    ```bash
    $ sudo mkdir -p /opt/thp/thehive/files
    ```
    - This path will be utilized in the configuration of TheHive.
2. After installing TheHive, ensure the user thehive owns the chosen path for storing files:
    ```bash
    $ sudo chown -R thehive:thehive /opt/thp/thehive/files
    $ ls -lh /opt/thp/thehive/
    ```
</details>


<!---------- STEP 6: THEHIVE ---------->
<details>
<summary>
<h3>Step 6: TheHive</h3>
</summary>

TheHive is a scalable Security Incident Response Platform integrated with MISP (Malware Information Sharing Platform) for promptly investigating and addressing security incidents.

#### Installation

1. Add the TheHive repository keys and the repository to the Apt sources list::
    ```bash
    $ wget -O- https://archives.strangebee.com/keys/strangebee.gpg | sudo gpg --dearmor -o /usr/share/keyrings/strangebee-archive-keyring.gpg
    $ echo 'deb [signed-by=/usr/share/keyrings/strangebee-archive-keyring.gpg] https://deb.strangebee.com thehive-5.3 main' | sudo tee -a /etc/apt/sources.list.d/strangebee.list
    ```
2. Update the package manager and install the TheHive package:
    ```bash
    $ sudo apt update
    $ sudo apt install thehive
    ```

#### Configuration

1. Configure TheHive by editing the `/etc/thehive/application.conf` file:
    ```bash
    $ sudo nano /etc/thehive/application.conf
    ```
    - Set the following parameters:
    ```yml
    # Cassandra and Elasticsearch configuration
    db.janusgraph {
        storage {
            backend = cql
            hostname = ["127.0.0.1"]
            cql {
                cluster-name = thehive-db
                keyspace = thehive
            }
        }
        index.search {
            backend = elasticsearch
            hostname = ["127.0.0.1:9201"]
            index-name = thehive-engine
    # Attachment storage configuration
    storage {
        provider = localfs
        localfs.location = /opt/thp/thehive/files
    }
    # Service configuration
    application.baseUrl = "http://0.0.0.0:9000"
    play.http.context = "/"
    # Additional modules
    scalligraph.modules += org.thp.thehive.connector.cortex.CortexModule
    scalligraph.modules += org.thp.thehive.connector.misp.MispModule
    ```
2. Ensure thehive user has permissions on the default file storage location:
    ```bash
    $ ls -lhd /opt/thp/thehive/files
    ```
    - Otherwise change the directory ownership:
    ```bash
    $ chown -R thehive:thehive /opt/thp/thehive/files
    ```
3. Start and enable TheHive:
    ```bash
    $ sudo systemctl start thehive
    $ sudo systemctl enable thehive
    $ systemctl status thehive
    ```
</details>


<!---------- STATUS CHECK ---------->
<details>
<summary>
<h3>Status check</h3>
</summary>

Check if Cassandra, Elasticsearch, and TheHive services are running:
```bash
$ systemctl status cassandra
$ systemctl status elasricsearch
$ systemctl status thehive
```
**Note:** Any modification on the configuration file of Cassandra, Elasticsearch, or TheHive should follow a reset of the three services with TheHive last.

</details>


<!---------- TROUBLESHOOTING ---------->
<details>
<summary>
<h3>Troubleshooting</h3>
</summary>

1. Check possible issues reported in the Cassandra log file:
    ```bash
    $ cat /var/log/cassandra/system.log | grep -E "ERROR|Caused"
    ```
2. Check possible issues reported in the Elasticsearch log file:
    ```bash
    $ sudo cat /var/log/elasticsearch/<cluster-name>.log | grep -E "ERROR|Caused"
    ```
3. Check possible issues reported in the TheHive log file:
    ```bash
    $ sudo cat /var/log/thehive/applicatin.log | grep -E "ERROR|Caused"
    ```
</details>


<!---------- TheHive Create Organization and User Accounts ---------->
<details>
<summary>
<h3>TheHive Create Organization and User Accounts</h3>
</summary>

Sign in into TheHive.

### Create Organisation

1. Go to **Organisations** and click on the **plus sign** to create one if you already don't have one.
	1. Fill the fields on **Adding an Organisation**.
		- **Name:** JAHWS
		- **Description:** SOC Automation Project
		- **Tasks sharing rule:** manual
		- **Observables sharing rule:** manual
	2. Then, click **Confirma**.

### Create User Accounts

1. On **Organisations**, click on the organization name.
2. On the organisaton page, under **Users** click on the **plus sign** to add an user.
	1. Fill the fields on **Adding a User**
		- **Type:** Normal
		- **Organisation:** JASHWS
		- **Login:** user1@jah.com
		- **Name:** User1
		- **Profile:** Analyst
	2. Then, click **Confirm**.
3. To add a second user, click on the **plus sign** again user **Users**.
	1. Fill the fields on **Adding a User**
		- **Type:** Service
		- **Organisation:** JASHWS
		- **Login:** shuffle@jah.com
		- **Name:** User Shuffle
		- **Profile:** Analyst
	2. Then, click **Confirm**.

</details>


---------------------------------------------------------------------------------------------------


## Docker Installation on Ubuntu Server

Docker Engine is an open source containerization technology for building and containerizing applications, which acts as a client-server application.


<!-- Installation -->
<details>
<summary>
<h3>Installation</h3>
</summary>

1. Install dependencies:
	```bash
	$ $ sudo apt-get install apt-transport-https ca-certificates curl software-properties-common
	```
2. Add the Docker repository:
	```bash
	$ curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
	$ echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
	```
2. Install Docker Community Edition:
	```bash
	$ sudo apt update
	$ sudo apt install docker-ce
	```
3. Start and enable Docker service:
	```bash
	$ sudo systemctl start docker
	$ sudo systemctl enable docker
	```
4. Check the installation by verifying the Docker version:
	```bash
	$ docker --version
	```
5. Test Docker by running the "Hello, World!" container:
	```bash
	$ sudo docker run hello-world
	```
6. (TODO) Permissions:

</details>

---------------------------------------------------------------------------------------------------


## (TODO - update to new version) Admyral Installation on Ubuntu Server using Docker

Admyral is an open-source Cybersecurity Automation & Investigation Assistant powered by AI.


<!-- Installation -->
<details>
<summary>
<h3>Installation</h3>
</summary>

1. Clone the repository:
    ```bash
    $ git clone https://github.com/Admyral-Security/admyral.git
    ```

2. Change directory to docker self-hosting:
    ```bash
    $ cd admyral/deploy/self-hosting
    ```

3. Copy and edit the env vars:
    ```bash
    $ cp .env.example .env
    $ nano .env
    ```
    - Set the parameters below:
    ```yaml
    ADMYRAL_SITE_URL="http://192.168.57.3:3000"
    ASMYRAL_WORKFLOW_RUNNER_API_URL="http://192.168.57.3:5000"
    SUPABASE_URL="http://192.168.57.3:8000"
    ```
4. Edit the docker-compose.yml file:
	```bash
	$ nano docker-compose.yml
	```
	- Set the parameters below:
	```yml
    services:
    	workflow-runner:
    		# Image requested linux/amd64
    		image: admyralai/workflow-runner:latest
    		# Use image for linux/amd64 platform

        web:
            healthcheck:
                test:
                    [
                        ...
                        # Use IP address instead of domain name
                        "http://127.0.0.1:3000/health"
                    ]
        studio:
            healthcheck:
                test:
                    [
                        ...
                        '"require(''http'').get(''http://'' + process.env.HOSTNAME + '':3000/api/profile'', (r) => {if (r.statusCode !== 200) throw new Error(r.statusCode)})"'
					]
				timeout: 15s
		storage:
			healthcheck:
					[
						...
						# Use IP address instead of domain name
						"http://127.0.0.1:5000/status"
					]
	```
4. Start the services in detached mode, then list all containers:
    ```bash
    $ sudo docker compose up -d
    $ sudo docker ps -a
    ```
5. If it fails, restart the containers running the command below:
    ```bash
    $ sudo docker compose restart
    ```
</details>


<!-- Install Admyral using pip -->
<details>
<summary>
<h3>Install Admyral using pip</h3>
</summary>

### Step 1: Installing and Starting Admyral

1. Install Admyrall using pip and Python 3.12:
	```bash
	python3.12 -m pip install admyral
	```
2. Start Admyral:
	```bash
	admyral up
	```
### Step 2: Tool and Secret Setup

</details>


<!-- Troubleshooting -->
<details>
<summary>
<h3>Troubleshooting</h3>
</summary>

1. Install Python 3.12 and pip for python 3.12
	```BASH
	sudo apt update && sudo apt upgrade
	sudo apt install software-properties-common
	sudo add-apt-repository ppa:deadsnakes/ppa
	sudo apt update
	sudo apt install python3.12
	sudo python3.12 --version
	curl -sS https://bootstrap.pypa.io/get-pip.py | python3.12
	python3.12 -m pip --version
	```
2. AttributeError: module 'lib' has no attribute 'X509_V_FLAG_NOTIFY_POLICY'. Did you mean: 'X509_V_FLAG_EXPLICIT_POLICY'?
	- Solution: Upgrade the latest version of PyOpenSSL.
		```bash
		python3.12 -m pip install pip --upgrade
		python3.12 -m pip install pyopenssl --upgrade
		```
</details>


<!-- References -->
<details>
<summary>
<h3>References</h3>
</summary>

- GitHub: https://github.com/Admyral-Security/admyral
- How to contribute: https://github.com/Admyral-Security/admyral/blob/main/CONTRIBUTING.md
- Cloud Version: https://admyral.dev/login
- Discord: https://discord.gg/GqbJZT9Hbf

</details>


---------------------------------------------------------------------------------------------------


## DVWA Installation on Debian

DVWA (Damn Vulnerable Web Application) is a web application designed to help security professionals test their skills and tools in a legal environment. It contains various vulnerabilities for users to exploit and practice their penetration testing techniques.


<!-- Step 1: Download and configure DVWA -->
<details>
<summary>
<h3>Step 1: Download and configure DVWA</h3>
</summary>

1. Change your directory to `/var/www/html`:
	```bash
	$ cd /var/www/html
	```
2. Clone the DVWA GitHub repository:
	```bash
	$ sudo git clone https://github.com/digininja/DVWA
	```
3. Rename `DVWA` to `dvwa`:
	```bash
	$ sudo mv DVWA dvwa
	```
4. Grant full permissions (read, write, execute) to all users for the DVWA directory and its contents:
	```bash
	$ sudo chmod -R 777 dvwa/
	```
5. To set up the user and password required to access the databasase, change to the config directory:
	```bash
	$ cd dvwa/config
	```
6. Create a copy of the original file containing the default configurations:
	```bash
	$ sudo cp config.inc.php.dist config.inc.php
	```
7. Open the created file using a text editor:
	```bash
	$ sudo nano config.inc.php
	```
	- Set the server address, database name, username, and password as shown below, then save it:
	```bash
	# If you are using MariaDB then you cannot use root, you must use create a dedicated DVWA user.
	#   See README.md for more information on this.
	$_DVWA = array();
	$_DVWA[ 'db_server' ]   = '127.0.0.1';
	$_DVWA[ 'db_database' ] = 'dvwa';
	$_DVWA[ 'db_user' ]     = 'admin';
	$_DVWA[ 'db_password' ] = 'password';
	$_DVWA[ 'db_port']      = '3306';
	```
</details>


<!-- Step 2: Install and configure MySQL Server -->
<details>
<summary>
<h3>Step 2: Install and configure MySQL Server</h3>
</summary>

1. Run the command below to install the mysql-server:
	```bash
	$ sudo apt install default-mysql-server
	```
2. Start the MySQL service and check if it is running with the commands below:
	```bash
	$ sudo systemctl start mysql
	$ sudo systemctl status mysql
	```
3. Login as root to the MySQL database using the command below:
	```bash
	$ sudo mysql -u root -p
	```
4. Create a new user with the same credentials set in the DVWA configuration file earlier:
	```sql
	MariaDB [(none)]> create user 'admin'@'127.0.0.1' identified by 'password';
	```
5. Grant this new user privilege over the dvwa database with the command below:
	```sql
	MariaDB [(none)]> grant all privileges on dvwa.* to 'admin'@'127.0.0.1' identified by 'password';
	```
6. Type `exit` to close the database.

</details>


<!-- Step 3: Install PHP and configure Apache Server -->
<details>
<summary>
<h3>Step 3: Install PHP and configure Apache Server</h3>
</summary>

1. First, update the system and add the SURY PHP PPA repository running the commands below:
	```bash
	$ sudo apt update
	$ sudo apt -y install lsb-release apt-transport-https ca-certificates
	$ sudo wget -O /etc/apt/trusted.gpg.d/php.gpg https://packages.sury.org/php/apt.gpg
	$ echo "deb https://packages.sury.org/php/ $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/php.list
	```
2. Now, use the commands below to install PHP 7.4:
	```bash
	$ sudo apt update
	$ sudo apt install php7.4 -y
	$ php -v
	```
3. To install additional PHP extensions, run the command below:
	```bash
	$ sudo apt install php7.4-{cli,json,imap,bcmath,bz2,intl,gd,mbstring,mysql,zip}
	```
4. To configure the server, change the directory using the command below:
	```bash
	$ cd /etc/php/7.4/apache2
	```
5. Open the `php.ini` file with a text editor:
	```bash
	$ sudo nano php.ini
	```
	- Search for the `allow_url_fopen` and `allow_url_include` and set them to `On`:
	```bash
	; Whether to allow the treatment of URLs (like http:// or ftp://) as files.
	; http://php.net/allow-url-fopen
	allow_url_fopen = On

	; Whether to allow include/require to open URLs (like http:// or ftp://) as files.
	; http://php.net/allow-url-include
	allow_url_include = On
	```
6. Restart the Apache server and check its status using the commands below:
	```bash
	$ sudo systemctl restart apache2
	$ sudo systemctl status apache2
	```
</details>


<!-- Step 4: Access DVWA on your browser -->
<details>
<summary>
<h3>Step 4: Access DVWA on your browser</h3>
</summary>

1. From the host machine, open your browser and enter the URL `http://192.168.57.4/dvwa/setup.php`.
2. Click on **Create / Reset Database** at the bottom, then you will be redirected to the login page.
3. At the login page, log in using the credentials created earlier, and everything should be up and running.

</details>


<!-- Troubleshooting -->
<details>
<summary>
<h3>Troubleshooting</h3>
</summary>

1. Look at the error log file:
	```bash
	$ nano /var/log/apache2/error.log
	```
</details>


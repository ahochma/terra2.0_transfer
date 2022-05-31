# Terra Transfer

This SDK provides an automatic and a CLI version to transfer Terra 2.0 Luna to a specific address.
## Requirements
Install dependencies:
```
pip install -r req.txt
```
Run the certificate.py with your python alias (python / python3), using **sudo**. For example:
```
sudo python certificate.py
```
​
## Configuration
### CLI
The CLI tool (transfer_cli.py) will only require to set up an API user and configure its corresponding API key and relevant 
private key location. The rest of the information will be put through the programs prompts.
​
### Automatic Transfer
In addition to the configuration mentioned above, the below will be required as well:
* A list of vaults to transfer from. These will be identified through the vault ID, as a string. For example:
```
SOURCE_VAULTS = ["24", "0"] 
```
* Destination, a single address, stored as a string. For example:
```
DESTINATION = "terra123123123123123123123123123123123123123"
```
* Memo for all transactions:
```
MEMO = "FBFBFBFBFBFBFBFB"

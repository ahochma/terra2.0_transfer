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

### There are 2 scripts that can be used: transfer_cli.py and transfer_auto.py

### CLI
The CLI script (transfer_cli.py) is an interactive scripts that prompts for the required inputs.
It will require to set up an API user and configure its corresponding API key and relevant 
private key location. The required parameters that should be updated in the script are:
```
API_KEY
API_SECRET
```
​
### Automatic Transfer
The automatic script does not have an interactive interface and in addition to the configuration mentioned aboverequires to update the script with the following parameters:
```
SOURCE_VAULTS - list of source vault accounts. For example - SOURCE_VAULTS = ["24", "0"] 
DESTINATION - the destination to move the funds out to. For example - DESTINATION = "terra123123123123123123123123123123123123123"
MEMO - if the destination wallet requires a MEMO, esle leave empty string. For example - MEMO = "FBFBFBFBFBFBFBFB"
```
### To execute either of the scripts please run after updating the relevant script with all the parameters mentioned in the above:
```
python transfer_cli.py OR python transfer_auto.py
```

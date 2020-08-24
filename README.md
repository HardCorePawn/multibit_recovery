# multibit_recovery
* A couple of simple Python scripts that help with recovering funds from "broken" MultiBit HD and MultiBit Classic wallets due to the "Password did not unlock the wallet" issue

* Based upon the incredibly useful ["decrypt_bitcoinj_seed" by Christopher Gurnee](https://github.com/gurnec/decrypt_bitcoinj_seed)

## Warning ##

Some of these scripts extract unencrypted Private Keys from your Wallet file or Key Backup. If you are uncertain whether or not your computer is completely free of malware, you should not run this nor any other program that can affect your finances.

Even if you are certain you are currently free of malware, it is strongly advised that you not store unencrypted private keys to your hard drive.

## Installation ##

Just download the latest version from https://github.com/HardCorePawn/multibit_recovery/archive/master.zip and unzip it to a location of your choice. There’s no installation procedure for the actual Python scripts, however there are additional requirements below.

### Windows ###

*NOTE: wll probably not work properly with Python 3... make sure you're using Python 2!*

 * Python 2.7 – visit the download page here: <https://www.python.org/downloads/windows/>, and click the link for the latest Python 2 release. Download and run either the `Windows x86 MSI installer` for the 32-bit version of Python, or the `Windows x86-64 MSI installer` for the 64-bit one. If you're unsure which one is compatible with your PC, choose the 32-bit one.
 * Google Protobuf and pylibscrypt for Python and bitcoin – choose *one* of the following two installation methods:
     * Automated installation: right-click on the included *install-windows-requirements.ps1* file and choose *Run with Powershell*. Automated installation typically only works with Windows Vista SP1 and higher (including Windows 7+), but it doesn't hurt to try with other versions of Windows.
     * Manual installation:
         1. You must have Python 2.7.9 or later (or you must [manually install Python pip](https://pip.pypa.io/en/latest/installing.html#install-pip)).
         2. Open a command prompt (Start -> Run, type `cmd` and click OK).
         3. Type this at the command prompt: `C:\Python27\Scripts\pip install protobuf pylibscrypt bitcoin`, and then press the `Enter` key.

### Linux ###

* This project has NOT been tested on Linux... I have no idea if it will work. You can try following the Linux install instructions for ["decrypt_bitcoinj_seed" by Christopher Gurnee](https://github.com/gurnec/decrypt_bitcoinj_seed)
* Let me know if it works! ;)

As [suggested by Matthew Pilsbury](https://github.com/HardCorePawn/multibit_recovery/issues/7) you can try:
>To install dependencies:
>`pip install protobuf pylibscrypt bitcoin `
> 
>To execute:
>`python2 find_unspent_multibitHD_txes.py mbhd.wallet.aes `


## How to Use ##

### find_unspent_multibitHD_txes.py ###

Copy your "broken" MultiBit HD wallet file (%appdata%/MulitBitHD/mbhd-\<GUID>/mbhd.wallet.aes) into the folder where you extracted multibit_recovery scripts. Open a commandline at the folder where you extracted the scripts and then run the script:
* `python find_unspent_multibitHD_txes.py mbhd.wallet.aes`

Enter your wallet password and a list of Transactions in the wallet UNSPENT pool should be output along with Addresses and Amounts.

The script will then look through the first 1000 addresses/keys on the m/0'/0 (Receive Addresses) and m/0'/1 (Change Addresses) Derivation Paths. If it there is a match for an address from a transaction in the UNSPENT pool, it will dump the Address and Private Key (in "WIF Compressed" format).

Please note that some MultiBitHD wallet files may take several minutes to decrypt (if you don't have [one of the optional libraries](https://pypi.python.org/pypi/pylibscrypt#requirements) installed).

### decrypt_multibit_classic_keys.py

Find your Key Backup (%appdata%/MultiBit/multibit-data/key-backup/multibit-\<DATETIMESTAMP>.key) and copy it to the folder where you extracted multibit_recovery scripts. Open a commandline at the folder where you extracted the scripts and then run the script:
* `python decrypt_multibit_classic_keys.py multibit-\<DATETIMESTAMP>.key`

Enter your wallet password and an unencrypted list of all your private keys should be output. Go and import them into another wallet like [Electrum](https://electrum.org/) ;)

### decrypt_multibit_classic_walletkeys.py

If you don't have a Key Backup, then use this script to extract the keys directly from the .wallet file. Copy your multibit.wallet file to the folder where you extracted multibit_recovery scripts. Open a commandline at the folder where you extracted the scripts and then run the script:
* `python decrypt_multibit_classic_walletkeys.py multibit.wallet`

Enter your wallet password (if wallet was password protected) and an unencrypted list of all your Public and Private Keys should be output. Go and import them into another wallet like [Electrum](https://electrum.org/) ;)

## Credits ##

* Borrowed heavily from the incredibly useful ["decrypt_bitcoinj_seed" by Christopher Gurnee](https://github.com/gurnec/decrypt_bitcoinj_seed)

* [mocaccino](http://www.mocacinno.com/) - for helping me work out the BIP32 Derivation Path stuff

Third-party libraries distributed with multibit_recovery include:

 * aespython, please see [aespython/README.txt](aespython/README.txt) for
 more information

 * bitcoinj wallet protobuf, please see [wallet.proto](wallet.proto)
 for more information

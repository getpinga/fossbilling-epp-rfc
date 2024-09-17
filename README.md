# Compatibility

This module is designed for use with:

- Any Generic RFC EPP registry.

- Caucasus Online - .ge

- CentralNic - all

- CoCCA - all

- CORE/Knipp - all

- GoDaddy Registry - all

- Google Nomulus - all

- HKIRC - .hk

- Identity Digital - all

- RoTLD - .ro

- RyCE - all

- SIDN - all

- ZADNA - .za

- ZDNS - .all

# FOSSBilling Module Installation instructions

## 1. Download and Install FOSSBilling:

Start by downloading the latest version of FOSSBilling from the official website (https://fossbilling.org/). Follow the instructions below to install it, or run for automated installation:

```bash
wget https://raw.githubusercontent.com/getpinga/fossbilling-epp-rfc/main/install_epp_module.sh -O install_epp_module.sh && chmod +x install_epp_module.sh && ./install_epp_module.sh
```

## 2. Installation and Configuration of Registrar Adapter:

First, download this repository which contains the epp.php file. After successfully downloading the repository, move the epp.php file into the `[FOSSBilling]/library/Registrar/Adapter` directory.

Next, rename `epp.php` as `YourRegistryName.php`. Please ensure to replace "**YourRegistryName**" with the actual name of your registry.

Proceed to open the newly renamed file and locate the phrase "**Registrar_Adapter_EPP**". Replace it with "**Registrar_Adapter_YourRegistryName**".

## 3. Addition of Synchronization Script:

There is one additional script in the repository: **eppSync.php**. It needs to be placed in the main `[FOSSBilling]` directory.

Rename `eppSync.php` to `YourRegistryNameSync.php`.

Edit `eppSync.php` and replace **Epp** in the line `$registrar = "Epp";` with the name of your registry provided in step 2.

## 4. Setting Up the Cron Job:

You need to set up a cron job that runs the sync module twice a day. Open crontab using the command `crontab -e` in your terminal.

Add the following cron job:

`0 0,12 * * * php /var/www/html/YourRegistryNameSync.php`

This command schedules the synchronization script to run once every 12 hours (at midnight and noon).

## 5. Activate the Domain Registrar Module:

Within FOSSBilling, go to **System -> Domain Registration -> New Domain Registrar** and activate the new domain registrar.

## 6. Registrar Configuration:

Next, head to the "**Registrars**" tab. Here, you'll need to enter your specific configuration details, including the path to your SSL certificate and key.

## 7. Adding a New TLD:

Finally, add a new Top Level Domain (TLD) using your module from the "**New Top Level Domain**" tab. Make sure to configure all necessary details, such as pricing, within this tab.

# Troubleshooting

If you experience problems connecting to your EPP server, follow these steps:

1. Ensure your server's IP (IPv4 and IPv6) is whitelisted by the EPP server.

2. Confirm your client and server support IPv6 if required. If needed, disable IPv6 support in EPP server.

3. Reload the EPP module or restart the web server after any changes.

4. Ensure certificates have the correct permissions: `chown www-data:www-data cert.pem` and `chown www-data:www-data key.pem`.

5. Verify the EPP module is configured with the chosen registrar prefix.
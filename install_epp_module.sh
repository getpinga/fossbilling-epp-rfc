#!/bin/bash

# Function to make a string filename safe
sanitize_filename() {
    echo "$1" | tr -cd '[:alnum:]_-' 
}

# Ask for registry name
echo "Enter the name of the registry you are installing this module for:"
read -r registry_name
safe_registry_name=$(sanitize_filename "$(echo "$registry_name" | sed -E 's/^(.)/\U\1/')") 

# Ask for FOSSBilling directory
echo "Enter the path to the FOSSBilling directory (default is /var/www):"
read -r fossbilling_path
fossbilling_path=${fossbilling_path:-/var/www}

# Clone the repository to /tmp
git clone https://github.com/getpinga/fossbilling-epp-rfc /tmp/fossbilling-epp-rfc

# Rename and move the epp.php file
mv /tmp/fossbilling-epp-rfc/epp.php "$fossbilling_path/library/Registrar/Adapter/${safe_registry_name}.php"

# Edit the newly copied file
sed -i "s/Registrar_Adapter_EPP/Registrar_Adapter_${safe_registry_name}/g" "$fossbilling_path/library/Registrar/Adapter/${safe_registry_name}.php"

# Move and rename eppSync.php
mv /tmp/fossbilling-epp-rfc/eppSync.php "$fossbilling_path/${safe_registry_name}Sync.php"

# Check if eppClient.php exists and move if not
if [ ! -f "$fossbilling_path/eppClient.php" ]; then
    mv /tmp/fossbilling-epp-rfc/eppClient.php "$fossbilling_path/"
fi

# Edit the renamed eppSync.php
sed -i "s/\$registrar = \"Epp\";/\$registrar = \"${safe_registry_name}\";/g" "$fossbilling_path/${safe_registry_name}Sync.php"

# Add the cron job
(crontab -l 2>/dev/null; echo "0 0,12 * * * php $fossbilling_path/${safe_registry_name}Sync.php") | crontab -

# Clean up
rm -rf /tmp/fossbilling-epp-rfc

# Final instructions
echo "Installation complete."
echo ""
echo "1. Activate the Domain Registrar Module:"
echo "Within FOSSBilling, go to System -> Domain Registration -> New Domain Registrar and activate the new domain registrar."
echo ""
echo "2. Registrar Configuration:"
echo "Next, head to the 'Registrars' tab. Here, you'll need to enter your specific configuration details, including the path to your SSL certificate and key."
echo ""
echo "3. Adding a New TLD:"
echo "Finally, add a new Top Level Domain (TLD) using your module from the 'New Top Level Domain' tab. Make sure to configure all necessary details, such as pricing, within this tab."
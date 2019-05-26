SCAN_TIME=60

echo "Switching to Monitor mode..."
sudo airmon-ng start wlan0

echo "60 Second scan..."
sudo tshark -i wlan0mon -a duration:$SCAN_TIME -w last.pcap -F pcap

echo "Anlayzing and sending to server"
python ./prober-service.py

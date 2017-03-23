#	api.macvendors.com


##	Information

-	Listens on port 80/443

##	Installation

### Create API binary
```
go build
sudo mv [binary_name] /opt/macvendors
```

### Open port 80 and 443 via UFW
```
sudo ufw allow http/tcp
sudo ufw allow https/tcp
```

### Give binary permissions to bind to port 80/443
```
setcap 'cap_net_bind_service=+ep' /opt/macvendors
```

### Configure systemd to autorun api
- Create /lib/systemd/system/macvendors.service
```
[Unit]
Description=api.macvendors.com http server

[Service]
ExecStart=/opt/macvendors
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

- Enable and start new service
```
sudo systemctl enable macvendors.service
sudo systemctl start macvendors.service
```

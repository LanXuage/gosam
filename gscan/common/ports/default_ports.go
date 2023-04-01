package ports

import "github.com/google/gopacket/layers"

func GetDefaultPorts() []layers.TCPPort {
	return []layers.TCPPort{
		layers.TCPPort(DEFAULT_DB2),
		layers.TCPPort(DEFAULT_DB2),
		layers.TCPPort(DEFAULT_ELASTICSEARCH),
		layers.TCPPort(DEFAULT_FTP),
		layers.TCPPort(DEFAULT_MONGODB),
		layers.TCPPort(DEFAULT_MYSQL),
		layers.TCPPort(DEFAULT_MYSQL),
		layers.TCPPort(DEFAULT_ORACLE),
		layers.TCPPort(DEFAULT_WEBLOGIC),
		layers.TCPPort(DEFAULT_REDIS),
		layers.TCPPort(DEFAULT_SMB),
		layers.TCPPort(DEFAULT_SQLSERVER),
		layers.TCPPort(DEFAULT_WEB),
		layers.TCPPort(DEFAULT_WEB_HTTPS),
	}
}

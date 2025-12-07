package commons

import "fmt"

func GetVendor(mac MACAddress) string {
	oui := fmt.Sprintf("%02X:%02X:%02X", mac[0], mac[1], mac[2])

	vendors := map[string]string{
		"00:50:56": "VMware",
		"00:0C:29": "VMware",
		"00:1C:42": "Parallels",
		"08:00:27": "VirtualBox",
		"AC:DE:48": "Apple",
		"00:1B:63": "Apple",
		"FC:FC:48": "Apple",
		"B8:27:EB": "Raspberry Pi",
		"DC:A6:32": "Raspberry Pi",
		"E4:5F:01": "Raspberry Pi",
		"00:1A:79": "HP",
		"00:24:81": "HP",
		"D4:3D:7E": "Amazon (Echo/FireTV)",
		"CC:9E:A2": "Google (Chromecast)",
		"18:B4:30": "Nest Labs",
		"A0:20:A6": "TP-Link",
		"50:C7:BF": "TP-Link",
		"00:1D:0F": "Dell",
		"D0:67:E5": "Dell",
		"00:50:F2": "Microsoft",
		"00:15:5D": "Microsoft (Hyper-V)",
		"E8:50:8B": "Samsung",
		"34:C3:AC": "Samsung",
		"5C:0A:5B": "Samsung",
		"78:1F:DB": "Samsung",
		"84:38:38": "Samsung",
		"D0:C5:F3": "Samsung",
		"F4:7B:5E": "Samsung",
		"2C:0E:3D": "Samsung",
	}

	if vendor, found := vendors[oui]; found {
		return vendor
	}

	return "Unknown"
}

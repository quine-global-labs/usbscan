// usbscan merges three independent views of USB state into one table:
//
//   - lsusb:        devices the kernel fully enumerated.
//   - sysfs ports:  every hub port (root and nested), including ones that
//     never finished enumeration (e.g. tripped over-current protection
//     before the device got an address, so lsusb/udev never saw it).
//   - journalctl -k: recent kernel fault lines, attributed back to the
//     port that logged them.
//
// Ports are the join key: a device, if enumerated, hangs off a specific
// port, and a fault line names the port directly.
package main

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type usbDevice struct {
	vendorID, productID string
	desc                string
}

type portRow struct {
	port        string
	connectType string
	overCurrent int
	state       string
	busDevKey   string // "003:009", empty if nothing attached
}

type faultInfo struct {
	count    int
	lastLine string
}

func main() {
	sinceFlag := "-10 min"
	if len(os.Args) > 1 {
		sinceFlag = "-" + strings.TrimPrefix(os.Args[1], "-")
	}

	devices := readLsusbTable()
	ports := readPortTable("/sys/devices")
	faults := readFaultTable(sinceFlag, ports)

	keys := make([]string, 0, len(ports))
	for k := range ports {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	fmt.Printf("%-16s %-10s %-9s %-12s %-42s %s\n",
		"PORT", "CONNECT", "OC_COUNT", "STATE", "DEVICE", "RECENT FAULTS")
	for _, k := range keys {
		p := ports[k]

		dev := "-"
		if p.busDevKey != "" {
			if d, ok := devices[p.busDevKey]; ok {
				dev = fmt.Sprintf("%s:%s %s", d.vendorID, d.productID, d.desc)
			} else {
				dev = p.busDevKey // enumerated per sysfs but lsusb didn't list it
			}
		}

		flt := "-"
		if f, ok := faults[k]; ok {
			flt = fmt.Sprintf("x%d (%s)", f.count, f.lastLine)
		}

		marker := ""
		if p.overCurrent > 0 {
			marker = fmt.Sprintf(" <-- OVER-CURRENT x%d", p.overCurrent)
		}

		fmt.Printf("%-16s %-10s %-9d %-12s %-42s %s%s\n",
			p.port, p.connectType, p.overCurrent, p.state, dev, flt, marker)
	}
}

// readLsusbTable is the "lsusb" source: devices the kernel fully enumerated.
func readLsusbTable() map[string]usbDevice {
	out := make(map[string]usbDevice)
	data, err := exec.Command("lsusb").Output()
	if err != nil {
		return out
	}
	re := regexp.MustCompile(`^Bus (\d+) Device (\d+): ID ([0-9a-fA-F]{4}):([0-9a-fA-F]{4})\s*(.*)$`)
	for _, line := range strings.Split(string(data), "\n") {
		m := re.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		bus, _ := strconv.Atoi(m[1])
		dev, _ := strconv.Atoi(m[2])
		key := fmt.Sprintf("%03d:%03d", bus, dev)
		out[key] = usbDevice{vendorID: m[3], productID: m[4], desc: strings.TrimSpace(m[5])}
	}
	return out
}

var portNumRe = regexp.MustCompile(`port(\d+)$`)

// readPortTable is the "sysfs ports" source: every hub port on the system,
// including ones with nothing successfully enumerated on them.
func readPortTable(root string) map[string]portRow {
	out := make(map[string]portRow)
	filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		ocStr, ok := readFile(filepath.Join(path, "over_current_count"))
		if !ok {
			return nil
		}
		name := d.Name()
		m := portNumRe.FindStringSubmatch(name)
		if m == nil {
			return nil
		}
		portNum := m[1]
		oc, _ := strconv.Atoi(ocStr)
		connectType, _ := readFile(filepath.Join(path, "connect_type"))
		state, _ := readFile(filepath.Join(path, "state"))

		// Child device dirs are named "<parent>.<port>" for nested hubs,
		// or "<bus>-<port>" for root hubs (interface dir is "<bus>-0:1.0").
		ifaceDir := filepath.Dir(path)
		ifaceName := filepath.Base(ifaceDir)
		prefix := strings.SplitN(ifaceName, ":", 2)[0]
		var childName string
		if strings.HasSuffix(prefix, "-0") {
			childName = strings.TrimSuffix(prefix, "-0") + "-" + portNum
		} else {
			childName = prefix + "." + portNum
		}
		childPath := filepath.Join(filepath.Dir(ifaceDir), childName)

		busDevKey := ""
		if _, ok := readFile(filepath.Join(childPath, "idVendor")); ok {
			busnum, _ := readFile(filepath.Join(childPath, "busnum"))
			devnum, _ := readFile(filepath.Join(childPath, "devnum"))
			b, _ := strconv.Atoi(busnum)
			dv, _ := strconv.Atoi(devnum)
			busDevKey = fmt.Sprintf("%03d:%03d", b, dv)
		}

		out[name] = portRow{
			port:        name,
			connectType: connectType,
			overCurrent: oc,
			state:       state,
			busDevKey:   busDevKey,
		}
		return nil
	})
	return out
}

var faultKeywords = []string{
	"over-current", "over current", "reset", "unable to enumerate",
	"device descriptor read", "not accepting address", "disabled by hub", "fail",
}

// readFaultTable is the "journalctl -k" source: recent kernel fault lines,
// attributed back to whichever port name they mention.
func readFaultTable(since string, ports map[string]portRow) map[string]faultInfo {
	out := make(map[string]faultInfo)
	data, err := exec.Command("journalctl", "-k", "--no-pager", "--since", since).Output()
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(data), "\n") {
		low := strings.ToLower(line)
		if !strings.Contains(low, "usb") {
			continue
		}
		matched := false
		for _, kw := range faultKeywords {
			if strings.Contains(low, kw) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		for key := range ports {
			if strings.Contains(line, key+":") {
				f := out[key]
				f.count++
				f.lastLine = tailAfterKernel(line)
				out[key] = f
			}
		}
	}
	return out
}

func tailAfterKernel(line string) string {
	if idx := strings.Index(line, "kernel: "); idx >= 0 {
		return strings.TrimSpace(line[idx+len("kernel: "):])
	}
	return strings.TrimSpace(line)
}

func readFile(path string) (string, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(string(b)), true
}

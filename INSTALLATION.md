# Installation Guide

## 🚀 **Quick Start - M5Burner (Recommended)**

### **Step 1: Download M5Burner**
- Download M5Burner from: https://docs.m5stack.com/en/download
- Install and run M5Burner

### **Step 2: Flash Firmware**
1. Connect your M5Stack C Plus2 via USB
2. Open M5Burner
3. Select **M5StickC Plus2** from device list
4. Click **"Add File"** and select `Bruce-Enhanced-Evil-Counter-Attack-FINAL.bin`
5. Click **"Burn"** to flash the firmware
6. Wait for completion (should take ~40 seconds)

### **Step 3: First Boot**
1. Disconnect and reconnect the device
2. You should see the Bruce logo and main menu
3. Navigate to **Anti-Predator Menu** to access new features!

---

## 🔧 **Alternative: ESPTool Command Line**

### **Prerequisites**
```bash
pip install esptool
```

### **Flash Command**
```bash
# Replace /dev/ttyACM0 with your device port (Windows: COM3, etc.)
esptool --chip esp32 --port /dev/ttyACM0 --baud 1500000 write-flash 0x0 Bruce-Enhanced-Evil-Counter-Attack-FINAL.bin
```

---

## 🛠️ **Developer: Build from Source**

### **Prerequisites**
- PlatformIO IDE or CLI
- Git

### **Build Steps**
```bash
# Clone and build
git clone [this-repo]
cd Bruce-Enhanced-Evil-Counter-Attack-Release
pio run -e m5stack-cplus2

# Flash
pio run -e m5stack-cplus2 -t upload
```

---

## 🧪 **Testing the Evil Counter Attack**

### **Quick Test Setup**
1. Flash the firmware to your M5Stack C Plus2
2. Set up an evil portal on another device (can use original Bruce)
3. On the enhanced device: Menu → Anti-Predator → Counter Attack → **Evil Counter Attack**
4. Watch it detect and counter-attack the evil portal!
5. Check the portal's `/creds` page - you should see our warning message!

### **Expected Results**
The counter-attack should capture:
- **Email:** `Ya damn Fool`
- **Password:** `Caught ya Slippin_@_pwned.com`

---

## ⚠️ **Troubleshooting**

### **Blank Screen After Flash**
- This was a known issue with Joy-C hat conflicts
- **Fixed in this version!** Non-blocking I2C initialization prevents hangs
- If still occurs, disconnect any Grove/I2C accessories and retry

### **Counter Attack Not Working**
- Ensure the target has an open WiFi network
- Check that it's actually an evil portal (not a legitimate hotspot)
- The attack only works on captive portals that accept form submissions

### **Build Errors**
- Ensure you have the latest PlatformIO
- Run `pio lib install` to install dependencies
- Check that your board definition supports M5Stack C Plus2

---

## 📱 **Device Compatibility**

### **Confirmed Working**
- ✅ M5Stack C Plus2 (Primary target)
- ✅ Joy-C Hat (optional, with fallback support)

### **Memory Requirements**
- **RAM:** ~111KB used (216KB free)
- **Flash:** ~3.8MB used (1.2MB free)
- **Minimum:** ESP32 with 320KB RAM, 8MB Flash

---

## 🔄 **Reverting to Original Bruce**

If you want to go back to the original Bruce firmware:
1. Download original Bruce from: https://github.com/pr3y/Bruce
2. Flash using the same method above
3. Your settings and files will be preserved

---

**Need help? Open an issue in this repository!**
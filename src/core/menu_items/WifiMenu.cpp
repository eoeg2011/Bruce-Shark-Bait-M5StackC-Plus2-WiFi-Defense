#include "WifiMenu.h"
#include "core/display.h"
#include "core/settings.h"
#include "core/utils.h"
#include "core/wifi/webInterface.h"
#include "core/wifi/wg.h"
#include "core/wifi/wifi_common.h"
#include "modules/ethernet/ARPScanner.h"
#include "modules/wifi/ap_info.h"
#include "modules/wifi/clients.h"
#include "modules/wifi/evil_portal.h"
#include "modules/wifi/scan_hosts.h"
#include "modules/wifi/sniffer.h"
#include "modules/wifi/wifi_atks.h"
#include "modules/wifi/karma_attack.h"
#include "core/wifi/wifi_mac.h"

#ifndef LITE_VERSION
#include "modules/pwnagotchi/pwnagotchi.h"
#endif

// #include "modules/reverseShell/reverseShell.h"
//  Developed by Fourier (github.com/9dl)
//  Use BruceC2 to interact with the reverse shell server
//  BruceC2: https://github.com/9dl/Bruce-C2
//  To use BruceC2:
//  1. Start Reverse Shell Mode in Bruce
//  2. Start BruceC2 and wait.
//  3. Visit 192.168.4.1 in your browser to access the web interface for shell executing.

// 32bit: https://github.com/9dl/Bruce-C2/releases/download/v1.0/BruceC2_windows_386.exe
// 64bit: https://github.com/9dl/Bruce-C2/releases/download/v1.0/BruceC2_windows_amd64.exe
#include "modules/wifi/tcp_utils.h"

void WifiMenu::optionsMenu() {
    returnToMenu = false;
    if (isWebUIActive) {
        drawMainBorderWithTitle("WiFi", true);
        padprintln("");
        padprintln("Iniciar una función WiFi puede hacer que WebUI deje de funcionar");
        padprintln("");
        padprintln("Sel: continuar");
        padprintln("Cualquier tecla: menú");
        while (1) {
            if (check(SelPress)) { break; }
            if (check(AnyKeyPress)) { return; }
            vTaskDelay(10 / portTICK_PERIOD_MS);
        }
    }
    if (!wifiConnected) {
        options = {
            {"Conectar WiFi", lambdaHelper(wifiConnectMenu, WIFI_STA)},
            {"Punto de acceso WiFi", [=]() {
                 wifiConnectMenu(WIFI_AP);
                 displayInfo("pwd: " + bruceConfig.wifiAp.pwd, true);
             }},
        };
    } else {
        options = {
            {"Desconectar", wifiDisconnect}
        };
        if (WiFi.getMode() == WIFI_MODE_STA) options.push_back({"Info del AP", displayAPInfo});
    }
    options.push_back({"Ataques WiFi", wifi_atk_menu});
    options.push_back({"Portal malicioso", [=]() {
                           if (isWebUIActive || server) {
                               stopWebUi();
                               wifiDisconnect();
                           }
                           EvilPortal();
                       }});
    // options.push_back({"ReverseShell", [=]()       { ReverseShell(); }});
    options.push_back({"Escuchar TCP", listenTcpPort});
    options.push_back({"Cliente TCP", clientTCP});
#ifndef LITE_VERSION
    options.push_back({"TelNET", telnet_setup});
    options.push_back({"SSH", lambdaHelper(ssh_setup, String(""))});
    options.push_back({"Sniffers", [=]() {
        std::vector<Option> snifferOptions;


            snifferOptions.push_back({"Sniffer bruto",    sniffer_setup});
            snifferOptions.push_back({"Sniffer de probes",  karma_setup});
            snifferOptions.push_back({"Atrás",      [=]()  {optionsMenu(); }});
        
        loopOptions(snifferOptions, MENU_TYPE_SUBMENU, "Sniffers");
    }});
    options.push_back({"Escanear hosts", [=]() {
                           bool doScan = true;
                           if (!wifiConnected) doScan = wifiConnectMenu();

                           if (doScan) {
                               esp_netif_t *esp_netinterface =
                                   esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
                               if (esp_netinterface == nullptr) {
                                   Serial.println("Failed to get netif handle");
                                   return;
                               }
                               ARPScanner{esp_netinterface};
                           }
                       }});
    options.push_back({"WireGuard", wg_setup});
    options.push_back({"Brucegotchi", brucegotchi_start});
#endif
    options.push_back({"Configurar", [=]() { configMenu(); }});
    addOptionToMainMenu();

    loopOptions(options, MENU_TYPE_SUBMENU, "WiFi");
}

void WifiMenu::configMenu() {
    options = {
        {"Añadir Evil WiFi",    addEvilWifiMenu         },
        {"Eliminar Evil WiFi", removeEvilWifiMenu      },
        {"Cambiar MAC", wifiMACMenu      },
        {"Atrás",             [=]() { optionsMenu(); }},
    };

    loopOptions(options, MENU_TYPE_SUBMENU, "Config WiFi");
}
void WifiMenu::drawIconImg() {
    drawImg(
        *bruceConfig.themeFS(), bruceConfig.getThemeItemImg(bruceConfig.theme.paths.wifi), 0, imgCenterY, true
    );
}
void WifiMenu::drawIcon(float scale) {
    clearIconArea();
    int deltaY = scale * 20;
    int radius = scale * 6;

    tft.fillCircle(iconCenterX, iconCenterY + deltaY, radius, bruceConfig.priColor);
    tft.drawArc(
        iconCenterX,
        iconCenterY + deltaY,
        deltaY + radius,
        deltaY,
        130,
        230,
        bruceConfig.priColor,
        bruceConfig.bgColor
    );
    tft.drawArc(
        iconCenterX,
        iconCenterY + deltaY,
        2 * deltaY + radius,
        2 * deltaY,
        130,
        230,
        bruceConfig.priColor,
        bruceConfig.bgColor
    );
}
